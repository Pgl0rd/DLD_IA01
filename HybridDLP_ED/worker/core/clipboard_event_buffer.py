"""
Clipboard Event Buffer for Smart Alert Control
=============================================

Thay vì alert ngay mỗi khi có clipboard paste, ta buffer các events
và chỉ alert khi có đủ evidence.

Luồng:
1. Event vào buffer
2. Đợi đến khi đủ min_events HOẶC timeout
3. Phân tích pattern với ML/NLP
4. Alert chỉ khi thực sự suspicious
"""

import time
import threading
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from collections import deque
from loguru import logger
import hashlib

from .alert_flow_config import AlertFlowConfig


@dataclass
class BufferedEvent:
    """Một event đang được buffer"""
    event: Dict[str, Any]
    timestamp: float
    event_id: str
    event_type: str
    destination: str = ""
    content_preview: str = ""  # First 100 chars
    content_hash: str = ""
    yara_matches: List[Dict] = field(default_factory=list)
    has_sensitive_content: bool = False
    entropy: float = 0.0
    text_length: int = 0


class ClipboardEventBuffer:
    """
    Buffer cho clipboard events với smart aggregation logic
    
    Features:
    - Buffer events theo user
    - Track content patterns
    - Suppress single-action alerts
    - Aggregate for ML analysis
    """
    
    def __init__(self):
        # Per-user event buffers
        self._user_buffers: Dict[str, deque] = {}
        self._user_last_analysis: Dict[str, float] = {}
        
        # Lock for thread safety
        self._lock = threading.Lock()
        
        # Configuration
        self._config = AlertFlowConfig()
        
        # Stats
        self._stats = {
            'events_buffered': 0,
            'events_suppressed': 0,
            'alerts_triggered': 0,
            'buffers_cleared': 0,
        }
    
    def _get_user_id(self, event: Dict[str, Any]) -> str:
        """Extract user ID from event"""
        ctx = event.get('context', {}) or {}
        user = ctx.get('user') or event.get('user') or event.get('actor', {}).get('user', 'unknown')
        return str(user).lower()
    
    def _get_event_destination(self, event: Dict[str, Any]) -> str:
        """Extract destination from event"""
        clipboard = event.get('clipboard', {}) or {}
        raw_original = event.get('raw_original', {}) or {}
        raw_clipboard = raw_original.get('clipboard', {}) or {}
        
        dest = (
            clipboard.get('dest_window_title') or
            raw_clipboard.get('dest_window_title') or
            clipboard.get('active_window_title') or
            raw_clipboard.get('active_window_title') or
            event.get('context', {}).get('window_title') or
            ''
        )
        return str(dest)[:100]
    
    def _get_content_preview(self, event: Dict[str, Any]) -> str:
        """Get preview of clipboard content"""
        content = event.get('content', {}) or {}
        clipboard = event.get('clipboard', {}) or {}
        raw_original = event.get('raw_original', {}) or {}
        raw_clipboard = raw_original.get('clipboard', {}) or {}
        raw_content = raw_original.get('content', {}) or {}
        
        text = (
            clipboard.get('text_file') or
            raw_clipboard.get('text_file') or
            content.get('sample') or
            raw_content.get('sample') or
            clipboard.get('content') or
            ''
        )
        return str(text)[:100]
    
    def _compute_content_hash(self, text: str) -> str:
        """Compute hash for content deduplication"""
        if not text:
            return ""
        return hashlib.md5(text.encode('utf-8', errors='ignore')).hexdigest()[:16]
    
    def add_event(self, event: Dict[str, Any], yara_matches: List[Dict] = None) -> bool:
        """
        Thêm event vào buffer
        
        Returns:
            True nếu event được buffer thành công
            False nếu event bị suppress
        """
        if yara_matches is None:
            yara_matches = []
        
        # Check if event should be aggregated
        if not self._config.should_aggregate_event(event):
            logger.debug("Event suppressed by aggregation filter")
            self._stats['events_suppressed'] += 1
            return False
        
        user_id = self._get_user_id(event)
        event_id = event.get('event_id', f'evt_{time.time()}')
        event_type = event.get('type', 'unknown')
        timestamp = time.time()
        
        # Extract content info
        content_preview = self._get_content_preview(event)
        content_hash = self._compute_content_hash(content_preview)
        destination = self._get_event_destination(event)
        
        # Get metrics
        metrics = event.get('metrics', {}) or {}
        entropy = float(metrics.get('entropy', 0.0))
        clipboard = event.get('clipboard', {}) or {}
        text_length = int(
            clipboard.get('content_len') or
            clipboard.get('text_len') or
            len(content_preview) or
            0
        )
        
        # Check suppression rules
        if self._config.SUPPRESS_SINGLE_ACTION:
            # Will suppress if this is first event (will be checked on analysis)
            pass
        
        if entropy < self._config.MIN_ENTROPY_FOR_ALERT and not yara_matches:
            logger.debug(f"Event suppressed: low entropy ({entropy:.2f})")
            self._stats['events_suppressed'] += 1
            return False
        
        if text_length < self._config.MIN_TEXT_LENGTH_FOR_ALERT and not yara_matches:
            logger.debug(f"Event suppressed: short text ({text_length} chars)")
            self._stats['events_suppressed'] += 1
            return False
        
        # Create buffered event
        buffered = BufferedEvent(
            event=event,
            timestamp=timestamp,
            event_id=event_id,
            event_type=event_type,
            destination=destination,
            content_preview=content_preview,
            content_hash=content_hash,
            yara_matches=yara_matches,
            has_sensitive_content=len(yara_matches) > 0 or entropy >= 4.0,
            entropy=entropy,
            text_length=text_length,
        )
        
        with self._lock:
            # Get or create user buffer
            if user_id not in self._user_buffers:
                self._user_buffers[user_id] = deque(maxlen=self._config.AGGREGATION_MAX_BUFFER)
            
            buffer = self._user_buffers[user_id]
            buffer.append(buffered)
            self._stats['events_buffered'] += 1
        
        logger.debug(
            f"Event buffered: user={user_id}, type={event_type}, "
            f"destination={destination[:50]}, buffer_size={len(buffer)}"
        )
        
        return True
    
    def get_buffer_size(self, user_id: str) -> int:
        """Get current buffer size for user"""
        with self._lock:
            if user_id not in self._user_buffers:
                return 0
            return len(self._user_buffers[user_id])
    
    def should_analyze(self, user_id: str) -> tuple[bool, str]:
        """
        Kiểm tra xem nên phân tích buffer cho user chưa
        
        Returns:
            (should_analyze: bool, reason: str)
        """
        min_events = self._config.get_min_events_for_analysis()
        
        with self._lock:
            if user_id not in self._user_buffers:
                return False, "No buffer for user"
            
            buffer = self._user_buffers[user_id]
            buffer_size = len(buffer)
        
        # Not enough events
        if buffer_size < min_events:
            return False, f"Buffering ({buffer_size}/{min_events} events)"
        
        # Check time window
        last_analysis = self._user_last_analysis.get(user_id, 0)
        time_since_analysis = time.time() - last_analysis
        
        if time_since_analysis < self._config.AGGREGATION_WINDOW_SEC:
            return False, f"Recently analyzed ({time_since_analysis:.0f}s ago)"
        
        return True, f"Ready to analyze ({buffer_size} events)"
    
    def get_buffer_for_analysis(self, user_id: str) -> List[BufferedEvent]:
        """Get all buffered events for user"""
        with self._lock:
            if user_id not in self._user_buffers:
                return []
            return list(self._user_buffers[user_id])
    
    def mark_analyzed(self, user_id: str):
        """Mark that we've analyzed this user's buffer"""
        self._user_last_analysis[user_id] = time.time()
    
    def clear_buffer(self, user_id: str):
        """Clear buffer for user"""
        with self._lock:
            if user_id in self._user_buffers:
                self._user_buffers[user_id].clear()
                self._stats['buffers_cleared'] += 1
                logger.debug(f"Buffer cleared for user: {user_id}")
    
    def analyze_buffer(self, user_id: str) -> Dict[str, Any]:
        """
        Phân tích buffer và trả về kết quả
        
        Returns:
            Dict với analysis results và alert decision
        """
        if not self.should_analyze(user_id)[0]:
            return {'should_alert': False, 'reason': 'Not ready to analyze'}
        
        buffer = self.get_buffer_for_analysis(user_id)
        
        # Aggregate data from buffer
        all_yara_matches = []
        content_samples = []
        destinations = set()
        total_entropy = 0.0
        total_text_length = 0
        sensitive_count = 0
        
        for buffered in buffer:
            all_yara_matches.extend(buffered.yara_matches)
            if buffered.content_preview:
                content_samples.append(buffered.content_preview)
            destinations.add(buffered.destination)
            total_entropy += buffered.entropy
            total_text_length += buffered.text_length
            if buffered.has_sensitive_content:
                sensitive_count += 1
        
        avg_entropy = total_entropy / len(buffer) if buffer else 0
        sensitivity_ratio = sensitive_count / len(buffer) if buffer else 0
        
        # Unique YARA rules
        unique_yara_rules = list({m.get('rule', '') for m in all_yara_matches if m.get('rule')})
        
        # Check if should alert
        # For analysis: use first event's YARA matches (they were already scanned)
        first_event_yara = buffer[0].yara_matches if buffer else []
        
        alert_decision = self._config.can_trigger_alert(
            yara_matches=first_event_yara,
            ml_score=avg_entropy * 2,  # Approximate ML score from entropy
            ml_confidence=sensitivity_ratio,
            behavioral_score=len(destinations) * 0.5,  # Multiple destinations = suspicious
            event_count=len(buffer),
        )
        
        result = {
            'should_alert': alert_decision['can_alert'],
            'reason': alert_decision['reason'],
            'primary_evidence': alert_decision['primary_evidence'],
            'confidence': alert_decision['confidence'],
            
            # Analysis details
            'event_count': len(buffer),
            'unique_destinations': len(destinations),
            'destinations': list(destinations),
            'unique_yara_rules': unique_yara_rules,
            'yara_match_count': len(unique_yara_rules),
            'avg_entropy': round(avg_entropy, 2),
            'sensitivity_ratio': round(sensitivity_ratio, 2),
            'content_samples': content_samples[:5],  # First 5 previews
            
            # For ML analysis
            'combined_content': '\n'.join(content_samples[:10]),
            'buffered_events': buffer,
        }
        
        if alert_decision['can_alert']:
            self._stats['alerts_triggered'] += 1
        
        return result
    
    def get_stats(self) -> Dict[str, int]:
        """Get buffer statistics"""
        return dict(self._stats)
    
    def cleanup_old_buffers(self, max_age_seconds: int = 600):
        """Clear buffers that haven't been updated in a while"""
        current_time = time.time()
        users_to_clear = []
        
        with self._lock:
            for user_id, buffer in self._user_buffers.items():
                if buffer:
                    oldest_timestamp = buffer[0].timestamp
                    if current_time - oldest_timestamp > max_age_seconds:
                        users_to_clear.append(user_id)
        
        for user_id in users_to_clear:
            self.clear_buffer(user_id)
            logger.debug(f"Cleaned up stale buffer for user: {user_id}")


# Singleton instance
clipboard_event_buffer = ClipboardEventBuffer()
