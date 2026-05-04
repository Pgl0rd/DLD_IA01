"""
Alert Flow Configuration for HybridDLP Demo
============================================

Luồng xử lý alert đúng cho demo:
1. YARA xử lý TRƯỚC - phát hiện pattern nhạy cảm ngay
2. Buffer ~10 events - đợi đủ data
3. ML/NLP phân tích pattern - chỉ khi đủ data
4. Alert chỉ khi thực sự suspicious

Control flags:
- ALERT_ON_DIRECT_YARA_MATCH: Alert ngay khi có YARA match rõ ràng (ID, Credit, API)
- AGGREGATION_MIN_EVENTS: Số events tối thiểu trước khi phân tích
- SUPPRESS_SINGLE_ALERTS: Không alert single action
- BEHAVIORAL_REQUIRES_YARA: Behavioral rule phải có YARA support
"""

from typing import Dict, Any
from pathlib import Path
import os

class AlertFlowConfig:
    """
    Configuration cho alert flow pipeline
    
    Luồng:
    1. YARA scan → nếu có match cụ thể → ALERT NGAY
    2. Buffer events → đợi đủ min_events
    3. NLP/ML analysis → phân tích pattern
    4. Alert chỉ khi: YARA_match HOẶC (ML_confident HOẶC behavioral_cumulative)
    """
    
    # ==== Tier 1: YARA Direct Match ====
    # Alert ngay lập tức chỉ khi có YARA match thuộc nhóm này
    CRITICAL_YARA_PATTERNS = {
        'id', 'cmnd', 'cccd', 'passport',
        'credit', 'card', 'cvv',
        'api_key', 'secret_key', 'private_key',
        'ssn', 'social_security',
    }
    
    # Alert threshold cho YARA direct match (thường cao vì đã xác nhận bằng pattern)
    DIRECT_YARA_MIN_SCORE = 6.0  # YARA match = score tối thiểu 6.0
    
    # ==== Tier 2: Aggregation Buffer ====
    # Số events tối thiểu để bắt đầu phân tích pattern
    AGGREGATION_MIN_EVENTS = 5   # Đợi ít nhất 5 events
    
    # Số events tối đa để buffer (quá thì clear cũ)
    AGGREGATION_MAX_BUFFER = 15
    
    # Thời gian buffer tối đa (giây) - quá thì reset
    AGGREGATION_WINDOW_SEC = 300  # 5 phút
    
    # ==== Tier 3: ML/NLP Analysis ====
    # Chỉ chạy ML khi buffer đủ lớn
    ML_REQUIRE_MIN_EVENTS = 5
    
    # ML confidence threshold để trigger alert
    ML_CONFIDENCE_THRESHOLD = 0.7  # 70% confident
    
    # ML anomaly score threshold (0-10)
    ML_ANOMALY_MIN_SCORE = 7.0
    
    # ==== Tier 4: Behavioral Rules ====
    # Behavioral rule KHÔNG tự trigger alert - phải có YARA hoặc ML support
    BEHAVIORAL_REQUIRES_CONTENT_MATCH = True
    
    # Behavioral risk boost chỉ khi có content evidence
    BEHAVIORAL_BOOST_ONLY_WITH_EVIDENCE = True
    
    # ==== Suppression Rules ====
    # Không alert những loại event này (chỉ log)
    SUPPRESS_EVENT_TYPES = {
        'heartbeat',
        'proc_start', 
        'proc_end',
        'corr_',  # correlation events (prefix match)
    }
    
    # Suppress alert nếu chỉ có 1 event (cần cumulative evidence)
    SUPPRESS_SINGLE_ACTION = True
    
    # Suppress nếu entropy thấp (có thể là noise)
    MIN_ENTROPY_FOR_ALERT = 3.5
    
    # Suppress nếu text quá ngắn (không đủ context)
    MIN_TEXT_LENGTH_FOR_ALERT = 100
    
    # ==== Scoring Weights ====
    # Trọng số để tính final risk score
    WEIGHT_YARA = 0.6        # YARA là evidence mạnh nhất
    WEIGHT_ML = 0.25         # ML phụ
    WEIGHT_BEHAVIORAL = 0.15 # Behavioral pattern
    
    # ==== Demo Mode ====
    # Khi True: giảm threshold để dễ trigger (cho demo)
    DEMO_MODE = os.getenv("DEMO_MODE", "0").strip().lower() in {"1", "true", "yes", "on"}
    
    # Demo: số events thấp hơn để nhanh thấy kết quả
    DEMO_MIN_EVENTS = 3
    DEMO_ALERT_THRESHOLD = 5.0  # Demo: alert sớm hơn
    
    @classmethod
    def get_min_events_for_analysis(cls) -> int:
        """Số events tối thiểu để phân tích"""
        if cls.DEMO_MODE:
            return cls.DEMO_MIN_EVENTS
        return cls.AGGREGATION_MIN_EVENTS
    
    @classmethod
    def get_alert_threshold(cls) -> float:
        """Alert threshold tùy mode"""
        if cls.DEMO_MODE:
            return cls.DEMO_ALERT_THRESHOLD
        return cls.DIRECT_YARA_MIN_SCORE
    
    @classmethod
    def should_alert_on_yara(cls, yara_matches: list) -> bool:
        """
        Kiểm tra xem có nên alert ngay với YARA match không
        
        Returns:
            True nếu có YARA match thuộc nhóm CRITICAL
        """
        if not yara_matches:
            return False
        
        for match in yara_matches:
            rule_name = str(match.get('rule', '')).lower()
            if any(pattern in rule_name for pattern in cls.CRITICAL_YARA_PATTERNS):
                return True
        
        return False
    
    @classmethod
    def should_aggregate_event(cls, event: Dict[str, Any]) -> bool:
        """
        Kiểm tra xem event có nên được thêm vào aggregation buffer không
        
        Returns:
            True nếu event đáng được track
        """
        event_type = str(event.get('type') or event.get('event_type', '')).lower()
        
        # Skip suppressed types
        for suppress in cls.SUPPRESS_EVENT_TYPES:
            if event_type.startswith(suppress) or event_type == suppress:
                return False
        
        # Skip heartbeat
        if event_type == 'heartbeat':
            return False
        
        return True
    
    @classmethod
    def can_trigger_alert(cls, 
                          yara_matches: list,
                          ml_score: float,
                          ml_confidence: float,
                          behavioral_score: float,
                          event_count: int) -> Dict[str, Any]:
        """
        Kiểm tra xem có đủ điều kiện để trigger alert không
        
        Args:
            yara_matches: List of YARA matches
            ml_score: ML anomaly score (0-10)
            ml_confidence: ML confidence (0-1)
            behavioral_score: Behavioral risk score
            event_count: Số events trong buffer
            
        Returns:
            Dict với:
                - can_alert: bool
                - reason: str
                - primary_evidence: str
                - confidence: float
        """
        min_events = cls.get_min_events_for_analysis()
        
        # Case 1: Direct YARA match (CRITICAL patterns) → Alert immediately
        if cls.should_alert_on_yara(yara_matches):
            return {
                'can_alert': True,
                'reason': 'Direct YARA match on critical pattern',
                'primary_evidence': 'yara',
                'confidence': 0.9,
            }
        
        # Case 2: Not enough events → Buffer only, no alert
        if event_count < min_events:
            return {
                'can_alert': False,
                'reason': f'Buffering events ({event_count}/{min_events})',
                'primary_evidence': 'buffering',
                'confidence': 0.0,
            }
        
        # Case 3: ML confident anomaly → Alert
        if ml_score >= cls.ML_ANOMALY_MIN_SCORE and ml_confidence >= cls.ML_CONFIDENCE_THRESHOLD:
            return {
                'can_alert': True,
                'reason': f'ML confident anomaly (score={ml_score:.1f}, conf={ml_confidence:.0%})',
                'primary_evidence': 'ml',
                'confidence': ml_confidence,
            }
        
        # Case 4: Behavioral + Content evidence → Alert (suppressed if no content)
        if behavioral_score > 0:
            if cls.BEHAVIORAL_REQUIRES_CONTENT_MATCH:
                # Need YARA or ML support
                if yara_matches or (ml_score >= cls.ML_ANOMALY_MIN_SCORE):
                    return {
                        'can_alert': True,
                        'reason': f'Behavioral anomaly with content support (behavioral={behavioral_score:.1f})',
                        'primary_evidence': 'behavioral',
                        'confidence': 0.6,
                    }
                else:
                    # Behavioral without content → suppress
                    return {
                        'can_alert': False,
                        'reason': 'Behavioral pattern without content evidence - suppressed',
                        'primary_evidence': 'none',
                        'confidence': 0.0,
                    }
            else:
                return {
                    'can_alert': True,
                    'reason': f'Behavioral anomaly (score={behavioral_score:.1f})',
                    'primary_evidence': 'behavioral',
                    'confidence': 0.5,
                }
        
        # Case 5: Cumulative evidence from buffer
        if event_count >= cls.AGGREGATION_MAX_BUFFER:
            # Đã buffer đủ lâu → check cumulative
            if ml_score >= cls.ML_ANOMALY_MIN_SCORE * 0.8:  # Giảm threshold 20%
                return {
                    'can_alert': True,
                    'reason': f'Cumulative analysis triggered (events={event_count}, ml={ml_score:.1f})',
                    'primary_evidence': 'cumulative',
                    'confidence': ml_confidence * 0.8,
                }
        
        # Default: No alert
        return {
            'can_alert': False,
            'reason': f'Insufficient evidence (events={event_count}, ml={ml_score:.1f})',
            'primary_evidence': 'none',
            'confidence': 0.0,
        }


# Singleton instance
alert_flow_config = AlertFlowConfig()
