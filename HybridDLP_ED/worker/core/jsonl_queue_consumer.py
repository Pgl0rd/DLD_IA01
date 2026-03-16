"""
JSONL Queue Consumer - Đọc events từ JSONL files thay vì SQLite
Tránh database locking issues
"""
import time
import json
import os
import glob
from typing import Optional, Dict, Any, List
from pathlib import Path
from datetime import datetime, timezone, timedelta
from loguru import logger
import threading

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig


class JSONLQueueConsumer:
    """Consumer cho JSONL files với file-based processing"""
    
    def __init__(self, lookback_hours: int = 1):
        """
        Initialize JSONLQueueConsumer
        
        Args:
            lookback_hours: Chỉ quét events từ N giờ trước (default: 1 hours)
        """
        self.panic_mode = False
        self.queue_size = 0
        self.runtime_dir = WorkerConfig.RUNTIME_DIR
        self.pid = os.getpid()
        self.lookback_hours = lookback_hours
        
        # Track processed events by file and line number
        self.processed_events = {}  # {file_path: set(line_numbers)}
        self.output_dir = WorkerConfig.LOGS_DIR / "processed_events"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Lock for file operations
        self.file_lock = threading.Lock()
        
        logger.info(f"[PID={self.pid}] Initializing JSONLQueueConsumer (lookback: {lookback_hours} hours)")
        logger.info(f"[PID={self.pid}] Runtime directory: {self.runtime_dir}")
        logger.info(f"[PID={self.pid}] Output directory: {self.output_dir}")
        logger.info(f"[PID={self.pid}] Runtime directory exists: {self.runtime_dir.exists()}")
    
    def _find_jsonl_files(self) -> List[Path]:
        """Tìm tất cả JSONL files trong runtime directory"""
        pattern = str(self.runtime_dir / "events_*.jsonl")
        files = sorted(glob.glob(pattern))
        return [Path(f) for f in files]
    
    def _get_output_file_path(self) -> Path:
        """Tạo output file path dựa trên ngày hiện tại"""
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        return self.output_dir / f"output_event-{today}.jsonl"
    
    def _is_event_recent(self, event: Dict[str, Any], lookback_time: datetime) -> bool:
        """Kiểm tra event có trong khoảng lookback time không"""
        try:
            ts_str = event.get('ts') or event.get('timestamp', '')
            if not ts_str:
                return False
            
            # Parse timestamp (ISO8601 format)
            if isinstance(ts_str, str):
                event_time = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            else:
                return False
            
            return event_time >= lookback_time
        except Exception as e:
            logger.debug(f"Error parsing timestamp: {e}")
            return False
    
    def _skip_heartbeat(self, event: Dict[str, Any]) -> bool:
        """Kiểm tra event có phải heartbeat không"""
        event_type = (event.get('type') or '').lower()
        return event_type == 'heartbeat'
    
    def _read_and_process_file(self, file_path: Path, lookback_time: datetime) -> Optional[Dict[str, Any]]:
        """
        Đọc file JSONL và trả về event tiếp theo chưa được xử lý
        
        Returns:
            Event dict hoặc None nếu không có event mới
        """
        if not file_path.exists():
            return None
        
        # Initialize processed set for this file
        if str(file_path) not in self.processed_events:
            self.processed_events[str(file_path)] = set()
        
        processed_lines = self.processed_events[str(file_path)]
        
        try:
            with self.file_lock:
                # Read all lines (with retry for file locking)
                max_retries = 3
                lines = None
                for attempt in range(max_retries):
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                        break
                    except (IOError, PermissionError) as e:
                        if attempt < max_retries - 1:
                            time.sleep(0.1)
                            continue
                        else:
                            logger.warning(f"Could not read file {file_path} after {max_retries} attempts: {e}")
                            return None
                
                if lines is None:
                    return None
                
                # Find next unprocessed event
                for line_num, line in enumerate(lines, start=1):
                    if line_num in processed_lines:
                        continue  # Already processed
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event = json.loads(line)
                        
                        # Skip heartbeat
                        if self._skip_heartbeat(event):
                            processed_lines.add(line_num)
                            continue
                        
                        # Check if event is recent enough
                        if not self._is_event_recent(event, lookback_time):
                            # Event too old, mark as processed but skip
                            processed_lines.add(line_num)
                            continue
                        
                        # Found valid event - mark as processed
                        processed_lines.add(line_num)
                        
                        # Write to output file
                        self._write_to_output(event)
                        
                        # Remove processed line from source file (batch mode)
                        self._remove_processed_line(file_path, line_num, lines)
                        
                        return event
                        
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON at line {line_num} in {file_path}: {e}")
                        processed_lines.add(line_num)  # Mark as processed to skip
                        continue
                    except Exception as e:
                        logger.error(f"Error processing line {line_num} in {file_path}: {e}")
                        continue
                
                return None
                
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None
    
    def _write_to_output(self, event: Dict[str, Any]) -> None:
        """Ghi event vào output file"""
        try:
            output_file = self._get_output_file_path()
            with open(output_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event, ensure_ascii=False) + '\n')
        except Exception as e:
            logger.error(f"Error writing to output file: {e}")
    
    def _remove_processed_line(self, file_path: Path, line_num: int, all_lines: List[str]) -> None:
        """
        Xóa dòng đã xử lý khỏi file gốc
        Ghi lại file mới không bao gồm dòng đã xử lý
        Chỉ ghi lại khi có nhiều dòng đã xử lý để tránh I/O overhead
        """
        try:
            # Get all processed line numbers for this file
            processed_lines = self.processed_events.get(str(file_path), set())
            
            # Only rewrite file if we have processed a significant number of lines
            # Batch size: rewrite every 10 processed lines or if we've processed more than 50% of file
            should_rewrite = (
                len(processed_lines) % 10 == 0 or
                len(processed_lines) >= len(all_lines) * 0.5
            )
            
            if should_rewrite:
                # Write new file without processed lines
                new_lines = [
                    line for idx, line in enumerate(all_lines, start=1)
                    if idx not in processed_lines
                ]
                
                # Only rewrite if we actually have lines to remove
                if len(new_lines) < len(all_lines):
                    # Write back to file atomically (with retry for file locking)
                    temp_file = file_path.with_suffix('.tmp')
                    max_retries = 3
                    
                    for attempt in range(max_retries):
                        try:
                            with open(temp_file, 'w', encoding='utf-8') as f:
                                f.writelines(new_lines)
                            
                            # Atomic replace
                            temp_file.replace(file_path)
                            
                            # Update processed lines tracking (reset since we've written the file)
                            lines_removed = len(processed_lines)
                            self.processed_events[str(file_path)] = set()
                            
                            logger.debug(
                                f"Removed {lines_removed} processed lines from {file_path.name}, "
                                f"remaining: {len(new_lines)} lines"
                            )
                            break
                            
                        except (IOError, PermissionError) as e:
                            if attempt < max_retries - 1:
                                time.sleep(0.1)
                                continue
                            else:
                                logger.warning(f"Could not rewrite file {file_path} after {max_retries} attempts: {e}")
                                # Don't reset processed_lines if we couldn't write
                                break
            
        except Exception as e:
            logger.error(f"Error removing processed line from {file_path}: {e}")
    
    def get_event(self, timeout: int = 1) -> Optional[Dict[str, Any]]:
        """Lấy event từ JSONL files"""
        try:
            # Calculate lookback time
            now = datetime.now(timezone.utc)
            lookback_time = now - timedelta(hours=self.lookback_hours)
            
            # Find all JSONL files
            jsonl_files = self._find_jsonl_files()
            
            if not jsonl_files:
                logger.debug(f"[PID={self.pid}] No JSONL files found, waiting...")
                time.sleep(timeout)
                return None
            
            # Try each file
            for file_path in jsonl_files:
                event = self._read_and_process_file(file_path, lookback_time)
                if event:
                    event_id = event.get('event_id', 'unknown')
                    event_type = event.get('type', 'unknown')
                    source = event.get('source', 'unknown')
                    
                    logger.info(
                        f"[PID={self.pid}] Received event from JSONL: "
                        f"event_id={event_id}, type={event_type}, "
                        f"source={source}, file={file_path.name}"
                    )
                    
                    # Update queue size
                    self._update_queue_size()
                    
                    return event
            
            # No new events found
            time.sleep(timeout)
            return None
            
        except Exception as e:
            logger.error(f"[PID={self.pid}] Error getting event from JSONL: {e}", exc_info=True)
            time.sleep(timeout)
            return None
    
    def _update_queue_size(self) -> None:
        """Cập nhật queue size (số events chưa xử lý)"""
        try:
            jsonl_files = self._find_jsonl_files()
            total_lines = 0
            processed_lines = 0
            
            for file_path in jsonl_files:
                if not file_path.exists():
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        total_lines += len(lines)
                        
                        processed = self.processed_events.get(str(file_path), set())
                        processed_lines += len(processed)
                except Exception:
                    pass
            
            self.queue_size = max(0, total_lines - processed_lines)
            
        except Exception as e:
            logger.debug(f"Error updating queue size: {e}")
    
    def get_queue_size(self) -> int:
        """Lấy số events còn lại trong queue"""
        self._update_queue_size()
        return self.queue_size
    
    def is_panic_mode(self) -> bool:
        """Kiểm tra trạng thái Panic Mode"""
        return self.panic_mode
    
    def check_panic_mode(self) -> bool:
        """Kiểm tra trạng thái Panic Mode (alias for compatibility)"""
        return self.panic_mode
    
    def get_stats(self) -> Dict[str, Any]:
        """Lấy thống kê queue"""
        self._update_queue_size()
        return {
            'queue_size': self.queue_size,
            'panic_mode': self.panic_mode,
            'queue_type': 'jsonl',
            'jsonl_files': len(self._find_jsonl_files()),
            'processed_events_count': sum(len(s) for s in self.processed_events.values())
        }
