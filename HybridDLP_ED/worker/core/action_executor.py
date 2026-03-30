"""
Action Executor - Thực thi hành động: Block/Alert/Log
"""
import requests
from pathlib import Path
from typing import Dict, Any, Optional
from loguru import logger
import sys
import json
import os
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig
from typing import Optional, Dict, Any
from core.windows_notification import WindowsNotification


class ActionExecutor:
    """Thực thi hành động: Block/Alert/Log"""
    
    def __init__(self):
        self.server_url = WorkerConfig.SERVER_URL
        self.api_key = WorkerConfig.SERVER_API_KEY
        self.device_id = WorkerConfig.DEVICE_ID
        self.timeout = WorkerConfig.SERVER_TIMEOUT
        self.windows_alert_min_score = float(getattr(WorkerConfig, "WINDOWS_ALERT_MIN_SCORE", 7.0))
        self.notification = WindowsNotification()
        
        # Dashboard alerts.json path
        # In Docker: /app/logs/alerts.json (shared volume)
        # Local: dashboard/logs/alerts.json (relative to project root)
        if Path("/app/logs").exists():
            self.dashboard_log_path = Path("/app/logs/alerts.json")
            logger.info(f"[PID={os.getpid()}] Dashboard log path (Docker): {self.dashboard_log_path}")
        else:
            # Local development - find dashboard directory
            base_dir = Path(__file__).parent.parent.parent
            dashboard_log_dir = base_dir / "dashboard" / "logs"
            dashboard_log_dir.mkdir(parents=True, exist_ok=True)
            self.dashboard_log_path = dashboard_log_dir / "alerts.json"
            logger.info(f"[PID={os.getpid()}] Dashboard log path (Local): {self.dashboard_log_path}")
        
        # Ensure parent directory exists
        self.dashboard_log_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"[PID={os.getpid()}] Dashboard log directory exists: {self.dashboard_log_path.parent.exists()}")
    
    def execute(self, action: str, file_path: Path, 
               risk_score: float, details: Dict[str, Any],
               event_context: Dict[str, Any],
               report: Optional[Dict[str, Any]] = None) -> bool:
        """
        Thực thi hành động
        
        Args:
            action: 'block', 'alert', hoặc 'log'
            file_path: Đường dẫn file
            risk_score: Risk score
            details: Chi tiết từ risk scoring
            event_context: Context của event
            report: Report fields (REPORT FIELDS format)
        
        Returns:
            True nếu thành công
        """
        event_id = event_context.get('event_id', 'unknown')
        event_type = event_context.get('action_type', 'unknown')
        pid = os.getpid()
        
        logger.info(
            f"[PID={pid}] Executing action: "
            f"action={action.upper()}, event_id={event_id}, "
            f"type={event_type}, risk_score={risk_score:.1f}"
        )
        
        try:
            if action == 'block':
                return self._block_action(file_path, risk_score, details, event_context, report)
            elif action == 'alert':
                return self._alert_action(file_path, risk_score, details, event_context, report)
            elif action == 'log':
                return self._log_action(file_path, risk_score, details, event_context, report)
            else:
                logger.warning(f"[PID={pid}] Unknown action: {action}")
                return False
        except Exception as e:
            logger.error(f"[PID={pid}] Error executing action {action}: {e}", exc_info=True)
            return False
    
    def _block_action(self, file_path: Path, risk_score: float,
                     details: Dict[str, Any], context: Dict[str, Any],
                     report: Optional[Dict[str, Any]] = None) -> bool:
        """Block hành động (xóa file, kill process, etc.)"""
        file_name = file_path.name if hasattr(file_path, 'name') and str(file_path) != 'clipboard://clipboard_content' else str(file_path)
        event_id = context.get('event_id', 'unknown')
        pid = os.getpid()
        
        logger.warning(
            f"[PID={pid}] BLOCK triggered: "
            f"event_id={event_id}, file={file_name}, score={risk_score:.1f}"
        )
        
        # Hiển thị thông báo block
        try:
            violation_type = self._determine_violation_type(details, context, report)
            # Lấy yara_matches từ nhiều nguồn có thể
            yara_matches = (
                details.get('content', {}).get('yara_matches', []) or
                details.get('yara_matches', []) or
                []
            )
            notification_details = {
                'risk_score': risk_score,
                'window_title': context.get('window_title') or context.get('active_window') or '',
                'yara_matches': yara_matches,
                'action_type': context.get('action_type', ''),
                'file_path': str(file_path) if file_path and str(file_path) != 'clipboard://clipboard_content' else None
            }
            self.notification.show_violation_alert(
                violation_type=f"BI CHAN: {violation_type}",
                details=notification_details
            )
        except Exception as e:
            logger.error(f"Error showing block notification: {e}")
        
        try:
            # Block clipboard paste if applicable
            is_clipboard = str(file_path) == 'clipboard://clipboard_content' if file_path else False
            
            if is_clipboard:
                # For clipboard, we can't prevent paste that already happened
                # But we can log and alert (already done above)
                # Note: Real-time blocking would require agent-level integration
                logger.warning(f"BLOCKED clipboard paste to sensitive app: {context.get('window_title', 'unknown')}")
            else:
                # For file operations, could implement:
                # - Kill copy process (if PID available)
                # - Delete copied file (if path available)
                logger.warning(f"BLOCKED file operation: {file_path}")
            
            # Send alert to server với report fields
            self._send_to_server('block', file_path, risk_score, details, context, report)
            
            # Save to dashboard log
            self._save_to_dashboard_log('blocked', file_path, risk_score, details, context, report)
            
            return True
        except Exception as e:
            logger.error(f"Block action error: {e}")
            return False
    
    def _alert_action(self, file_path: Path, risk_score: float,
                     details: Dict[str, Any], context: Dict[str, Any],
                     report: Optional[Dict[str, Any]] = None) -> bool:
        """Gửi cảnh báo và hiển thị thông báo trên Windows"""
        file_name = file_path.name if hasattr(file_path, 'name') and str(file_path) != 'clipboard://clipboard_content' else str(file_path)
        event_id = context.get('event_id', 'unknown')
        pid = os.getpid()
        
        logger.warning(
            f"[PID={pid}] ALERT triggered: "
            f"event_id={event_id}, file={file_name}, score={risk_score:.1f}"
        )
        
        try:
            # Xác định loại vi phạm
            violation_type = self._determine_violation_type(details, context, report)
            
            # Build notification details
            # Lấy yara_matches từ nhiều nguồn có thể
            yara_matches = (
                details.get('content', {}).get('yara_matches', []) or
                details.get('yara_matches', []) or
                []
            )
            
            notification_details = {
                'risk_score': risk_score,
                'window_title': context.get('window_title') or context.get('active_window') or '',
                'yara_matches': yara_matches,
                'action_type': context.get('action_type', ''),
                'file_path': str(file_path) if file_path and str(file_path) != 'clipboard://clipboard_content' else None
            }
            
            # Hiển thị popup Windows chỉ với mức rủi ro cao để tránh spam.
            if float(risk_score) >= self.windows_alert_min_score:
                self.notification.show_violation_alert(
                    violation_type=violation_type,
                    details=notification_details
                )
            else:
                logger.info(
                    f"[PID={pid}] Skip Windows popup (score={risk_score:.1f} < "
                    f"threshold={self.windows_alert_min_score:.1f})"
                )
            
            # Send alert to server với report fields
            self._send_to_server('alert', file_path, risk_score, details, context, report)
            
            # Save to dashboard log
            self._save_to_dashboard_log('alerted', file_path, risk_score, details, context, report)
            
            return True
        except Exception as e:
            logger.error(f"Alert action error: {e}")
            return False
    
    def _determine_violation_type(self, 
                                  details: Dict[str, Any],
                                  context: Dict[str, Any],
                                  report: Optional[Dict[str, Any]] = None) -> str:
        """Xác định loại vi phạm"""
        # Check clipboard paste
        if context.get('is_clipboard_paste') and context.get('is_sensitive_app'):
            return "Paste Dữ Liệu Nhạy Cảm Vào Ứng Dụng Bên Ngoài"
        
        # Check YARA matches
        yara_matches = details.get('content', {}).get('yara_matches', [])
        if yara_matches:
            rules = [m.get('rule', '').lower() for m in yara_matches]
            if any('id' in r or 'cmnd' in r or 'cccd' in r for r in rules):
                return "Phát Hiện Thông Tin CMND/CCCD"
            elif any('credit' in r or 'card' in r for r in rules):
                return "Phát Hiện Thông Tin Thẻ Tín Dụng"
            elif any('bank' in r for r in rules):
                return "Phát Hiện Thông Tin Tài Khoản Ngân Hàng"
            elif any('api' in r or 'key' in r for r in rules):
                return "Phát Hiện API Key/Secret"
            else:
                return "Phát Hiện Dữ Liệu Nhạy Cảm"
        
        # Check file operations
        action_type = context.get('action_type', '').lower()
        if 'usb' in action_type or 'removable' in str(context.get('destination', '')).lower():
            return "Copy Dữ Liệu Ra USB"
        elif 'clipboard' in action_type:
            return "Copy Dữ Liệu Nhạy Cảm"
        
        return "Vi Phạm Chính Sách Bảo Mật"
    
    def _log_action(self, file_path: Path, risk_score: float,
                   details: Dict[str, Any], context: Dict[str, Any],
                   report: Optional[Dict[str, Any]] = None) -> bool:
        """Chỉ log"""
        file_name = file_path.name if hasattr(file_path, 'name') and str(file_path) != 'clipboard://clipboard_content' else str(file_path)
        logger.info(f"LOG: {file_name} (score: {risk_score})")
        
        try:
            # Send log to server với report fields
            self._send_to_server('log', file_path, risk_score, details, context, report)
            
            # Save to dashboard log (save all LOG actions to dashboard)
            # Always save to dashboard for visibility, even low risk events
            self._save_to_dashboard_log('allowed', file_path, risk_score, details, context, report)
            
            return True
        except Exception as e:
            logger.error(f"Log action error: {e}")
            return False
    
    def _send_to_server(self, action: str, file_path: Path,
                       risk_score: float, details: Dict[str, Any],
                       context: Dict[str, Any],
                       report: Optional[Dict[str, Any]] = None) -> bool:
        """Gửi kết quả về server với report fields"""
        if not self.server_url or self.server_url == "https://dlp-server.example.com":
            logger.debug("Server URL not configured, skipping send")
            return True  # Return True để không block flow
        
        try:
            # Build payload với report fields
            file_name = file_path.name if hasattr(file_path, 'name') and str(file_path) != 'clipboard://clipboard_content' else str(file_path)
            payload = {
                'device_id': self.device_id,
                'action': action,
                'file_path': str(file_path),
                'file_name': file_name,
                'risk_score': risk_score,
                'details': details,
                'context': context,
                'timestamp': context.get('time', ''),
                # Include report fields nếu có
                'report': report or {}
            }
            
            headers = {
                'Authorization': f'Bearer {self.api_key}' if self.api_key else '',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.server_url}/api/events",
                json=payload,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                logger.debug(f"Sent {action} to server successfully")
                return True
            else:
                logger.warning(f"Server returned {response.status_code}: {response.text}")
                return False
                
        except requests.exceptions.ConnectionError:
            logger.warning("Cannot connect to server, event logged locally only")
            return False
        except requests.exceptions.Timeout:
            logger.warning("Server timeout, event logged locally only")
            return False
        except Exception as e:
            logger.error(f"Error sending to server: {e}")
            return False
    
    def _save_to_dashboard_log(self, action: str, file_path: Path,
                               risk_score: float, details: Dict[str, Any],
                               context: Dict[str, Any],
                               report: Optional[Dict[str, Any]] = None) -> bool:
        """
        Save alert to dashboard alerts.json file
        
        Args:
            action: 'allowed' or 'alerted' (legacy: may still include 'blocked')
            file_path: File path or clipboard placeholder
            risk_score: Risk score
            details: Detection details
            context: Event context
            report: Report fields
        
        Returns:
            True if saved successfully
        """
        try:
            # Resolve filename/path from richest source first (event payload),
            # then fallback to file_path argument.
            ev = context.get("_event_data", {}) or {}
            ev_obj = ev.get("object", {}) if isinstance(ev, dict) else {}
            event_file_name = ""
            event_file_path = ""
            if isinstance(ev_obj, dict):
                event_file_name = str(ev_obj.get("name") or "").strip()
                event_file_path = str(
                    ev_obj.get("path")
                    or ev_obj.get("dst_path")
                    or ev_obj.get("src_path")
                    or ""
                ).strip()
            resolved_file_name = event_file_name or (
                file_path.name if hasattr(file_path, "name") else ""
            )
            resolved_file_path = event_file_path or str(file_path or "")
            is_clipboard_placeholder = str(file_path) == "clipboard://clipboard_content" if file_path else False

            # Extract keywords from YARA matches
            yara_matches = (
                details.get('content', {}).get('yara_matches', []) or
                details.get('yara_matches', []) or
                []
            )
            keywords = [match.get('rule', '') for match in yara_matches if match.get('rule')]
            
            # If no YARA matches but has behavioral rule, use that
            if not keywords and details.get('behavioral', {}).get('behavioral_rule_matched'):
                keywords = [details['behavioral']['behavioral_rule_matched']]
            
            # Get timestamp - ensure ISO8601 format
            timestamp = context.get('time') or context.get('timestamp') or datetime.now().isoformat()
            # Ensure timestamp is in ISO8601 format (with timezone if possible)
            if isinstance(timestamp, str):
                # If already ISO8601, use as is
                if 'T' in timestamp and ('+' in timestamp or 'Z' in timestamp or timestamp.endswith('+00:00')):
                    pass  # Already ISO8601
                else:
                    # Try to parse and reformat
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        timestamp = dt.isoformat()
                    except:
                        # Fallback to current time
                        timestamp = datetime.now(timezone.utc).isoformat()
            else:
                timestamp = datetime.now(timezone.utc).isoformat()
            
            # Build alert entry
            alert_entry = {
                'timestamp': timestamp,
                'risk_score': round(float(risk_score), 2),
                'action': action,
                'file_path': resolved_file_path if resolved_file_path and not is_clipboard_placeholder else 'Clipboard Content',
                'file_name': resolved_file_name if resolved_file_name and not is_clipboard_placeholder else 'Clipboard',
                'keywords': keywords,
                'window_title': context.get('window_title') or context.get('active_window') or '',
                'process_name': context.get('process_name') or '',
                'user': context.get('user') or 'unknown',
                'source': context.get('source') or 'unknown',
                'is_clipboard': str(file_path) == 'clipboard://clipboard_content' if file_path else False
            }
            
            # Load existing alerts
            alerts = []
            if self.dashboard_log_path.exists():
                try:
                    with open(self.dashboard_log_path, 'r', encoding='utf-8') as f:
                        alerts = json.load(f)
                        if not isinstance(alerts, list):
                            alerts = []
                except (json.JSONDecodeError, IOError) as e:
                    logger.warning(f"Error reading dashboard log: {e}, creating new file")
                    alerts = []
            
            # Append new alert
            alerts.append(alert_entry)
            
            # Keep only last 1000 alerts to prevent file from growing too large
            if len(alerts) > 1000:
                alerts = alerts[-1000:]
            
            # Write back to file
            with open(self.dashboard_log_path, 'w', encoding='utf-8') as f:
                json.dump(alerts, f, indent=2, ensure_ascii=False)
            
            pid = os.getpid()
            logger.info(
                f"[PID={pid}] Saved alert to dashboard: "
                f"action={action}, score={risk_score}, "
                f"keywords={keywords}, path={self.dashboard_log_path}, "
                f"total_alerts={len(alerts)}"
            )
            return True
            
        except Exception as e:
            pid = os.getpid()
            logger.error(
                f"[PID={pid}] Error saving to dashboard log: {e} | "
                f"Path: {self.dashboard_log_path} | "
                f"Path exists: {self.dashboard_log_path.exists()} | "
                f"Parent exists: {self.dashboard_log_path.parent.exists()}"
            )
            return False