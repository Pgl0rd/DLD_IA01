"""
Windows Notification Module - Hiển thị thông báo trên Windows
"""
import sys
from typing import Dict, Any, Optional
from loguru import logger

# Try to import Windows-specific libraries
try:
    import win10toast
    WIN10TOAST_AVAILABLE = True
except ImportError:
    WIN10TOAST_AVAILABLE = False
    logger.warning("win10toast not available, trying alternative methods")

try:
    import win32api
    import win32con
    import win32gui
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    logger.debug("pywin32 not available for message box")

try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False
    logger.debug("plyer not available")


class WindowsNotification:
    """Hiển thị thông báo Windows cho người dùng"""
    
    def __init__(self):
        self.method = self._detect_best_method()
        if self.method == 'console':
            logger.info("Windows notification: Using console fallback (running in Docker/Linux)")
        else:
            logger.info(f"Windows notification method: {self.method}")
    
    def _detect_best_method(self) -> str:
        """Detect best available notification method"""
        if WIN10TOAST_AVAILABLE:
            return 'win10toast'
        elif PLYER_AVAILABLE:
            return 'plyer'
        elif WIN32_AVAILABLE:
            return 'win32_messagebox'
        else:
            return 'console'  # Fallback to console
    
    def show_alert(self, 
                   title: str,
                   message: str,
                   severity: str = "warning",
                   duration: int = 10) -> bool:
        """
        Hiển thị thông báo alert trên Windows
        
        Args:
            title: Tiêu đề thông báo
            message: Nội dung thông báo
            severity: "warning", "error", "info"
            duration: Thời gian hiển thị (giây)
        
        Returns:
            True nếu thành công
        """
        try:
            if self.method == 'win10toast':
                return self._show_win10toast(title, message, duration)
            elif self.method == 'plyer':
                return self._show_plyer(title, message, duration)
            elif self.method == 'win32_messagebox':
                return self._show_win32_messagebox(title, message, severity)
            else:
                # Fallback: console output
                logger.warning(f"ALERT: {title} - {message}")
                return True
        except Exception as e:
            logger.error(f"Error showing notification: {e}")
            # Fallback to console
            logger.warning(f"ALERT: {title} - {message}")
            return False
    
    def _show_win10toast(self, title: str, message: str, duration: int) -> bool:
        """Show notification using win10toast"""
        try:
            toaster = win10toast.ToastNotifier()
            toaster.show_toast(
                title=title,
                msg=message,
                duration=duration,
                icon_path=None,  # Có thể thêm icon sau
                threaded=True
            )
            return True
        except Exception as e:
            logger.error(f"win10toast error: {e}")
            return False
    
    def _show_plyer(self, title: str, message: str, duration: int) -> bool:
        """Show notification using plyer"""
        try:
            notification.notify(
                title=title,
                message=message,
                timeout=duration,
                app_name="HybridDLP"
            )
            return True
        except Exception as e:
            logger.error(f"plyer error: {e}")
            return False
    
    def _show_win32_messagebox(self, title: str, message: str, severity: str) -> bool:
        """Show message box using win32api"""
        try:
            # Map severity to win32 message box type
            if severity == "error":
                mb_type = win32con.MB_ICONERROR | win32con.MB_OK
            elif severity == "warning":
                mb_type = win32con.MB_ICONWARNING | win32con.MB_OK
            else:
                mb_type = win32con.MB_ICONINFORMATION | win32con.MB_OK
            
            win32api.MessageBox(0, message, title, mb_type)
            return True
        except Exception as e:
            logger.error(f"win32 messagebox error: {e}")
            return False
    
    def show_violation_alert(self,
                            violation_type: str,
                            details: Optional[Dict[str, Any]] = None) -> bool:
        """
        Hiển thị thông báo vi phạm chuẩn
        
        Args:
            violation_type: Loại vi phạm (ví dụ: "Sensitive Data", "Clipboard Paste")
            details: Chi tiết vi phạm
        
        Returns:
            True nếu thành công
        """
        # Build message
        title = "HybridDLP - Vi Pham Bao Mat"
        
        message_parts = [
            "BẠN ĐÃ VI PHẠM CHÍNH SÁCH BẢO MẬT!",
            "",
            f"Loại vi phạm: {violation_type}"
        ]
        
        if details:
            if details.get('window_title'):
                message_parts.append(f"Ứng dụng: {details['window_title']}")
            if details.get('yara_matches'):
                matches = details['yara_matches']
                if matches:
                    rules = [m.get('rule', '') for m in matches[:3]]
                    message_parts.append(f"Phát hiện: {', '.join(rules)}")
            if details.get('risk_score'):
                message_parts.append(f"Độ nguy hiểm: {details['risk_score']:.1f}/10")
        
        message_parts.extend([
            "",
            "Hành động của bạn đã được ghi lại.",
            "Vui lòng tuân thủ chính sách bảo mật công ty."
        ])
        
        message = "\n".join(message_parts)
        
        # Show notification
        return self.show_alert(
            title=title,
            message=message,
            severity="warning",
            duration=15  # Hiển thị 15 giây
        )
