"""
system_tray_app.py — System Tray Application

Icon ở system tray để manage HybridDLP
"""

import sys
import threading
from pathlib import Path
import queue

try:
    from pystray import Icon, Menu, MenuItem
    from PIL import Image, ImageDraw
    HAS_PYSTRAY = True
except ImportError:
    HAS_PYSTRAY = False

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agent.setup_wizard import run_setup_wizard
from agent.main_window import show_main_window
from agent.service_manager import get_service_manager
from agent.password_manager import is_password_set


class SystemTrayApp:
    """Ứng dụng system tray."""
    
    def __init__(self):
        self.icon = None
        self.manager = get_service_manager()
        self.action_queue = queue.Queue()
        self.running = False
    
    def _create_icon_image(self, size=64):
        """Tạo icon image."""
        image = Image.new('RGB', (size, size), color=(30, 30, 30))
        draw = ImageDraw.Draw(image)
        
        # Vẽ DLP text
        try:
            draw.text((10, 20), "DLP", fill=(0, 200, 100))
        except:
            # Nếu không có font, vẽ hình vuông
            draw.rectangle([10, 10, 54, 54], outline=(0, 200, 100))
        
        return image
    
    def _on_show_control(self, icon, item):
        """Click show control center."""
        # Run in separate thread để tránh block tray icon
        def show_gui():
            try:
                show_main_window(on_close_callback=lambda: None)
            except Exception as e:
                print(f"❌ Error showing control center: {e}")
        
        thread = threading.Thread(target=show_gui, daemon=True)
        thread.start()
    
    def _on_setup_wizard(self, icon, item):
        """Show setup wizard."""
        def run_wizard():
            try:
                if run_setup_wizard():
                    print("✅ Setup completed")
            except Exception as e:
                print(f"❌ Error in setup: {e}")
        
        thread = threading.Thread(target=run_wizard, daemon=True)
        thread.start()
    
    def _on_sensor_status(self, icon, item):
        """Show sensor status."""
        status = "🟢 Running" if self.manager.is_sensor_running() else "🔴 Stopped"
        print(f"[Sensor] Status: {status}")
    
    def _on_worker_status(self, icon, item):
        """Show worker status."""
        status = "🟢 Running" if self.manager.is_worker_running() else "🔴 Stopped"
        print(f"[Worker] Status: {status}")

    def _on_start_worker(self, icon, item):
        """Start worker from tray."""
        success, msg = self.manager.start_worker()
        print(f"[Worker] Start: {msg}")

    def _on_stop_worker(self, icon, item):
        """Stop worker from tray."""
        success, msg = self.manager.stop_worker()
        print(f"[Worker] Stop: {msg}")
    
    def _on_exit(self, icon, item):
        """Exit application."""
        self.running = False
        icon.stop()
    
    def _create_menu(self):
        """Tạo context menu."""
        sensor_status = "🟢 Running" if self.manager.is_sensor_running() else "🔴 Stopped"
        worker_status = "🟢 Running" if self.manager.is_worker_running() else "🔴 Stopped"
        
        menu_items = [
            MenuItem(
                "🎛️  Control Center",
                self._on_show_control
            ),
        ]
        
        # Add setup wizard option if not initialized
        if not is_password_set():
            menu_items.append(
                MenuItem(
                    "⚙️  Setup Wizard",
                    self._on_setup_wizard
                )
            )
        
        menu_items.extend([
            MenuItem(
                "---",
                lambda: None,
                enabled=False
            ),
            MenuItem(
                "Sensor",
                Menu(
                    MenuItem(
                        f"Status: {sensor_status}",
                        self._on_sensor_status,
                        enabled=False
                    ),
                )
            ),
            MenuItem(
                "Worker",
                Menu(
                    MenuItem(
                        "Start",
                        self._on_start_worker
                    ),
                    MenuItem(
                        "Stop",
                        self._on_stop_worker
                    ),
                    MenuItem(
                        f"Status: {worker_status}",
                        self._on_worker_status,
                        enabled=False
                    ),
                )
            ) ,
            MenuItem(
                "---",
                lambda: None,
                enabled=False
            ),
            MenuItem(
                "Exit",
                self._on_exit
            ),
        ])
        
        return Menu(*menu_items)
    
    def run(self):
        """Chạy system tray app."""
        if not HAS_PYSTRAY:
            print("❌ pystray not installed. Install with: pip install pystray pillow")
            return False
        
        try:
            image = self._create_icon_image()
            self.icon = Icon("HybridDLP", image, menu=self._create_menu())
            self.running = True
            
            # Chạy icon ở non-daemon thread (không phải daemon thread)
            # pystray cần chạy ở thread chính để tránh Tkinter errors
            def run_icon():
                try:
                    self.icon.run()
                except Exception as e:
                    print(f"❌ Tray icon error: {e}")
            
            self.tray_thread = threading.Thread(target=run_icon, daemon=False)
            self.tray_thread.start()
            
            return True
        except Exception as e:
            print(f"❌ Error creating system tray: {e}")
            return False
    
    def wait(self):
        """Block until tray is stopped."""
        try:
            while self.running:
                import time
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.running = False
            if self.icon:
                self.icon.stop()
    
    def stop(self):
        """Stop tray app."""
        self.running = False
        if self.icon:
            try:
                self.icon.stop()
            except:
                pass


def show_system_tray():
    """Hiển thị system tray app."""
    app = SystemTrayApp()
    if app.run():
        return app
    return None
