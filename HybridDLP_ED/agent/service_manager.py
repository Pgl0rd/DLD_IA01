"""
service_manager.py — Quản lý Sensor và Worker

Start/Stop sensor và worker processes
"""

import subprocess
import os
import sys
import time
from pathlib import Path
from typing import Optional, Tuple


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class ServiceManager:
    """Quản lý Sensor và Worker."""
    
    def __init__(self):
        self.sensor_process: Optional[subprocess.Popen] = None
        self.worker_process: Optional[subprocess.Popen] = None
    
    def _get_python_executable(self) -> str:
        """Lấy đường dẫn Python executable."""
        return sys.executable
    
    def start_sensor(self) -> Tuple[bool, str]:
        """Khởi động Sensor."""
        try:
            if self.sensor_process and self.sensor_process.poll() is None:
                return False, "Sensor đang chạy"
            
            # Chạy: python -m agent
            self.sensor_process = subprocess.Popen(
                [self._get_python_executable(), "-m", "agent"],
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
            )
            
            # Chờ xem có crash không
            time.sleep(2)
            if self.sensor_process.poll() is not None:
                _, err = self.sensor_process.communicate()
                return False, f"Sensor khởi động thất bại: {err.decode()[:200]}"
            
            return True, "Sensor đã khởi động"
        except Exception as e:
            return False, f"Lỗi khởi động Sensor: {e}"
    
    def stop_sensor(self) -> Tuple[bool, str]:
        """Tắt Sensor."""
        try:
            if not self.sensor_process or self.sensor_process.poll() is not None:
                return False, "Sensor không chạy"
            
            if sys.platform == "win32":
                os.killpg(os.getpgid(self.sensor_process.pid), 9)
            else:
                self.sensor_process.terminate()
            
            self.sensor_process.wait(timeout=5)
            return True, "Sensor đã tắt"
        except subprocess.TimeoutExpired:
            self.sensor_process.kill()
            return True, "Sensor đã dừng (force)"
        except Exception as e:
            return False, f"Lỗi tắt Sensor: {e}"
    
    def is_sensor_running(self) -> bool:
        """Kiểm tra Sensor có chạy không."""
        return self.sensor_process is not None and self.sensor_process.poll() is None
    
    def start_worker(self) -> Tuple[bool, str]:
        """Khởi động Worker (Docker)."""
        try:
            # Chạy: docker-compose up -d worker
            result = subprocess.run(
                ["docker-compose", "up", "-d", "worker"],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
            )
            
            if result.returncode == 0:
                return True, "Worker đã khởi động"
            else:
                return False, f"Lỗi khởi động Worker: {result.stderr[:200]}"
        except FileNotFoundError:
            return False, "Docker Compose không tìm thấy"
        except Exception as e:
            return False, f"Lỗi khởi động Worker: {e}"
    
    def stop_worker(self) -> Tuple[bool, str]:
        """Tắt Worker (Docker)."""
        try:
            result = subprocess.run(
                ["docker-compose", "stop", "worker"],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
            )
            
            if result.returncode == 0:
                return True, "Worker đã tắt"
            else:
                return False, f"Lỗi tắt Worker: {result.stderr[:200]}"
        except Exception as e:
            return False, f"Lỗi tắt Worker: {e}"
    
    def is_worker_running(self) -> bool:
        """Kiểm tra Worker có chạy không."""
        try:
            result = subprocess.run(
                ["docker-compose", "ps", "-q", "worker"],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
            )
            return result.returncode == 0 and len(result.stdout.strip()) > 0
        except:
            return False


_service_manager = ServiceManager()

def get_service_manager() -> ServiceManager:
    return _service_manager
