"""
Hash Cache Manager - Quản lý cache để skip file đã scan
"""
import sqlite3
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from loguru import logger
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig


class HashCacheManager:
    """Quản lý Hash Cache để skip file đã scan"""
    
    def __init__(self, db_path: Path = None):
        self.db_path = db_path or WorkerConfig.CACHE_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """Khởi tạo database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_cache (
                    file_hash TEXT PRIMARY KEY,
                    file_path TEXT,
                    file_size INTEGER,
                    scan_result TEXT,
                    risk_score REAL,
                    action_taken TEXT,
                    last_scan TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    scan_count INTEGER DEFAULT 1
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_file_path ON file_cache(file_path)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_last_scan ON file_cache(last_scan)")
            conn.commit()
            conn.close()
            logger.info(f"Hash cache database initialized: {self.db_path}")
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
    
    def calculate_hash(self, file_path: Path) -> str:
        """Tính hash của file"""
        hash_algo = getattr(hashlib, WorkerConfig.HASH_ALGORITHM)()
        
        try:
            with open(file_path, 'rb') as f:
                # Read in chunks để tiết kiệm memory
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_algo.update(chunk)
            return hash_algo.hexdigest()
        except PermissionError:
            logger.warning(f"Permission denied: {file_path}")
            return ""
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def get_cached_result(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Lấy kết quả từ cache"""
        if not file_hash:
            return None
            
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT file_hash, scan_result, risk_score, action_taken, last_scan
                FROM file_cache
                WHERE file_hash = ?
            """, (file_hash,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'file_hash': row['file_hash'],
                    'scan_result': row['scan_result'],
                    'risk_score': row['risk_score'],
                    'action_taken': row['action_taken'],
                    'last_scan': row['last_scan']
                }
            return None
        except Exception as e:
            logger.error(f"Error querying cache: {e}")
            return None
    
    def save_result(self, file_hash: str, file_path: str, file_size: int,
                   scan_result: str, risk_score: float, action_taken: str):
        """Lưu kết quả vào cache"""
        if not file_hash:
            return
            
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if exists
            cursor.execute("SELECT scan_count FROM file_cache WHERE file_hash = ?", (file_hash,))
            existing = cursor.fetchone()
            scan_count = (existing[0] if existing else 0) + 1
            
            cursor.execute("""
                INSERT OR REPLACE INTO file_cache
                (file_hash, file_path, file_size, scan_result, risk_score, 
                 action_taken, last_scan, scan_count)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
            """, (file_hash, file_path, file_size, scan_result, risk_score, 
                  action_taken, scan_count))
            
            conn.commit()
            conn.close()
            logger.debug(f"Cached result for hash: {file_hash[:16]}...")
        except Exception as e:
            logger.error(f"Error saving to cache: {e}")
    
    def cleanup_old_entries(self, days: int = None):
        """Xóa cache cũ"""
        days = days or WorkerConfig.CACHE_CLEANUP_DAYS
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                DELETE FROM file_cache
                WHERE last_scan < datetime('now', '-' || ? || ' days')
            """, (days,))
            
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} old cache entries")
        except Exception as e:
            logger.error(f"Error cleaning cache: {e}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Lấy thống kê cache"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM file_cache")
            total = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM file_cache WHERE scan_result = 'safe'")
            safe = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM file_cache WHERE scan_result = 'malicious'")
            malicious = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total': total,
                'safe': safe,
                'malicious': malicious,
                'other': total - safe - malicious
            }
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {'total': 0, 'safe': 0, 'malicious': 0, 'other': 0}
