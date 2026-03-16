"""
Fast Scan Module - YARA Rules và Header Check
"""
import yara
from pathlib import Path
from typing import Dict, List, Any, Optional
from loguru import logger
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    logger.warning("python-magic not available, file type detection limited")


class FastScanEngine:
    """Fast Scan với YARA và Header Check"""
    
    def __init__(self):
        self.yara_rules = None
        self.mime = None
        self._load_yara_rules()
        self._init_file_type_detection()
    
    def _load_yara_rules(self):
        """Load YARA rules"""
        try:
            rule_files = WorkerConfig.load_yara_rules()
            if rule_files:
                # Filter chỉ lấy file tồn tại
                existing_rules = {k: v for k, v in rule_files.items() if Path(v).exists()}
                
                if existing_rules:
                    self.yara_rules = yara.compile(filepaths=existing_rules)
                    logger.info(f"Loaded {len(existing_rules)} YARA rule files: {list(existing_rules.keys())}")
                else:
                    logger.warning("No YARA rule files found")
                    self.yara_rules = None
            else:
                logger.warning("No YARA rules configured")
                self.yara_rules = None
        except yara.Error as e:
            logger.error(f"Error loading YARA rules: {e}")
            self.yara_rules = None
        except Exception as e:
            logger.error(f"Unexpected error loading YARA rules: {e}")
            self.yara_rules = None
    
    def _init_file_type_detection(self):
        """Khởi tạo file type detection"""
        if MAGIC_AVAILABLE:
            try:
                self.mime = magic.Magic(mime=True)
            except Exception as e:
                logger.warning(f"Error initializing magic: {e}")
                self.mime = None
        else:
            self.mime = None
    
    def scan_file(self, file_path: Path, panic_mode: bool = False) -> Dict[str, Any]:
        """
        Scan file với YARA và Header Check
        
        Args:
            file_path: Đường dẫn file cần scan
            panic_mode: Nếu True, chỉ chạy YARA nhanh, skip các check phức tạp
        
        Returns:
            {
                'yara_matches': [...],
                'file_type': 'image/jpeg',
                'is_encrypted_zip': False,
                'is_suspicious': False,
                'scan_time_ms': 5.2
            }
        """
        import time
        start_time = time.time()
        
        result = {
            'yara_matches': [],
            'file_type': None,
            'is_encrypted_zip': False,
            'is_suspicious': False,
            'scan_time_ms': 0
        }
        
        if not file_path.exists():
            logger.warning(f"File not found: {file_path}")
            return result
        
        try:
            # 1. YARA Scan (luôn chạy, kể cả panic mode)
            if self.yara_rules:
                try:
                    matches = self.yara_rules.match(str(file_path), timeout=10)
                    result['yara_matches'] = [
                        {
                            'rule': match.rule,
                            'tags': list(match.tags),
                            'strings': [str(s) for s in match.strings[:5]]  # Limit strings
                        }
                        for match in matches
                    ]
                    
                    if matches:
                        result['is_suspicious'] = True
                        logger.debug(f"YARA match in {file_path.name}: {[m.rule for m in matches]}")
                except yara.TimeoutError:
                    logger.warning(f"YARA scan timeout for {file_path}")
                except Exception as e:
                    logger.warning(f"YARA scan error for {file_path}: {e}")
            
            # 2. Header Check (File Type Detection) - Skip nếu panic mode
            if not panic_mode:
                if self.mime:
                    try:
                        result['file_type'] = self.mime.from_file(str(file_path))
                    except Exception as e:
                        logger.debug(f"File type detection error: {e}")
                else:
                    # Fallback: check extension
                    result['file_type'] = self._get_file_type_from_extension(file_path)
                
                # 3. Encrypted Zip Detection
                result['is_encrypted_zip'] = self._check_encrypted_zip(file_path)
                if result['is_encrypted_zip']:
                    result['is_suspicious'] = True
                    logger.warning(f"Encrypted ZIP detected: {file_path.name}")
            
            result['scan_time_ms'] = (time.time() - start_time) * 1000
            
        except Exception as e:
            logger.error(f"Fast scan error for {file_path}: {e}")
            result['scan_time_ms'] = (time.time() - start_time) * 1000
        
        return result
    
    def _get_file_type_from_extension(self, file_path: Path) -> str:
        """Fallback: lấy file type từ extension"""
        ext = file_path.suffix.lower()
        type_map = {
            '.txt': 'text/plain',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.pdf': 'application/pdf',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.zip': 'application/zip',
            '.rar': 'application/x-rar-compressed',
        }
        return type_map.get(ext, 'application/octet-stream')
    
    def _check_encrypted_zip(self, file_path: Path) -> bool:
        """Kiểm tra file ZIP có mật khẩu không"""
        try:
            import zipfile
            
            if not file_path.suffix.lower() == '.zip':
                return False
            
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                # Kiểm tra xem có file nào được encrypt không
                for info in zip_file.infolist():
                    if info.flag_bits & 0x1:  # Bit 0 = encrypted
                        return True
            return False
        except zipfile.BadZipFile:
            return False
        except Exception as e:
            logger.debug(f"Error checking encrypted zip: {e}")
            return False
    
    def scan_text_content(self, text_content: str, panic_mode: bool = False) -> Dict[str, Any]:
        """
        Scan text content với YARA rules (cho clipboard, OCR text, etc.)
        
        Args:
            text_content: Text content cần scan
            panic_mode: Nếu True, chỉ chạy YARA nhanh
        
        Returns:
            {
                'yara_matches': [...],
                'is_suspicious': False,
                'scan_time_ms': 5.2
            }
        """
        import time
        import tempfile
        start_time = time.time()
        
        result = {
            'yara_matches': [],
            'is_suspicious': False,
            'scan_time_ms': 0
        }
        
        if not text_content or not text_content.strip():
            return result
        
        try:
            # YARA cần scan từ file hoặc memory
            # Tạo temp file để scan
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.txt', delete=False) as tmp_file:
                tmp_file.write(text_content)
                tmp_path = tmp_file.name
            
            try:
                # 1. YARA Scan
                if self.yara_rules:
                    try:
                        matches = self.yara_rules.match(tmp_path, timeout=10)
                        result['yara_matches'] = [
                            {
                                'rule': match.rule,
                                'tags': list(match.tags),
                                'strings': [str(s) for s in match.strings[:5]]  # Limit strings
                            }
                            for match in matches
                        ]
                        
                        if matches:
                            result['is_suspicious'] = True
                            logger.debug(f"YARA match in text content: {[m.rule for m in matches]}")
                    except yara.TimeoutError:
                        logger.warning(f"YARA scan timeout for text content")
                    except Exception as e:
                        logger.warning(f"YARA scan error for text content: {e}")
            finally:
                # Cleanup temp file
                try:
                    Path(tmp_path).unlink()
                except Exception:
                    pass
            
            result['scan_time_ms'] = (time.time() - start_time) * 1000
            
        except Exception as e:
            logger.error(f"Fast scan text content error: {e}")
            result['scan_time_ms'] = (time.time() - start_time) * 1000
        
        return result