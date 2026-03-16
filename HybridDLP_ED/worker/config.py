"""
Configuration cho Detection Engine (L3)
"""
import os
from pathlib import Path
from typing import Dict, Any

# Base directory
# Fix: Use absolute path to avoid resolution issues in Docker
# In Docker, worker runs from /app, so BASE_DIR should be /app
_config_file = Path(__file__).resolve()
BASE_DIR = Path("/app") if Path("/app").exists() else _config_file.parent.parent.resolve()
AGENT_DIR = BASE_DIR / "agent"
WORKER_DIR = BASE_DIR / "worker"

class WorkerConfig:
    """Configuration cho Detection Engine Worker"""
    
    # Paths
    BASE_DIR = BASE_DIR
    WORKER_DIR = WORKER_DIR
    AGENT_DIR = AGENT_DIR
    RUNTIME_DIR = AGENT_DIR / "runtime"
    # YARA rules are mounted at /app/yara_rules in Docker
    YARA_RULES_DIR = Path("/app/yara_rules") if Path("/app/yara_rules").exists() else WORKER_DIR / "yara_rules"
    ML_MODELS_DIR = WORKER_DIR / "ml_models"
    CACHE_DB_PATH = WORKER_DIR / "database" / "cache.db"
    LOGS_DIR = WORKER_DIR / "logs"
    
    # IPC Queue Configuration
    # Worker đọc events từ SQLite database
    EVENTS_DB_PATH = RUNTIME_DIR / "events.db"  # SQLite events từ agent
    
    # Hash Cache
    HASH_ALGORITHM = "sha256"  # md5 or sha256
    CACHE_CLEANUP_DAYS = 30  # Xóa cache cũ sau 30 ngày
    
    # Fast Scan
    YARA_RULES = [
        # PII Detection
        YARA_RULES_DIR / "vietnam_id.yar",
        YARA_RULES_DIR / "vietnam_id_single.yar",  # Single ID without keywords
        YARA_RULES_DIR / "credit_card.yar",
        YARA_RULES_DIR / "credit_card_single.yar",  # Single credit card
        YARA_RULES_DIR / "email.yar",
        YARA_RULES_DIR / "email_single.yar",  # Single email in context
        YARA_RULES_DIR / "phone_number.yar",
        YARA_RULES_DIR / "phone_number_single.yar",  # Single phone in context
        YARA_RULES_DIR / "bank_account.yar",
        # Sensitive Data
        YARA_RULES_DIR / "api_key.yar",  # Enhanced with more API key types
        YARA_RULES_DIR / "financial_data.yar",
        YARA_RULES_DIR / "source_code.yar",
        YARA_RULES_DIR / "contract_legal.yar",
        YARA_RULES_DIR / "hr_data.yar",
        # Export Detection
        YARA_RULES_DIR / "csv_excel_sensitive.yar",
        # Archive Detection
        YARA_RULES_DIR / "password_protected_archive.yar",
    ]
    
    # Overload Protection
    PANIC_MODE_THRESHOLD = 1000  # Queue size trigger
    PANIC_MODE_DISABLE_THRESHOLD = 500  # Disable khi queue < 500
    
    # OCR Configuration
    OCR_ENABLED = True
    OCR_MAX_FILE_SIZE_MB = 5
    OCR_MAX_CPU_PERCENT = 70
    OCR_SUPPORTED_FORMATS = ['.jpg', '.jpeg', '.png', '.pdf', '.tiff']
    OCR_TIMEOUT_SECONDS = 30
    
    # ML Configuration
    ML_MODEL_PATH = ML_MODELS_DIR / "classifier.pkl"
    ML_VECTORIZER_PATH = ML_MODELS_DIR / "vectorizer.pkl"
    ML_CONFIDENCE_THRESHOLD = 0.7
    ML_MAX_TEXT_LENGTH = 10000  # Max characters để đọc từ file
    
    # Risk Scoring
    RISK_THRESHOLDS = {
        # System requirement: alert-only (no blocking). Keep key for compatibility but make it unreachable.
        'block': 10**9,
        'alert': 40,  # Lowered from 50 to 40 for more sensitive detection
        'log': 0
    }
    
    # ML Anomaly Detection Thresholds
    ML_ANOMALY_THRESHOLD = float(os.getenv('ML_ANOMALY_THRESHOLD', '70.0'))  # Score > 70 = anomaly (lowered from 75)
    ML_ANOMALY_BOOST_THRESHOLD = float(os.getenv('ML_ANOMALY_BOOST_THRESHOLD', '70.0'))  # Threshold for likelihood boost
    
    # Behavioral Risk Boost Values
    BEHAVIORAL_RISK_BOOST = {
        'high': 40,    # Lowered from 50 to 40
        'medium': 25,  # Lowered from 30 to 25
        'low': 8       # Lowered from 10 to 8
    }
    
    RISK_WEIGHTS = {
        'content': 0.5,
        'behavior': 0.3,
        'context': 0.2
    }
    
    # Research-based Risk Scoring Weights (Composite Multi-Factor)
    RESEARCH_RISK_WEIGHTS = {
        'anomaly': 0.25,
        'behavioral_deviation': 0.25,
        'content_sensitivity': 0.30,
        'temporal': 0.10,
        'frequency': 0.10
    }
    
    # NIST SP 800-30 Based Risk Scoring Configuration
    # L = Σ(wj * cj) / Σ(wj)  with 0 <= cj <= 5
    NIST_LIKELIHOOD_WEIGHTS = {
        'destination': 0.4,      # USB/Cloud/Email channel
        'user_behavior': 0.3,    # Off-hours, bulk operations
        'file_protection': 0.2,  # Encryption, obfuscation
        'frequency': 0.1         # Frequency of risky actions
    }
    
    # Max values for normalization when mapping R = L * I to 0-100
    NIST_MAX_VALUES = {
        'likelihood_max': 5.0,   # Max L on 1–5 scale
        'impact_max': 4.0        # Max I on 1–4 scale (Public→Secret)
    }
    
    # Risk Scoring Method: 'traditional', 'research_based', or 'nist_based'
    # Mặc định dùng NIST-based theo yêu cầu đồ án
    RISK_SCORING_METHOD = os.getenv('RISK_SCORING_METHOD', 'nist_based')
    
    # Sensitive exfiltration folders (Windows paths in agent events)
    # Ví dụ: "C:\\PrivateFolder;D:\\HR_Secret"
    _sensitive_folders_env = os.getenv("SENSITIVE_EXFIL_FOLDERS", r"C:\PrivateFolder")
    SENSITIVE_EXFIL_FOLDERS = [
        folder.strip().lower()
        for folder in _sensitive_folders_env.split(";")
        if folder.strip()
    ]
    
    # Server Communication
    SERVER_URL = os.getenv("SERVER_URL", "https://dlp-server.example.com")
    SERVER_API_KEY = os.getenv("SERVER_API_KEY", "")
    DEVICE_ID = os.getenv("DEVICE_ID", "worker-1")
    SERVER_TIMEOUT = 5  # seconds
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = LOGS_DIR / "detection_engine.log"
    LOG_ROTATION = "10 MB"
    LOG_RETENTION = "7 days"
    
    # File Processing
    MAX_FILE_SIZE_MB = 100  # Skip files larger than this
    SUPPORTED_FILE_TYPES = [
        '.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp',
        '.zip', '.rar', '.7z'
    ]
    
    @classmethod
    def load_yara_rules(cls) -> Dict[str, str]:
        """Load YARA rules"""
        rules = {}
        for rule_file in cls.YARA_RULES:
            if rule_file.exists():
                rules[rule_file.stem] = str(rule_file)
        return rules
    
    @classmethod
    def ensure_directories(cls):
        """Tạo các thư mục cần thiết"""
        cls.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        cls.YARA_RULES_DIR.mkdir(parents=True, exist_ok=True)
        cls.ML_MODELS_DIR.mkdir(parents=True, exist_ok=True)
        cls.CACHE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        cls.RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
