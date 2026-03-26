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


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return float(default)


def _env_float_bounded(name: str, default: float, min_v: float, max_v: float) -> float:
    v = _env_float(name, default)
    if v < min_v:
        return float(min_v)
    if v > max_v:
        return float(max_v)
    return float(v)

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
        'alert': _env_float_bounded("RISK_ALERT_THRESHOLD", 40.0, 40.0, 70.0),
        'log': 0
    }

    # Phân loại mức độ rủi ro trên thang điểm tổng 0–100 (điều chỉnh được qua biến môi trường)
    # low: [0, low_max), medium: [low_max, medium_max), high: [medium_max, high_max), critical: [high_max, 100]
    RISK_LEVEL_LOW_MAX = _env_float_bounded("RISK_LEVEL_LOW_MAX", 25.0, 10.0, 40.0)
    RISK_LEVEL_MEDIUM_MAX = _env_float_bounded("RISK_LEVEL_MEDIUM_MAX", 50.0, 30.0, 70.0)
    RISK_LEVEL_HIGH_MAX = _env_float_bounded("RISK_LEVEL_HIGH_MAX", 75.0, 55.0, 95.0)
    
    # ML Anomaly Detection Thresholds
    ML_ANOMALY_THRESHOLD = _env_float_bounded("ML_ANOMALY_THRESHOLD", 70.0, 40.0, 95.0)
    ML_ANOMALY_BOOST_THRESHOLD = _env_float_bounded("ML_ANOMALY_BOOST_THRESHOLD", 70.0, 40.0, 95.0)

    # Phương pháp traditional: điểm anomaly UEBA (0–100) gộp vào Behavior score
    # S_behavior = min(100, S_behavior^0 + β * S_anomaly), β = ML_ANOMALY_BEHAVIOR_BLEND
    ML_ANOMALY_BEHAVIOR_BLEND = _env_float_bounded("ML_ANOMALY_BEHAVIOR_BLEND", 0.25, 0.0, 1.0)
    ML_ANOMALY_RISK_BOOST_FACTOR = _env_float_bounded("ML_ANOMALY_RISK_BOOST_FACTOR", 0.0, 0.0, 1.0)

    # Composite model for final risk:
    # - "weighted_sum": R = wc*Sc + wb*Sb + wx*Sx
    # - "nist_multiplicative": Impact=Sc, Likelihood=alpha*Sb + (1-alpha)*Sx, R=(Impact*Likelihood)/100
    RISK_COMPOSITE_MODEL = os.getenv("RISK_COMPOSITE_MODEL", "nist_multiplicative").strip().lower()
    RISK_LIKELIHOOD_ALPHA = _env_float_bounded("RISK_LIKELIHOOD_ALPHA", 0.6, 0.0, 1.0)

    # Anomaly normalization policy for raw anomaly signal (if any):
    # - "percentile": robust clipping with p5/p95 then map to [0,100]
    # - "minmax": min-max map to [0,100]
    ML_ANOMALY_NORM_METHOD = os.getenv("ML_ANOMALY_NORM_METHOD", "percentile").strip().lower()
    ML_ANOMALY_P5 = _env_float("ML_ANOMALY_P5", -0.6)
    ML_ANOMALY_P95 = _env_float("ML_ANOMALY_P95", 0.6)
    ML_ANOMALY_MIN = _env_float("ML_ANOMALY_MIN", -1.0)
    ML_ANOMALY_MAX = _env_float("ML_ANOMALY_MAX", 1.0)
    
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
