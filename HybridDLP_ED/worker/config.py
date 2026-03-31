"""
Configuration cho Detection Engine (L3)
"""
import os
from pathlib import Path
from typing import Dict, Any

# Base directory
# - Docker Linux: /app
# - Native Windows/Linux: project root (parent of worker/)
_config_file = Path(__file__).resolve()
_docker_app = Path("/app")
_running_in_docker = (
    os.name != "nt"
    and (_docker_app.exists() or Path("/.dockerenv").exists())
)
BASE_DIR = _docker_app if _running_in_docker else _config_file.parent.parent.resolve()
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

def _env_queue_backend() -> str:
    v = os.getenv("WORKER_QUEUE_BACKEND", "sqlite").strip().lower()
    return v if v in ("sqlite", "jsonl") else "sqlite"


class WorkerConfig:
    """Configuration cho Detection Engine Worker"""
    
    # Paths
    BASE_DIR = BASE_DIR
    WORKER_DIR = WORKER_DIR
    AGENT_DIR = AGENT_DIR
    RUNTIME_DIR = AGENT_DIR / "runtime"
    # SQLite thống nhất: queue + (mặc định) hash cache — kiến trúc 2 process (Noteupdate)
    AGENT_STORE_DB = RUNTIME_DIR / "agent_store.db"
    # YARA rules are mounted at /app/yara_rules in Docker
    YARA_RULES_DIR = Path("/app/yara_rules") if Path("/app/yara_rules").exists() else WORKER_DIR / "yara_rules"
    ML_MODELS_DIR = WORKER_DIR / "ml_models"
    # Hash cache cùng file agent_store.db (bảng file_cache) trừ khi ghi đè CACHE_DB_PATH
    CACHE_DB_PATH = Path(os.getenv("CACHE_DB_PATH", str(RUNTIME_DIR / "agent_store.db")))
    LOGS_DIR = WORKER_DIR / "logs"
    # sqlite: PersistentEventQueue | jsonl: đọc events_*.jsonl (legacy)
    WORKER_QUEUE_BACKEND = _env_queue_backend()
    
    # IPC Queue Configuration
    # Worker đọc events từ SQLite database
    EVENTS_DB_PATH = RUNTIME_DIR / "events.db"  # SQLite events từ agent
    
    # Hash Cache (Noteupdate SHA-256 checklist)
    HASH_ALGORITHM = "sha256"  # md5 or sha256 — đồ án nên dùng sha256
    HASH_READ_CHUNK_BYTES = int(os.getenv("HASH_READ_CHUNK_BYTES", str(256 * 1024)))  # 256KB; 1MB cũng ổn
    HASH_COMPUTE_RETRIES = int(os.getenv("HASH_COMPUTE_RETRIES", "3"))
    HASH_STABILITY_ENABLED = os.getenv("HASH_STABILITY_ENABLED", "1").strip().lower() in {"1", "true", "yes", "on"}
    FILE_STABILITY_INTERVAL_SEC = _env_float("FILE_STABILITY_INTERVAL_SEC", 0.15)
    FILE_STABILITY_MAX_WAIT_SEC = _env_float("FILE_STABILITY_MAX_WAIT_SEC", 3.0)
    # Invalidação cache khi policy/YARA/model thay đổi (Noteupdate §14)
    SCAN_ENGINE_VERSION = os.getenv("SCAN_ENGINE_VERSION", "1.0.0").strip() or "1.0.0"
    POLICY_VERSION = os.getenv("POLICY_VERSION", "1.0.0").strip() or "1.0.0"
    # Chống alert lặp cùng hash (giây) — Noteupdate §19
    ALERT_DEDUP_SEC = float(os.getenv("ALERT_DEDUP_SEC", "600"))
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
    
    # Risk Scoring — toàn bộ điểm trên thang 0–10 (cùng ý nghĩa CVSS Base 0–10)
    RISK_SCORE_MAX = 10.0
    RISK_THRESHOLDS = {
        # System requirement: alert-only (no blocking). Keep key for compatibility but make it unreachable.
        'block': 10**9,
        # CVSS > 3.9 cần xử lý ⇒ mặc định 4.0
        'alert': _env_float_bounded("RISK_ALERT_THRESHOLD", 4.0, 3.0, 8.5),
        'log': 0
    }
    # Chỉ hiện popup Windows khi risk đủ cao (giảm spam cảnh báo UI).
    WINDOWS_ALERT_MIN_SCORE = _env_float_bounded("WINDOWS_ALERT_MIN_SCORE", 7.0, 0.0, 10.0)

    # Ranh giới trên thang 0–10: Low <4, Medium 4–6.9, High 7–8.9, Critical ≥9
    RISK_LEVEL_LOW_MAX = 4.0
    RISK_LEVEL_MEDIUM_MAX = 7.0
    RISK_LEVEL_HIGH_MAX = 9.0
    
    # ML Anomaly Detection Thresholds (cùng thang 0–10 với UEBA output)
    ML_ANOMALY_THRESHOLD = _env_float_bounded("ML_ANOMALY_THRESHOLD", 7.0, 4.0, 9.5)
    ML_ANOMALY_BOOST_THRESHOLD = _env_float_bounded("ML_ANOMALY_BOOST_THRESHOLD", 7.0, 4.0, 9.5)

    # Traditional: S_behavior = min(10, S_base + β * S_anomaly), S_anomaly ∈ [0,10]
    ML_ANOMALY_BEHAVIOR_BLEND = _env_float_bounded("ML_ANOMALY_BEHAVIOR_BLEND", 0.25, 0.0, 1.0)
    ML_ANOMALY_RISK_BOOST_FACTOR = _env_float_bounded("ML_ANOMALY_RISK_BOOST_FACTOR", 0.0, 0.0, 1.0)

    # Composite model for final risk:
    # - "weighted_sum": R = wc*Sc + wb*Sb + wx*Sx
    # - "nist_multiplicative": Impact=Sc, Likelihood=alpha*Sb + (1-alpha)*Sx, R=(Impact*Likelihood)/10
    RISK_COMPOSITE_MODEL = os.getenv("RISK_COMPOSITE_MODEL", "nist_multiplicative").strip().lower()
    RISK_LIKELIHOOD_ALPHA = _env_float_bounded("RISK_LIKELIHOOD_ALPHA", 0.6, 0.0, 1.0)

    # Anomaly normalization policy for raw anomaly signal (if any):
    # - "percentile": robust clipping with p5/p95 then map to [0,10]
    # - "minmax": min-max map to [0,10]
    ML_ANOMALY_NORM_METHOD = os.getenv("ML_ANOMALY_NORM_METHOD", "percentile").strip().lower()
    ML_ANOMALY_P5 = _env_float("ML_ANOMALY_P5", -0.6)
    ML_ANOMALY_P95 = _env_float("ML_ANOMALY_P95", 0.6)
    ML_ANOMALY_MIN = _env_float("ML_ANOMALY_MIN", -1.0)
    ML_ANOMALY_MAX = _env_float("ML_ANOMALY_MAX", 1.0)
    
    # Behavioral Risk Boost Values
    BEHAVIORAL_RISK_BOOST = {
        'high': 4.0,
        'medium': 2.5,
        'low': 0.8,
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
    
    # Max values for normalization when mapping R = L * I to 0–10
    NIST_MAX_VALUES = {
        'likelihood_max': 5.0,   # Max L on 1–5 scale
        'impact_max': 4.0        # Max I on 1–4 scale (Public→Secret)
    }
    
    # Risk Scoring Method: mặc định 'cvss_dlp' (Noteupdate); có thể đổi: nist_based, traditional, research_based
    RISK_SCORING_METHOD = os.getenv('RISK_SCORING_METHOD', 'cvss_dlp').strip().lower()

    # Clipboard tuning: tăng độ nhạy YARA cho luồng clipboard.
    CLIPBOARD_YARA_WEIGHT_MULTIPLIER = _env_float_bounded(
        "CLIPBOARD_YARA_WEIGHT_MULTIPLIER", 1.35, 1.0, 3.0
    )
    # Nếu clipboard paste có YARA match, ép score tối thiểu để luôn cảnh báo.
    CLIPBOARD_YARA_MIN_ALERT_SCORE = _env_float_bounded(
        "CLIPBOARD_YARA_MIN_ALERT_SCORE", 7.2, 0.0, 10.0
    )
    # Nếu có YARA match thuộc nhóm cực nhạy cảm (ID/CCCD/CMND/Credit/API key), ép ngưỡng cao hơn.
    CLIPBOARD_HIGHLY_SENSITIVE_MIN_ALERT_SCORE = _env_float_bounded(
        "CLIPBOARD_HIGHLY_SENSITIVE_MIN_ALERT_SCORE", 8.4, 0.0, 10.0
    )
    # Giảm trọng số "web nhạy cảm" để tránh over-score khi chỉ dựa vào title/domain.
    SENSITIVE_WEB_BEHAVIOR_WEIGHT = _env_float_bounded(
        "SENSITIVE_WEB_BEHAVIOR_WEIGHT", 0.6, 0.3, 1.0
    )
    SENSITIVE_WEB_CONTEXT_TITLE_POINTS = _env_float_bounded(
        "SENSITIVE_WEB_CONTEXT_TITLE_POINTS", 12.0, 0.0, 25.0
    )
    SENSITIVE_WEB_CONTEXT_DOMAIN_POINTS = _env_float_bounded(
        "SENSITIVE_WEB_CONTEXT_DOMAIN_POINTS", 12.0, 0.0, 25.0
    )

    # --- CVSS-inspired DLP (Noteupdate.txt §3–§4) ---
    CVSS_DLP_BASE_WEIGHTS = {
        'content_sensitivity': _env_float('CVSS_DLP_W_CONTENT', 0.35),
        'data_criticality': _env_float('CVSS_DLP_W_CRITICALITY', 0.25),
        'behavior_anomaly': _env_float('CVSS_DLP_W_BEHAVIOR', 0.25),
        'confidence': _env_float('CVSS_DLP_W_CONFIDENCE', 0.15),
    }
    CVSS_DLP_FUSION_WEIGHTS = {
        'base': _env_float('CVSS_DLP_F_BASE', 0.60),
        'maturity': _env_float('CVSS_DLP_F_MATURITY', 0.25),
        'environmental': _env_float('CVSS_DLP_F_ENV', 0.15),
    }
    CVSS_DLP_MATURITY_LEVEL_SCORES = {
        'U': _env_float('CVSS_DLP_MAT_U', 2.0),
        'P': _env_float('CVSS_DLP_MAT_P', 5.0),
        'A': _env_float('CVSS_DLP_MAT_A', 8.5),
        'X': _env_float('CVSS_DLP_MAT_X', 3.5),
    }
    CVSS_DLP_EM_FACTORS = {
        'U': _env_float('CVSS_DLP_EMF_U', 0.85),
        'P': _env_float('CVSS_DLP_EMF_P', 1.0),
        'A': _env_float('CVSS_DLP_EMF_A', 1.25),
        'X': _env_float('CVSS_DLP_EMF_X', 0.95),
    }
    CVSS_DLP_ENV_WEIGHTS = {
        'user': _env_float('CVSS_DLP_E_USER', 0.30),
        'time': _env_float('CVSS_DLP_E_TIME', 0.20),
        'asset': _env_float('CVSS_DLP_E_ASSET', 0.25),
        'destination': _env_float('CVSS_DLP_E_DEST', 0.25),
    }
    CVSS_DLP_USE_FORMULA1_EM_FACTOR = os.getenv('CVSS_DLP_USE_FORMULA1', '0').strip().lower() in {
        '1', 'true', 'yes', 'on',
    }
    
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
