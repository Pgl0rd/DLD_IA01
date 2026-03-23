# Detection Engine (L3) - Worker Process

## 📋 Tổng quan

**Detection Engine (L3)** là Worker Process chịu trách nhiệm phân tích và phát hiện dữ liệu nhạy cảm từ events được tạo bởi Agent (L1).

## 🏗️ Kiến trúc

```
Agent (L1) → IPC Queue (SQLite/Redis) → Detection Engine (L3)
                                              ↓
                                    Pipeline xử lý:
                                    1. Hash Cache Check
                                    2. Fast Scan (YARA)
                                    3. Deep Analysis (OCR/ML)
                                    4. Risk Scoring
                                    5. Action Executor
```

## 📁 Cấu trúc

```
worker/
├── worker.py              # Main entry point
├── config.py              # Configuration
├── requirements.txt       # Dependencies
│
├── core/                  # Core modules
│   ├── queue_consumer.py  # Queue Consumer & Panic Mode
│   ├── hash_cache.py      # Hash Cache Manager
│   ├── fast_scan.py       # YARA & Header Check
│   ├── deep_analysis.py   # OCR & ML (Lazy Load)
│   ├── risk_scoring.py    # Risk Score Calculator
│   └── action_executor.py # Block/Alert/Log
│
├── models/                # ML Models
│   └── ml_classifier.py   # ML Classifier (Lazy Load)
│
├── yara_rules/            # YARA Rules
│   ├── vietnam_id.yar
│   ├── credit_card.yar
│   ├── email.yar
│   └── api_key.yar
│
├── ml_models/             # Trained ML models (sẽ được tạo khi train)
│   ├── classifier.pkl
│   └── vectorizer.pkl
│
├── database/              # SQLite cache database
│   └── cache.db
│
└── logs/                  # Log files
    └── detection_engine.log
```

## 🚀 Cài đặt

### 1. Install dependencies

```bash
cd worker
pip install -r requirements.txt
```

### 2. Cài đặt system dependencies

**Windows:**
- YARA: Download từ https://github.com/VirusTotal/yara/releases
- Tesseract OCR: Download từ https://github.com/UB-Mannheim/tesseract/wiki
- python-magic: Cần libmagic (có thể dùng python-magic-bin)

**Linux (nếu chạy trong Docker):**
```bash
apt-get update
apt-get install -y yara libyara-dev tesseract-ocr tesseract-ocr-vie libmagic1
```

### 3. Tạo thư mục cần thiết

```bash
mkdir -p yara_rules ml_models database logs
```

## ⚙️ Cấu hình

### Environment Variables

Tạo file `.env` hoặc set environment variables:

```env
# Queue Configuration
WORKER_QUEUE_TYPE=sqlite  # hoặc redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Server Configuration
SERVER_URL=https://your-management-server.com
SERVER_API_KEY=your-api-key
DEVICE_ID=worker-1

# Logging
LOG_LEVEL=INFO
```

### Config trong `config.py`

Các tham số có thể điều chỉnh:
- `PANIC_MODE_THRESHOLD`: Ngưỡng kích hoạt panic mode (default: 1000)
- `OCR_MAX_FILE_SIZE_MB`: Kích thước file tối đa cho OCR (default: 5MB)
- `OCR_MAX_CPU_PERCENT`: CPU usage tối đa cho OCR (default: 70%)
- `RISK_THRESHOLDS`: Ngưỡng risk score cho block/alert/log
- `RISK_WEIGHTS`: Trọng số cho content/behavior/context scores (phương pháp `traditional`)
- `RISK_SCORING_METHOD`: `traditional` | `nist_based` | `research_based`
- `ML_ANOMALY_BEHAVIOR_BLEND`: Hệ số gộp điểm anomaly UEBA (0–100) vào Behavior score (traditional)
- `RISK_LEVEL_LOW_MAX`, `RISK_LEVEL_MEDIUM_MAX`, `RISK_LEVEL_HIGH_MAX`: Ranh giới phân loại low/medium/high/critical

Tài liệu công thức đầy đủ (NIST, trọng số, Isolation Forest, sơ đồ): `../docs/PHUONG_PHAP_RISK_SCORE_VA_NGUONG.md`

## 🎯 Sử dụng

### Chạy Worker

```bash
python worker.py
```

### Chạy như Windows Service (tùy chọn)

Worker có thể được spawn bởi Agent Service hoặc chạy độc lập.

## 📊 Pipeline xử lý

1. **Queue Consumer**: Đọc events từ SQLite/Redis
2. **Panic Mode Check**: Kiểm tra queue size, kích hoạt panic mode nếu cần
3. **Hash Cache**: Kiểm tra file đã scan chưa
4. **Fast Scan**: YARA rules + Header check + Encrypted ZIP detection
5. **Decision Point**: Quyết định có cần Deep Analysis không
6. **Deep Analysis** (nếu cần):
   - OCR (với điều kiện: size < 5MB, CPU < 70%, là ảnh)
   - ML Classification (lazy load)
7. **Risk Scoring**: Theo `RISK_SCORING_METHOD` — traditional (trọng số Content/Behavior/Context + blend UEBA vào Behavior), NIST (L×I), hoặc research-based; kết quả có `risk_level` (low/medium/high/critical)
8. **Action Executor**: Thực thi Block/Alert/Log
9. **Update Cache**: Lưu kết quả vào cache

## 🔍 YARA Rules

YARA rules được đặt trong `yara_rules/`:
- `vietnam_id.yar`: Phát hiện CMND/CCCD
- `credit_card.yar`: Phát hiện số thẻ tín dụng
- `email.yar`: Phát hiện email lists
- `api_key.yar`: Phát hiện API keys và secrets

## 🤖 ML Models

ML models cần được train trước khi sử dụng:
- `classifier.pkl`: Trained classifier (Random Forest/SVM)
- `vectorizer.pkl`: TF-IDF vectorizer

Xem `scripts/train_model.py` để train models.

## 📝 Logs

Logs được lưu tại:
- `logs/detection_engine.log`: File log chính
- Console output: Real-time logs

## 🔧 Troubleshooting

### YARA không load rules

```bash
# Kiểm tra rules tồn tại
ls yara_rules/

# Test YARA
yara --version
```

### OCR không hoạt động

```bash
# Kiểm tra Tesseract
tesseract --version
tesseract --list-langs  # Should show: eng, vie
```

### ML model không load

- Đảm bảo `ml_models/classifier.pkl` và `ml_models/vectorizer.pkl` tồn tại
- Nếu chưa có, cần train model trước (xem `scripts/train_model.py`)

### Queue connection error

- Kiểm tra `EVENTS_DB_PATH` trỏ đúng đến SQLite database từ agent
- Hoặc kiểm tra Redis connection nếu dùng Redis

## 📚 Tài liệu tham khảo

- [HUONG_DAN_DETECTION_ENGINE.md](../../../HUONG_DAN_DETECTION_ENGINE.md)
- [PHAN_TICH_KIEN_TRUC.md](../../../PHAN_TICH_KIEN_TRUC.md)
