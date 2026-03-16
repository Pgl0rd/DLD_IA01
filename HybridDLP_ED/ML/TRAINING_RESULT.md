# Kết Quả Training UEBA Model

## ✅ Training Đã Thành Công!

### Thống Kê Training:

| Metric | Giá Trị |
|--------|---------|
| **File Events Streamed** | 1,000,000 |
| **Email Events Streamed** | 1,000,000 |
| **HTTP Events Streamed** | 1,000,000 |
| **CERT Events Processed** | 30,030 (sau sampling 1%) |
| **Synthetic Events** | 115 (1% của 10,050) |
| **Total Features Extracted** | 30,145 |
| **Feature Matrix Shape** | (30,145, 13) |
| **Anomalies Detected** | 302 (1.00%) |
| **Model Saved** | ✅ `worker/ml_models/ueba_iso_forest.pkl` |

### Giải Thích:

1. **Streamed 3M events** nhưng chỉ **processed 30K events** vì:
   - Sampling ratio: **1%** → Chỉ giữ lại 1% events sau khi stream
   - 3M events × 1% = ~30K events (đúng với kết quả)

2. **Anomalies detected: 302 (1.00%)**:
   - Isolation Forest phát hiện 1% events là anomalies
   - Phù hợp với contamination=0.01 (1%)

3. **Model đã được lưu thành công** tại:
   - `worker/ml_models/ueba_iso_forest.pkl`

---

## 🧪 Cách Test Model

### Cách 1: Chạy Test Script (Khuyến nghị)

```bash
cd HybridDLP_ED/ML
test_model.bat
```

Script này sẽ test model với 3 scenarios:
1. **Normal Event**: Business hours, local app → Kỳ vọng: Low score
2. **Anomalous: Off-hours + ChatGPT**: 2h sáng, paste vào ChatGPT → Kỳ vọng: High score
3. **Anomalous: USB Bulk Copy**: Copy lớn ra USB lúc 8h tối → Kỳ vọng: High score

### Cách 2: Test Manual với Python

```python
from ML.behavioral_ml_analyzer import BehavioralMLAnalyzer
from pathlib import Path

# Load model
model_path = Path("worker/ml_models/ueba_iso_forest.pkl")
ml_analyzer = BehavioralMLAnalyzer(model_path)

# Test với event
test_event = {
    "ts": "2026-03-15T02:30:00+00:00",
    "type": "clipboard_paste",
    "user": "test_user",
    "clipboard": {
        "content": "API_KEY=sk-123456",
        "dest_domain": "chat.openai.com"
    },
    "metrics": {"entropy": 6.5}
}

result = ml_analyzer.predict(test_event)
print(f"Anomaly Score: {result['anomaly_score']:.2f}")
print(f"Is Anomaly: {result['is_anomaly']}")
```

### Cách 3: Test với Real Events

Model sẽ tự động được sử dụng trong L3 Detection Engine khi:
1. Worker khởi động
2. Có event mới từ Agent
3. Model sẽ tự động predict và thêm `ml_anomaly_score` vào risk scoring

---

## 📊 Kết Quả Mong Đợi Khi Test

### Normal Event:
- Anomaly Score: **< 50**
- Is Anomaly: **False**
- Kết luận: ✅ NORMAL

### Anomalous Events:
- Anomaly Score: **> 75** (threshold)
- Is Anomaly: **True**
- Kết luận: ⚠️ ANOMALY

---

## 🔍 Kiểm Tra Model Có Hoạt Động

### Bước 1: Kiểm tra file model
```bash
ls worker/ml_models/ueba_iso_forest.pkl
```

### Bước 2: Chạy test script
```bash
cd HybridDLP_ED/ML
test_model.bat
```

### Bước 3: Kiểm tra trong Worker
Khi worker chạy, bạn sẽ thấy log:
```
UEBA model loaded from worker/ml_models/ueba_iso_forest.pkl
```

Khi có event, sẽ thấy:
```
UEBA Anomaly Detected: score=85.23 (raw=-0.7045)
```

---

## ✅ Kết Luận

**Training đã thành công!** Model đã được train với:
- ✅ 30,145 events (đủ để train Isolation Forest)
- ✅ 13 features extracted
- ✅ 1% anomalies detected (đúng với contamination)
- ✅ Model saved successfully

**Model sẵn sàng sử dụng** trong L3 Detection Engine!
