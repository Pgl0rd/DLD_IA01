# Giải Thích Raw Score trong Isolation Forest

## 🔍 Raw Score là gì?

**Raw Score** là output trực tiếp từ Isolation Forest's `decision_function()`, có giá trị từ **-1 đến 1**.

## 📊 Cách Isolation Forest Hoạt Động

### Decision Function Output:

| Raw Score | Ý nghĩa | Mức độ bất thường |
|-----------|---------|-------------------|
| **-1.0** | Rất bất thường | Cực kỳ anomalous |
| **-0.5** | Hơi bất thường | Có dấu hiệu anomaly |
| **0.0** | Trung bình | Không rõ ràng |
| **0.5** | Bình thường | Normal behavior |
| **1.0** | Rất bình thường | Typical behavior |

### Công Thức Convert:

```python
# Isolation Forest: -1 (anomaly) → 1 (normal)
# Chúng ta muốn: 0 (normal) → 100 (highly anomalous)

anomaly_score = (1 - raw_score) / 2 * 100
```

**Ví dụ:**
- Raw Score = **0.0434** → Anomaly Score = (1 - 0.0434) / 2 * 100 = **47.83**
- Raw Score = **-0.0382** → Anomaly Score = (1 - (-0.0382)) / 2 * 100 = **51.91**
- Raw Score = **-0.0634** → Anomaly Score = (1 - (-0.0634)) / 2 * 100 = **53.17**

## ❓ Tại Sao Raw Score Có Thể Âm?

### 1. **Raw Score Âm = Có Dấu Hiệu Bất Thường**

Khi Raw Score **< 0**, nghĩa là:
- Event này **khác biệt** so với training data
- Isolation Forest phát hiện event này **khó cô lập** (dễ bị isolate)
- **Nhưng chưa đủ mạnh** để được coi là anomaly (threshold = 75)

### 2. **Raw Score Dương = Bình Thường**

Khi Raw Score **> 0**, nghĩa là:
- Event này **giống** với training data
- Isolation Forest thấy event này **khó cô lập** (giống normal data)
- Đây là **normal behavior**

## 📈 Giải Thích Kết Quả Test

### Test 1: Normal Event
- **Raw Score: 0.0434** (dương, gần 0)
- **Anomaly Score: 47.83**
- ✅ **Đúng**: Normal event có score thấp

### Test 2: Anomalous (Off-hours + ChatGPT)
- **Raw Score: -0.0382** (âm, nhưng gần 0)
- **Anomaly Score: 51.91**
- ⚠️ **Vấn đề**: Score quá thấp (51.91 < 75 threshold)

**Lý do:**
- Model mới train với 30K events (1% sample)
- Có thể chưa học đủ patterns về off-hours + ChatGPT
- Hoặc test event không đủ "extreme" so với training data

### Test 3: Anomalous (USB Bulk Copy)
- **Raw Score: -0.0634** (âm, nhưng gần 0)
- **Anomaly Score: 53.17**
- ⚠️ **Vấn đề**: Score quá thấp (53.17 < 75 threshold)

**Lý do tương tự:**
- Model cần nhiều training data hơn
- Hoặc cần điều chỉnh threshold

## 🎯 Kết Luận

### Raw Score Âm = Tốt hay Xấu?

**Raw Score âm là BÌNH THƯỜNG** và có nghĩa là:
- ✅ Model đang hoạt động đúng
- ✅ Event có dấu hiệu bất thường (âm = khác biệt)
- ⚠️ Nhưng chưa đủ mạnh để trigger alert (cần threshold > 75)

### Tại Sao Test Events Có Score Thấp?

1. **Model mới train** với sample nhỏ (30K events)
2. **Cần nhiều data hơn** để học patterns tốt hơn
3. **Threshold có thể cần điều chỉnh** (từ 75 xuống 60-65)

## 💡 Khuyến Nghị

### Option 1: Tăng Training Data
```bash
# Train với 5% sample thay vì 1%
python -m ML.train_ueba \
    --cert-dir Dataset \
    --sample-ratio 0.05 \  # 5% thay vì 1%
    --max-events-per-file 2000000
```

### Option 2: Giảm Threshold
Trong `worker/config.py`:
```python
ML_ANOMALY_THRESHOLD = 60.0  # Giảm từ 75 xuống 60
```

### Option 3: Tăng Contamination
```bash
# Tăng contamination từ 0.01 lên 0.05 (5%)
python -m ML.train_ueba \
    --contamination 0.05 \
    --sample-ratio 0.01
```

## 📝 Tóm Tắt

| Raw Score | Ý nghĩa | Anomaly Score | Kết luận |
|-----------|---------|---------------|----------|
| **1.0** | Rất normal | 0 | ✅ Hoàn toàn bình thường |
| **0.5** | Normal | 25 | ✅ Bình thường |
| **0.0** | Trung bình | 50 | ⚠️ Cần theo dõi |
| **-0.5** | Hơi bất thường | 75 | ⚠️ Anomaly (threshold) |
| **-1.0** | Rất bất thường | 100 | 🚨 Cực kỳ anomalous |

**Raw Score âm = Model phát hiện có dấu hiệu bất thường, nhưng chưa đủ mạnh để alert!**
