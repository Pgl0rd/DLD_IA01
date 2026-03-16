# Update Code Chuẩn - Cải Thiện Model Training

## 🔍 Phân Tích Debug Features

Từ kết quả `debug_features.py`, ta thấy:

### ✅ Features Đã Khác Biệt Rõ Ràng:

| Feature | Normal | Anomalous Off-hours | Anomalous USB |
|---------|--------|---------------------|---------------|
| `is_off_hours` | 0.0000 | **1.0000** | **1.0000** |
| `entropy_value` | 0.4375 | **0.9000** | **0.9875** |
| `dest_app_category` | 0.0000 | **0.5000** (Chat) | **1.0000** (USB) |
| `content_size_log` | 0.5410 | 0.2221 | **0.8864** |

**Kết luận:** Features đã đúng và khác biệt rõ ràng!

### ❌ Vấn Đề: Model Chưa Học Được Patterns

- Model chỉ train với **30K events** (1% sample)
- **Contamination 0.01** (1%) quá thấp
- Model chưa thấy đủ patterns để học

## ✅ Đã Cập Nhật Code

### 1. Cải Thiện Feature Extractor

**File:** `ML/feature_extractor.py`

**Thay đổi:**
- ✅ Cải thiện USB detection (check `event_type` có chứa 'usb')
- ✅ Cải thiện destination category detection (check nhiều nguồn hơn)
- ✅ Tính frequency features bao gồm cả current event (không chỉ history)
- ✅ Cải thiện clipboard paste detection

### 2. Tạo Script Train Improved

**File:** `ML/train_improved.bat`

**Parameters:**
- Sample Ratio: **5%** (thay vì 1%)
- Contamination: **2%** (thay vì 1%)
- N Estimators: **200** (thay vì 100)
- Max Events/File: **2M**

**Kết quả mong đợi:**
- ~150K events thay vì 30K
- Model học tốt hơn
- Anomaly scores sẽ cao hơn (60-80+)

## 🚀 Cách Sử Dụng

### Bước 1: Train Lại Model Với Parameters Tốt Hơn

```bash
cd HybridDLP_ED/ML
train_improved.bat
```

**Thời gian:** ~30-60 phút (tùy máy)

### Bước 2: Test Lại Model

```bash
test_model.bat
```

**Kỳ vọng:**
- Normal Event: Score < 50 ✅
- Anomalous Off-hours: Score **60-80+** ⚠️
- Anomalous USB: Score **60-80+** ⚠️

### Bước 3: Nếu Vẫn Thấp, Giảm Threshold

Sửa trong `worker/config.py`:

```python
ML_ANOMALY_THRESHOLD = 60.0  # Giảm từ 70 xuống 60
```

## 📊 So Sánh

| Metric | Train Cũ | Train Improved |
|--------|----------|----------------|
| **Sample Ratio** | 1% | **5%** |
| **Events** | ~30K | **~150K** |
| **Contamination** | 1% | **2%** |
| **N Estimators** | 100 | **200** |
| **Training Time** | 10-20 phút | 30-60 phút |
| **Expected Scores** | 49-50 | **60-80+** |

## ✅ Kết Luận

**Code đã được update chuẩn:**
1. ✅ Feature extractor đã cải thiện
2. ✅ Script train improved đã tạo
3. ✅ Parameters đã tối ưu

**Next Step:** Chạy `train_improved.bat` để train lại model với nhiều data hơn!
