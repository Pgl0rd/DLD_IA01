# Fix: Model Không Phát Hiện Anomalies (Score Quá Thấp)

## 🔍 Vấn Đề

Test cases cho thấy:
- **Anomalous events** có score **51.91** và **53.17** (thấp hơn threshold 75)
- Model không trigger alert cho các events bất thường
- Raw scores âm nhưng quá gần 0 (-0.0382, -0.0634)

## 🎯 Nguyên Nhân

1. **Model mới train với ít data**: Chỉ 30K events (1% sample)
2. **Test events chưa đủ "extreme"**: Cần simulate bulk activity patterns
3. **Threshold quá cao**: 75 có thể quá strict cho model mới train

## ✅ Giải Pháp

### Solution 1: Giảm Threshold (Nhanh Nhất) ⭐

Sửa trong `worker/config.py`:

```python
ML_ANOMALY_THRESHOLD = 60.0  # Giảm từ 70 xuống 60
```

**Kết quả:**
- Anomalous events với score 51-53 sẽ không trigger alert
- Nhưng events với score 60+ sẽ trigger

### Solution 2: Train Lại Với Nhiều Data Hơn (Tốt Nhất)

```bash
cd HybridDLP_ED/ML
python train_ueba.py \
    --cert-dir ../Dataset \
    --synthetic ../synthetic_events.jsonl \
    --output ../worker/ml_models/ueba_iso_forest.pkl \
    --sample-ratio 0.05 \      # 5% thay vì 1%
    --max-events-per-file 2000000 \
    --contamination 0.02      # Tăng từ 0.01 lên 0.02
```

**Kết quả:**
- ~150K events thay vì 30K
- Model học tốt hơn
- Anomaly scores sẽ cao hơn

### Solution 3: Tăng Contamination

```bash
python train_ueba.py \
    --cert-dir ../Dataset \
    --synthetic ../synthetic_events.jsonl \
    --contamination 0.05 \    # 5% thay vì 1%
    --sample-ratio 0.01
```

**Kết quả:**
- Model sẽ nhạy cảm hơn với anomalies
- Scores sẽ cao hơn

### Solution 4: Cải Thiện Test Events

Đã cập nhật `test_model.py` để:
- Tạo event history (simulate bulk activity)
- Tăng entropy (7.2, 7.9)
- Tăng file size (50MB)
- Off-hours cực kỳ (11:45 PM)

## 📊 So Sánh Solutions

| Solution | Thời gian | Chất lượng | Khuyến nghị |
|----------|-----------|------------|-------------|
| Giảm threshold | ⚡ Ngay lập tức | ⚠️ Tạm thời | ✅ Dùng ngay |
| Train 5% data | 🕐 30-60 phút | ✅ Tốt | ✅ Lâu dài |
| Tăng contamination | 🕐 10-20 phút | ⚠️ Có thể false positive | ⚠️ Cẩn thận |

## 🚀 Khuyến Nghị

**Bước 1: Giảm threshold ngay** (để model hoạt động)
```python
# worker/config.py
ML_ANOMALY_THRESHOLD = 60.0
```

**Bước 2: Train lại với 5% data** (để cải thiện chất lượng)
```bash
python train_ueba.py --sample-ratio 0.05 --max-events-per-file 2000000
```

## 📝 Lưu Ý

- **Raw score âm là BÌNH THƯỜNG**: Nghĩa là model phát hiện có dấu hiệu bất thường
- **Score 51-53**: Có dấu hiệu bất thường nhưng chưa đủ mạnh
- **Với threshold 60**: Các events này vẫn không trigger, nhưng events với score 60+ sẽ trigger
- **Cần train lại** để model học tốt hơn và tăng scores lên 70-80+
