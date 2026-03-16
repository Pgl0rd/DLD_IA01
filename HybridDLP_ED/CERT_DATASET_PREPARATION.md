# Tài Liệu Chuẩn Bị Dữ Liệu: CERT Insider Threat Dataset

## 1. TRẢ LỜI CÁC CÂU HỎI VỀ LỰA CHỌN DATASET

### Câu hỏi 1: "Vì sao lấy bộ dataset này?"

**Trả lời:**

Chúng em chọn **CERT Insider Threat Detection Research Dataset** (Kaggle) vì các lý do sau:

1. **Phù hợp với bài toán DLP/UEBA:**
   - Dataset chứa hành vi thực tế của nhân viên nội bộ (insider threat) trong 18 tháng
   - Bao gồm các sự kiện liên quan đến Data Loss Prevention: file operations, email, web activity, device behavior
   - Đã được các chuyên gia CMU (Carnegie Mellon University) gán nhãn và validate

2. **Độ tin cậy và uy tín:**
   - Dataset từ CERT (Computer Emergency Response Team) - tổ chức nghiên cứu bảo mật hàng đầu
   - Được sử dụng rộng rãi trong nghiên cứu academic về Insider Threat Detection
   - Có documentation đầy đủ về cấu trúc và ý nghĩa các trường dữ liệu

3. **Kích thước và độ phức tạp phù hợp:**
   - Chứa dữ liệu của hơn 1000 users trong 18 tháng
   - Đủ lớn để train ML model nhưng không quá phức tạp để xử lý
   - Cân bằng giữa dữ liệu bình thường và anomalous behavior

4. **Tương thích với hệ thống:**
   - Có thể map các trường dữ liệu CERT sang format của Agent event
   - Hỗ trợ các loại sự kiện mà hệ thống DLP cần: file copy, email, network upload

---



**Các trường trong CERT Dataset:**

CERT dataset gồm 4 file CSV chính:

#### A. **file.csv** - File Operations
| Trường CERT | Kiểu dữ liệu | Mô tả | Có map được? |
|------------|--------------|-------|--------------|
| `user` | string | Tên người dùng | ✅ → `event.user` |
| `pc` | string | Tên máy tính | ✅ → `event.device.host_name` |
| `date` | string | Ngày (MM/DD/YYYY) | ✅ → `event.ts` (parse datetime) |
| `time` | string | Giờ (HH:MM:SS) | ✅ → `event.ts` (parse datetime) |
| `filename` | string | Đường dẫn file | ✅ → `event.object.path` |
| `activity` | string | Hành động (Read, Write, Copy, etc.) | ✅ → `event.operation.op_type` |

#### B. **email.csv** - Email Activity
| Trường CERT | Kiểu dữ liệu | Mô tả | Có map được? |
|------------|--------------|-------|--------------|
| `user` | string | Người gửi | ✅ → `event.user` |
| `pc` | string | Tên máy tính | ✅ → `event.device.host_name` |
| `date` | string | Ngày | ✅ → `event.ts` |
| `time` | string | Giờ | ✅ → `event.ts` |
| `to` | string | Người nhận | ✅ → `event.clipboard.dest_domain` (email domain) |
| `cc` | string | CC | ⚠️ → Có thể thêm vào `event.context` |
| `bcc` | string | BCC | ⚠️ → Có thể thêm vào `event.context` |
| `size` | int | Kích thước email (bytes) | ✅ → `event.clipboard.content_len` |
| `attachment` | string | File đính kèm | ✅ → `event.object.path` |

#### C. **http.csv** - Web Activity
| Trường CERT | Kiểu dữ liệu | Mô tả | Có map được? |
|------------|--------------|-------|--------------|
| `user` | string | Người dùng | ✅ → `event.user` |
| `pc` | string | Tên máy tính | ✅ → `event.device.host_name` |
| `date` | string | Ngày | ✅ → `event.ts` |
| `time` | string | Giờ | ✅ → `event.ts` |
| `url` | string | URL truy cập | ✅ → `event.network.dest_url` |
| `content` | string | Nội dung (nếu có) | ✅ → `event.content.sample` |

#### D. **logon.csv** - Authentication Events
| Trường CERT | Kiểu dữ liệu | Mô tả | Có map được? |
|------------|--------------|-------|--------------|
| `user` | string | Người dùng | ✅ → `event.user` |
| `pc` | string | Tên máy tính | ✅ → `event.device.host_name` |
| `date` | string | Ngày | ✅ → `event.ts` |
| `time` | string | Giờ | ✅ → `event.ts` |
| `activity` | string | Logon/Logoff | ✅ → `event.type` (logon/logoff) |
| `logon_type` | string | Loại logon | ⚠️ → Có thể thêm vào `event.context` |

**Kết luận:** 
- ✅ **Đủ các trường cần thiết:** CERT có đầy đủ thông tin về user, timestamp, file operations, email, network
- ✅ **Có thể map được:** Tất cả các trường quan trọng đều có thể map sang Agent event format
- ⚠️ **Một số trường bổ sung:** CC, BCC, logon_type có thể thêm vào context nhưng không bắt buộc

---


**Trả lời:**

Đúng vậy. CERT dataset đóng vai trò là **training data** để ML model học:

1. **Baseline Behavior:**
   - Model học được hành vi "bình thường" của users từ CERT data
   - Isolation Forest sẽ tạo baseline từ các patterns trong CERT

2. **Anomaly Detection:**
   - CERT có sẵn một số insider threat scenarios (đã được label)
   - Model học để phân biệt normal vs anomalous behavior

3. **Feature Learning:**
   - Model học cách extract và weight các features từ CERT events
   - Sau đó áp dụng knowledge này vào real-time detection với Agent events

4. **Không phải Production Data:**
   - CERT data chỉ dùng để train model (offline)
   - Khi deploy, model sẽ detect anomalies từ Agent events thực tế (real-time)

---

#### A. **Có mô tả được cho demo không?**

✅ **CÓ** - CERT dataset rất phù hợp để demo vì:

1. **Kịch bản demo rõ ràng:**
   - **Demo 1:** User copy nhiều files trong giờ làm việc → Normal behavior
   - **Demo 2:** User copy files ra USB lúc 2h sáng → Anomaly (off-hours + external device)
   - **Demo 3:** User gửi email với attachment lớn ra ngoài → Anomaly (data exfiltration)
   - **Demo 4:** User truy cập cloud storage và upload files → Anomaly (network upload)

2. **Có thể visualize:**
   - Timeline của user activities
   - Frequency charts (số lần copy/paste theo giờ)
   - Risk score distribution

3. **Có ground truth:**
   - CERT đã label một số users là "insider threat"
   - Có thể so sánh kết quả detection với ground truth

#### B. **Lấy những trường nào? (Tránh dư thừa)**

**Các trường BẮT BUỘC cần lấy:**

| File CERT | Trường cần lấy | Lý do |
|-----------|---------------|-------|
| `file.csv` | `user`, `date`, `time`, `filename`, `activity` | Core cho file operations detection |
| `email.csv` | `user`, `date`, `time`, `to`, `size`, `attachment` | Core cho email exfiltration detection |
| `http.csv` | `user`, `date`, `time`, `url` | Core cho network upload detection |
| `logon.csv` | `user`, `date`, `time`, `activity` | Bổ sung context về user session |

**Các trường KHÔNG CẦN (có thể bỏ qua):**

| Trường | Lý do bỏ qua |
|--------|-------------|
| `pc` (một số trường hợp) | Nếu không cần phân biệt theo máy tính |
| `cc`, `bcc` (email) | Không ảnh hưởng đến risk scoring chính |
| `logon_type` (chi tiết) | Chỉ cần biết logon/logoff, không cần chi tiết loại |

**Các trường BỔ SUNG (nếu có):**

- `file_size` (nếu CERT có) → Map sang `event.object.size_bytes`
- `file_hash` (nếu CERT có) → Map sang `event.object.hash_sha256`

---

**Trả lời:**

✅ **CÓ THỂ MAP ĐƯỢC** - Bảng mapping chi tiết:

## 2. BẢNG MAPPING CHI TIẾT: CERT → AGENT EVENT FORMAT

### Mapping cho file.csv

```python
CERT file.csv row:
{
    "user": "CMP2944",
    "pc": "PC-2944",
    "date": "01/02/2010",
    "time": "08:15:32",
    "filename": "C:\\Users\\CMP2944\\Documents\\report.xlsx",
    "activity": "Write"
}

↓ MAP TO ↓

Agent Event Format:
{
    "ts": "2010-01-02T08:15:32+00:00",           # Parse từ date + time
    "timestamp": "2010-01-02T08:15:32+00:00",
    "type": "file_copy",                          # Từ activity
    "event_type": "file_copy",
    "user": "CMP2944",                            # Direct map
    "source": "cert_dataset",
    "context": {
        "user": "CMP2944",
        "process_name": "explorer.exe",           # Default (CERT không có)
        "active_window": "File Explorer"          # Default
    },
    "object": {
        "path": "C:\\Users\\CMP2944\\Documents\\report.xlsx",  # Direct map
        "size_bytes": 0                           # CERT không có, set default
    },
    "operation": {
        "op_type": "write"                        # Từ activity
    },
    "metrics": {
        "entropy": 3.5                            # Default (sẽ tính sau)
    }
}
```

### Mapping cho email.csv

```python
CERT email.csv row:
{
    "user": "CMP2944",
    "pc": "PC-2944",
    "date": "01/02/2010",
    "time": "14:30:15",
    "to": "external@competitor.com",
    "cc": "",
    "bcc": "",
    "size": 524288,
    "attachment": "confidential_data.zip"
}

↓ MAP TO ↓

Agent Event Format:
{
    "ts": "2010-01-02T14:30:15+00:00",
    "timestamp": "2010-01-02T14:30:15+00:00",
    "type": "clipboard_paste",                    # Email = external paste
    "event_type": "clipboard_paste",
    "user": "CMP2944",
    "source": "cert_dataset",
    "context": {
        "user": "CMP2944",
        "process_name": "outlook.exe",             # Default
        "active_window": "Outlook",
        "dest_domain": "competitor.com"            # Extract từ "to"
    },
    "clipboard": {
        "content_type": "Text",
        "content": "Email content 524288 bytes",  # Synthetic
        "content_len": 524288,                     # Direct map từ size
        "dest_app": "outlook.exe",
        "dest_domain": "competitor.com",
        "snapshot_linked": True
    },
    "object": {
        "path": "confidential_data.zip",           # Từ attachment
        "size_bytes": 524288
    },
    "operation": {
        "op_type": "paste"
    },
    "metrics": {
        "entropy": 4.0                             # Default
    }
}
```

### Mapping cho http.csv

```python
CERT http.csv row:
{
    "user": "CMP2944",
    "pc": "PC-2944",
    "date": "01/02/2010",
    "time": "20:45:00",
    "url": "https://drive.google.com/upload",
    "content": "file_upload_data"
}

↓ MAP TO ↓

Agent Event Format:
{
    "ts": "2010-01-02T20:45:00+00:00",
    "timestamp": "2010-01-02T20:45:00+00:00",
    "type": "network_upload",                     # HTTP upload
    "event_type": "network_upload",
    "user": "CMP2944",
    "source": "cert_dataset",
    "context": {
        "user": "CMP2944",
        "process_name": "chrome.exe",              # Default
        "active_window": "Browser",
        "dest_domain": "drive.google.com"          # Extract từ URL
    },
    "object": {
        "path": "https://drive.google.com/upload",
        "dst_path": "https://drive.google.com/upload"
    },
    "network": {
        "dest_url": "https://drive.google.com/upload",
        "dest_domain": "drive.google.com",
        "method": "POST",                          # Default (upload)
        "external_dst": True                        # Cloud = external
    },
    "operation": {
        "op_type": "upload"
    },
    "metrics": {
        "entropy": 4.5                             # Default
    }
}
```

### Mapping cho logon.csv

```python
CERT logon.csv row:
{
    "user": "CMP2944",
    "pc": "PC-2944",
    "date": "01/02/2010",
    "time": "08:00:00",
    "activity": "Logon",
    "logon_type": "Network"
}

↓ MAP TO ↓

Agent Event Format:
{
    "ts": "2010-01-02T08:00:00+00:00",
    "timestamp": "2010-01-02T08:00:00+00:00",
    "type": "logon",                               # Từ activity
    "event_type": "logon",
    "user": "CMP2944",
    "source": "cert_dataset",
    "context": {
        "user": "CMP2944",
        "process_name": "winlogon.exe",             # Default
        "logon_type": "Network"                     # Bổ sung context
    },
    "operation": {
        "op_type": "logon"
    }
}
```

---

## 3. IMPLEMENTATION CODE

### File: `ml_pipeline/train_ueba.py` - CERTDatasetLoader

Code hiện tại đã implement mapping trong các methods:

1. **`_convert_cert_file_event()`** - Map file.csv → Agent event
2. **`_convert_cert_email_event()`** - Map email.csv → Agent event  
3. **`_convert_cert_http_event()`** - Map http.csv → Agent event

### Các trường đã map được:

✅ **Đã map thành công:**
- `user` → `event.user`
- `date` + `time` → `event.ts` (ISO8601)
- `filename` → `event.object.path`
- `activity` → `event.operation.op_type`
- `size` (email) → `event.clipboard.content_len`
- `url` → `event.network.dest_url`
- `to` (email) → `event.clipboard.dest_domain`

⚠️ **Cần bổ sung (nếu cần):**
- `pc` → `event.device.host_name` (hiện tại chưa map)
- `attachment` → `event.object.path` (đã có nhưng có thể cải thiện)
- `cc`, `bcc` → `event.context` (optional)

---

## 4. KẾT LUẬN

### ✅ Đánh giá tổng thể:

1. **Dataset phù hợp:** CERT Insider Threat Dataset rất phù hợp cho bài toán UEBA/DLP
2. **Đủ trường:** Có đầy đủ các trường cần thiết để train ML model
3. **Map được:** Tất cả trường quan trọng đều có thể map sang Agent event format
4. **Demo được:** Có thể tạo nhiều kịch bản demo từ CERT data
5. **Code sẵn sàng:** Đã có implementation trong `train_ueba.py`

### 📝 Khuyến nghị:

1. **Sử dụng 4 file chính:** `file.csv`, `email.csv`, `http.csv`, `logon.csv`
2. **Bỏ qua các trường không cần:** `cc`, `bcc`, `logon_type` (chi tiết)
3. **Bổ sung defaults:** Một số trường CERT không có (như `process_name`) → dùng giá trị mặc định hợp lý
4. **Validate mapping:** Test với sample data để đảm bảo mapping chính xác

---

## 5. HƯỚNG DẪN SỬ DỤNG

### Bước 1: Download CERT Dataset
```bash
# Download từ Kaggle
kaggle datasets download -d mrajaxnp/cert-insider-threat-detection-research
unzip cert-insider-threat-detection-research.zip -d data/cert/
```

### Bước 2: Kiểm tra cấu trúc
```bash
# Kiểm tra các file có đủ không
ls data/cert/
# Kỳ vọng: file.csv, email.csv, http.csv, logon.csv
```

### Bước 3: Train model
```bash
cd HybridDLP_ED/worker
python -m ml_pipeline.train_ueba \
    --cert-dir data/cert \
    --synthetic synthetic_events.jsonl \
    --output ml_models/ueba_iso_forest.pkl
```

### Bước 4: Verify mapping
```python
# Test mapping với sample data
from ml_pipeline.train_ueba import CERTDatasetLoader
loader = CERTDatasetLoader(Path("data/cert"))
events = loader.load_cert_events(limit=10)
print(events[0])  # Xem event đã map đúng chưa
```
