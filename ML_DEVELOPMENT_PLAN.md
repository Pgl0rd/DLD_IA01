# Hướng phát triển Machine Learning: Phân tích hành vi (UEBA) trong Hybrid DLP

Tài liệu này đi sâu vào phân tích kiến trúc, định hướng cụ thể để nâng cấp hệ thống L3 Detection Engine của dự án từ Rule-based (YARA + if/else) sang phân tích AI chuyên sâu, tập trung hoàn toàn vào **Phân tích hành vi thực thể người dùng (UEBA - User and Entity Behavior Analytics)**.

---

## 1. TỔNG QUAN VỀ UEBA VÀ LÝ DO LỰA CHỌN

**Hệ thống hiện tại (L3 Detection Engine):**
Đang sử dụng Pseudo-rules (luật tĩnh). Ví dụ: `Nếu (Copy > 50 files) -> Báo động Bulk Copy`.
*   **Nhược điểm của luật tĩnh:** 
    *   **Ngưỡng cứng nhắc (Hard Thresholds):** Nếu kẻ tấn công chỉ copy 49 files, hệ thống sẽ bỏ qua. Nếu một nhân viên IT cần backup 100 files hợp lệ, hệ thống lại báo động giả (False Positive).
    *   **Không hiểu thói quen người dùng:** Cùng một hành vi "Copy source code", với Developer là bình thường, nhưng với Nhân viên Kế toán lại là rủi ro rò rỉ dữ liệu (Insider Threat).

**Giải pháp UEBA (User and Entity Behavior Analytics):**
Sử dụng Machine Learning để tự động học "đường cơ sở" (Baseline) - tức là thói quen bình thường của từng người dùng/thiết bị. Khi có một hành vi **lệch xa khỏi baseline này (Anomaly)**, hệ thống sẽ tính toán Điểm bất thường (Anomaly Score) và cảnh báo.

### Ưu điểm & Nhược điểm của UEBA

**Ưu điểm:**
*   **Bắt được các cuộc tấn công Zero-day và Low & Slow:** Kẻ gian cố tình lách luật (copy từng file nhỏ qua nhiều ngày) vẫn bị phát hiện do hành vi tổng thể bị thay đổi.
*   **Giảm thiểu False Positive (Báo động giả):** Hiểu được ngữ cảnh (Context-aware). Mô hình biết rằng user này thường xuyên làm việc lúc 2h sáng, nên không cảnh báo "Hành vi ngoài giờ làm việc" một cách bừa bãi.
*   **Tăng điểm học thuật / giá trị đồ án:** Việc áp dụng Học không giám sát (Unsupervised Learning) vào Log dữ liệu lớn là một điểm cộng rất lớn trong báo cáo luận văn thay vì chỉ dùng regex/if-else.

**Nhược điểm:**
*   **Cold Start Problem:** Hệ thống cần thời gian (vd: 7-14 ngày) để thu thập đủ log và học được Baseline của người dùng trước khi có thể hoạt động chính xác.
*   **Đòi hỏi kỹ thuật Feature Engineering cao:** ML không tự hiểu chuỗi JSONL. Bạn phải trích xuất và biến đổi log thành các vector số học có ý nghĩa.

---

## 2. KIẾN TRÚC VÀ THUẬT TOÁN ĐỀ XUẤT

Vì dữ liệu DLP cực kỳ mất cân bằng (hành vi bình thường chiếm 99.99%, hành vi ăn cắp dữ liệu chỉ chiếm 0.01%) và ta **không có sẵn nhãn (labels)** cho mọi hành vi ăn cắp, nên phải sử dụng **Học không giám sát (Unsupervised Anomaly Detection)**.

### Thuật toán đề xuất: Isolation Forest (Cây rừng cách ly)
*   **Cơ chế hoạt động:** Thuật toán này không cố gắng tạo ra biên giới bao quanh dữ liệu bình thường. Thay vào đó, nó cố gắng "cô lập" các điểm dữ liệu. Vì dữ liệu bất thường (anomaly) có số lượng ít và giá trị đặc trưng khác biệt, chúng sẽ bị cô lập rất nhanh (ở gần gốc cây).
*   **Thư viện:** `scikit-learn` (`sklearn.ensemble.IsolationForest`).
*   **Output:** Điểm Anomaly Score (từ -1 đến 1). Càng gần -1 thì càng bất thường. Ta sẽ chuẩn hóa điểm này thành thang điểm từ 0-100 để cộng vào Risk Score.

*(Lựa chọn thay thế nếu muốn điểm học thuật cao hơn: Autoencoder bằng PyTorch/TensorFlow, dựa trên lỗi tái tạo - Reconstruction Error)*

### Trích xuất đặc trưng (Feature Engineering) từ JSONL
Để Isolation Forest hiểu được log JSONL hiện tại, bạn cần tạo ra một Vector gồm các cột số. Khi hàm `_process_special_event()` (hoặc file event) chạy, nó sẽ parse các giá trị sau:

1.  **Đặc trưng Thời gian (Temporal Features):**
    *   `is_off_hours`: 1 nếu từ 18:00 - 08:00, 0 nếu trong giờ hành chính.
    *   `is_weekend`: 1 nếu là T7/CN, 0 nếu là ngày thường.
2.  **Đặc trưng Tần suất (Velocity/Frequency Features) - Dùng cửa sổ thời gian (Sliding Window):**
    *   `clipboard_pastes_last_10m`: Số lần paste trong 10 phút qua.
    *   `bytes_transferred_usb_last_1h`: Tổng dung lượng copy ra USB trong 1 giờ.
3.  **Đặc trưng Định lượng (Quantitative Features):**
    *   `entropy_value`: Mức độ mã hóa/ngẫu nhiên của text (vd: 4.5).
    *   `content_size`: Dung lượng text/file.
4.  **Đặc trưng Ngữ cảnh (Contextual/Categorical Encoding):**
    *   `dest_app_category`: (0: Local App, 1: Browser, 2: Chat App, 3: Cloud Sync).

---

## 3. DANH SÁCH DATASET PHÙ HỢP CHO UEBA

Để huấn luyện và đánh giá hệ thống, bạn cần bộ dữ liệu chứa log hành vi. 

**1. CERT Insider Threat Dataset (Carnegie Mellon University)**
*   **Mức độ:** Rất nổi tiếng và phù hợp nhất cho bài toán này.
*   **Mô tả:** Chứa hàng triệu dòng log tổng hợp từ Logon/Logoff, cắm USB, lướt Web, Gửi Email. Đã được các chuyên gia chèn sẵn kịch bản người dùng nội bộ (Insider Threat) ăn cắp dữ liệu.
*   **Cách dùng:** Map các cột của CERT data sang format JSONL hiện tại của Agent, coi nó như log do Agent sinh ra để đưa vào hàm training.

**2. LANL (Los Alamos National Laboratory) Cybersecurity Data**
*   **Mức độ:** Khá phức tạp, thiên về Network/Authentication.
*   **Mô tả:** Bộ dữ liệu log cực lớn về event Windows (Process, Auth, Network). Rất tốt nếu bạn có ý định mở rộng bắt Anomaly của Process.

**3. Dataset Tự sinh (Synthetic Data via Script)**
*   **Khuyến nghị:** Dành cho việc test nhanh Worker của đồ án.
*   **Cách làm:** Viết script Python tạo ra 10,000 dòng log bình thường (sử dụng random giờ hành chính, dest_app = Word/Excel) và 50 dòng log bất thường (random giờ đêm, bulk copy USB, paste ChatGPT).

---

## 4. LỘ TRÌNH TRIỂN KHAI CỤ THỂ VÀO HYBRID DLP (ACTION PLAN)

Dưới đây là kế hoạch code cụ thể để tích hợp UEBA vào `Worker`:

### Bước 1: Xây dựng Module ML & Data Pipeline (Tuần 1)
*   Tạo thư mục `HybridDLP_ED/worker/ml_pipeline/`.
*   Viết file `feature_extractor.py`: Chứa class `EventFeatureExtractor` nhận vào 1 `event` (dict) và lịch sử lưu trong Redis/SQLite để tính toán các tính năng tần suất (`pastes_last_10m`). Trả về 1 mảng numpy `[is_off_hours, entropy, content_size, dest_app_cat, ...]`.
*   Tạo file `train_ueba.py`: Đọc file `events.jsonl` lịch sử, extract features ra ma trận (Matrix X). Sử dụng `IsolationForest().fit(X)` và lưu ra file `models/ueba_iso_forest.pkl`.

### Bước 2: Tích hợp vào L3 Detection Engine (Tuần 2)
*   Tạo class `BehavioralMLAnalyzer` tải file `ueba_iso_forest.pkl`.
*   Trong `worker/worker.py`, tại hàm `process_event` và `_process_special_event`:
    *   Sau khi chạy YARA và Pseudo-rules, gọi `vector = feature_extractor.transform(event)`.
    *   Gọi `anomaly_score = behavioral_ml_analyzer.predict(vector)`. (Score được chuẩn hóa từ 0-100).
*   Trong `worker/core/risk_scoring.py`:
    *   Nhận `anomaly_score` từ context.
    *   Thêm quy tắc: `if anomaly_score > 75: total_score += (anomaly_score * 0.5)` -> Tăng vọt điểm rủi ro.

### Bước 3: Tối ưu và Hiển thị (Tuần 3)
*   **Feedback Loop:** Trên giao diện Streamlit Dashboard, khi cảnh báo UEBA hiển thị, thêm tính năng "Đánh dấu Sai (False Positive)". Nếu đánh dấu sai, lưu vector sự kiện đó lại để lần Retrain tiếp theo mô hình sẽ học để bỏ qua.
*   Viết kịch bản Demo:
    *   *Demo 1:* Copy 1 đoạn code lên ChatGPT -> Risk_score = 40 (Chỉ YARA + Pseudo-rule). Không khóa.
    *   *Demo 2:* Copy 10 đoạn code liên tục trong 1 phút vào lúc 12h đêm lên ChatGPT -> Điểm Anomaly nhảy lên 90 -> Risk_score nhảy lên 85 -> **ALERT ĐỎ CHÓT** -> Chứng minh ML phát hiện được hành vi mà luật tĩnh bỏ sót.

---

## 5. CÁC BỘ DATASET BỔ SUNG CHO BÀI TOÁN UEBA/INSIDER THREAT

Ngoài CERT và LANL, dưới đây là các bộ dataset public chất lượng cao có thể được dùng để đa dạng hóa việc huấn luyện mô hình UEBA:

**1. BETH Dataset (Behavioral Threat)**
*   **Nguồn:** [Kaggle - BETH Dataset](https://www.kaggle.com/datasets/kateeespona/beth-dataset)
*   **Tác giả:** Nghiên cứu từ nhóm bảo mật của Đại học University College London (UCL) và Alan Turing Institute.
*   **Mô tả:** Tập dữ liệu tập trung hoàn toàn vào logs hệ thống (Linux host logs, process logs, network logs) của các máy trạm (host-based). Khác với các bộ data thiên về mạng, BETH có chứa log hoạt động thực tế trên máy, rất giống cấu trúc dữ liệu thu được từ Endpoint Agent.
*   **Ứng dụng:** Cực kỳ phù hợp để huấn luyện mô hình phát hiện tiến trình bất thường (Process Anomaly). 

**2. CTU-13 Dataset**
*   **Nguồn:** [CTU-13 Malware Dataset](https://www.stratosphereips.org/datasets-ctu13)
*   **Mô tả:** Tập hợp dữ liệu từ Đại học Kỹ thuật Séc (CTU) mô phỏng các botnet và malware.
*   **Ứng dụng:** Mặc dù chuyên về botnet, phần dữ liệu "background" (hành vi bình thường) của nó rất sạch và đồ sộ, có thể dùng để định hình "Baseline" cho các rule liên quan đến network/upload.

**3. UNSW-NB15 Dataset**
*   **Nguồn:** [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
*   **Mô tả:** Bộ dữ liệu bao gồm song song hành vi bình thường và 9 loại tấn công mạng tổng hợp (bao gồm cả phân tích payload nội dung).
*   **Ứng dụng:** Có thể sử dụng các trường (features) như `sbytes`, `dbytes`, `sttl` để mô phỏng kịch bản người dùng tuồn một lượng lớn dữ liệu nội bộ ra máy chủ bên ngoài (Data Exfiltration).

**4. Synthetic Data Generation Frameworks**
*   **Nguồn:** Các kho lưu trữ GitHub cộng đồng (Ví dụ công cụ `LogSynth` hoặc `EventGen`).
*   **Mô tả:** Thay vì lấy tệp CSV, bạn sử dụng các thư viện tạo log giả lập theo kịch bản tùy ý để chủ động tạo số lượng lớn file JSONL với định dạng khớp 100% với định dạng của đồ án.