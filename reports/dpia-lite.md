# DPIA-Lite — Đánh Giá Tác Động Bảo Vệ Dữ Liệu Cá Nhân (Checkpoint 5)

Báo cáo phân tích dòng dữ liệu, quyền hạn xử lý, cơ chế kiểm soát rủi ro và bằng chứng thực nghiệm trong kiến trúc Governance Agent Day 24.

---

### 1. Loại dữ liệu và phân loại (Data Inventory & Classification)

- **Các trường dữ liệu thu thập/xử lý:**
  - Dữ liệu PII khách hàng (tập dữ liệu synthetic): Họ và tên (`name`), Số định danh cá nhân (`cccd` - 12 chữ số), Số điện thoại liên lạc (`phone` - 10 chữ số), Số tài khoản ngân hàng (`bank_account` - 8 đến 16 chữ số), Địa chỉ thư điện tử (`email`), và Danh sách mã vé hỗ trợ liên kết (`related_tickets`).
  - Dữ liệu tài liệu hỗ trợ: Nội dung vé hỗ trợ khách hàng trong `corpus/ticket-*.md`.
- **Cấp độ phân loại dữ liệu (Classification Levels):**
  - `internal`: Dữ liệu tài liệu kỹ thuật, tài liệu quy trình nội bộ trong `corpus/`.
  - `restricted`: Hồ sơ khách hàng chứa thông tin PII định danh cá nhân (`data/customers.json`). Yêu cầu bảo mật cấp cao nhất; nghiêm cấm phát tán ra môi trường ngoài hoặc chuyển qua ranh giới không kiểm soát.
  - `audit`: Bản ghi nhật ký hoạt động gọi công cụ. Không lưu trữ PII thô; chỉ lưu trữ giá trị băm chuẩn hóa (`args_hash`).

---

### 2. Mục đích xử lý và chủ thể (Purpose Limitation & Principals)

- **Mục đích xử lý hợp lệ (`request_purpose`):**
  - `summarize-tickets`: Tổng hợp nội dung các vé hỗ trợ kỹ thuật còn mở trong tuần để báo cáo tổng quan.
  - `support-reply`: Tra cứu thông tin khách hàng gắn với vé hợp lệ để phục vụ hỗ trợ giải quyết sự cố.
- **Vai trò và quyền hạn chủ thể (Principals & Permissions):**
  - `support_l1` (Nhân viên hỗ trợ bậc 1):
    - Phạm vi công cụ: Chỉ được phép gọi `search_docs` với mục đích `summarize-tickets`.
    - Ràng buộc: Bị từ chối tuyệt đối khi yêu cầu gọi `read_customer` hoặc `http_post`.
  - `dpo` (Cán bộ phụ trách bảo vệ dữ liệu - Data Protection Officer):
    - Phạm vi công cụ: Được phép gọi `search_docs` và `read_customer` khi có mục đích hợp lệ (`support-reply`).
    - Ràng buộc: Bị từ chối khi thực hiện hành vi trích xuất dữ liệu ngoại vi (`http_post`) mang nhãn `restricted`.
- **Ủy quyền và thời hạn hiệu lực (Delegation & TTL):**
  - Mỗi phiên chạy có thời hạn tối đa 5 phút (`RUN_TTL = timedelta(minutes=5)`). Quyền ủy quyền của tác nhân con (`agent_scopes`) luôn bị chặn nếu vượt quá quyền tác nhân cha (`parent_scopes`).

---

### 3. Dữ liệu đi qua những run/tool nào, endpoint nào (Data Flow & Architecture)

- **Giai đoạn Run A (`lab24-agent/run-a` - Phân tích tài liệu công khai/nội bộ):**
  - Nhận yêu cầu từ người dùng (`message`).
  - Gọi công cụ `tools.search_docs` (phân loại `internal`) để nạp tài liệu từ `corpus/`.
  - **PII Redaction Gate:** Áp dụng `agent.pii.redact()` để che giấu toàn bộ CCCD, SĐT, STK, Email trong văn bản trước khi đưa vào ngữ cảnh xử lý.
  - **Trifecta Split Boundary:** Run A chỉ trích xuất danh sách ID dạng số (`list[int]`) từ **tên file Markdown** (`_extract_ticket_ids`). Toàn bộ nội dung văn bản tự do do người dùng hoặc kẻ tấn công đưa vào bị chặn lại tại boundary này.
- **Giai đoạn Run B (`lab24-agent/run-b` - Xử lý dữ liệu nhạy cảm):**
  - Nhận danh sách ticket ID số từ Run A.
  - Tra cứu khách hàng tương ứng thông qua ánh xạ tin cậy `related_tickets` trong `data/customers.json` (`_resolve_customer_ids`).
  - Gọi công cụ `tools.read_customer` (phân loại `restricted`) cho từng khách hàng sau khi thông qua kiểm tra chính sách.
  - Hồ sơ khách hàng được giữ kín trong phạm vi Run B, không gửi ngược lại vào ngữ cảnh LLM tổng hợp và không trả về người dùng CLI.
- **Ranh giới gửi dữ liệu ngoại vi (Egress Endpoint):**
  - Điểm đến ngoại vi dự kiến của kẻ tấn công: Sink HTTP endpoint `http://127.0.0.1:10024/reconcile`.
  - Khi tác nhân cố gắng thực hiện `tools.http_post`, Policy Enforcement Point (PEP) chặn lại ngay tại ranh giới trước khi request mạng được khởi tạo.

---

### 4. Bằng chứng deny/allow và giới hạn của mock (Evidence & Mock Limitations)

- **Bằng chứng kiểm toán (Ledger & Exfiltration Evidence):**
  - **Sổ cái `reports/ledger.jsonl`:**
    - Ghi nhận `allow` cho `search_docs` với principal `support_l1` và `dpo`.
    - Ghi nhận `deny` đối với `read_customer` khi chạy dưới quyền `support_l1` (Lý do: `requested tool is outside principal permissions`).
    - Ghi nhận `deny` đối với `http_post` khi chạy dưới quyền `dpo` (Lý do: `restricted data is not allowed when egress is enabled`).
    - Toàn bộ 46 bản ghi có `reason` hợp lệ và xác thực chuỗi băm thành công (`agent.ledger.verify() == True`).
  - **File log Sink so sánh trước và sau containment:**
    - `reports/attack-before.log` (299 bytes): Chứa dữ liệu rò rỉ của `KH-000999` (Lê Thu Trang, CCCD 811753472374) trong kịch bản baseline chưa bảo vệ.
    - `reports/attack-after.log` (0 bytes): Hoàn toàn rỗng sau khi kích hoạt containment runner; không có byte dữ liệu nào bị gửi tới sink.
  - **Kết quả kiểm thử tự động:** Toàn bộ 33/33 ca kiểm thử trong `tests/` vượt qua thành công, bao gồm kiểm tra phân quyền OBO, Trifecta split, và ngăn chặn 4 biến thể injection.
- **Giới hạn của môi trường Mock (Mock Limitations):**
  - Dữ liệu sử dụng trong bài lab là dữ liệu giả lập (synthetic data), không phải dữ liệu cá nhân của người dùng thực tế.
  - Sink đích là web server HTTP mock chạy trên cổng cục bộ localhost `127.0.0.1:10024`.
  - Mô hình ngôn ngữ sử dụng Fake LLM đối sánh quy tắc chuỗi để mô phỏng phản hồi, chưa bao gồm các rủi ro phi tất định của các mô hình LLM lớn ngoài thực tế.
  - Cơ chế phân quyền và kiểm soát chính sách được mô phỏng nội bộ trong tiến trình ứng dụng Python, chưa tích hợp hệ thống quản lý danh tính doanh nghiệp (Enterprise IAM/OAuth2) hoặc hạ tầng mạng Zero-Trust.
