# Secret giả trong lịch sử Git — Checkpoint 4

- **Scanner và phiên bản:** Gitleaks v8.30.1, được pin trong `.pre-commit-config.yaml`.
- **Commit chứa token giả:** `1bdd849`.
- **File chứa token giả:** `lab-fake-secret.txt`.
- **Phân loại:** Token synthetic được đưa vào lịch sử Git để phục vụ bài lab.
- **Phạm vi ảnh hưởng:** Token đã xuất hiện trong lịch sử Git. Xóa file khỏi working tree hoặc commit hiện tại không tự động xóa nội dung khỏi các commit cũ.
- **Bằng chứng:** Thông tin commit, diff của commit và kết quả quét Gitleaks.
- **Biện pháp xử lý:** Với token thật, cần thu hồi hoặc xoay vòng (rotate) credential ngay tại bên cấp khóa (identity provider/service), sau đó làm sạch lịch sử Git theo quy trình được phê duyệt và phối hợp cập nhật các bản clone/fork. Với token giả của bài lab, ghi nhận bằng chứng và không sử dụng token đó cho hệ thống thật.
- **Rule ID phát hiện:** lab24-synthetic-token.
- **Vì sao pin dependency và hook không thay thế bước rotate khi secret đã lộ:** Pinning dependency (như mã băm sha256 trong `requirements.lock`) và pre-commit hook chỉ là các chốt chặn phòng ngừa (preventive controls) ở tầng supply chain và kiểm soát trước khi commit vào working tree/HEAD trong tương lai. Khi một secret đã từng bị commit vào lịch sử Git, nó có thể đã bị clone, cache hoặc trích xuất ra ngoài. Các biện pháp tĩnh ở client không thể vô hiệu hóa trạng thái xác thực của khóa trên hệ thống đích; do đó, việc thu hồi và rotate credential tại máy chủ xác thực là biện pháp ứng phó sự cố (remediation) bắt buộc và duy nhất giúp triệt tiêu rủi ro bị khai thác.
