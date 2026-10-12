# Secret giả trong lịch sử Git — Checkpoint 4

- **Scanner và phiên bản:** Gitleaks v8.30.1, được pin trong `.pre-commit-config.yaml`.
- **Commit chứa token giả:** `1bdd849`.
- **File chứa token giả:** `lab-fake-secret.txt`.
- **Phân loại:** Token synthetic được đưa vào lịch sử Git để phục vụ bài lab.
- **Phạm vi ảnh hưởng:** Token đã xuất hiện trong lịch sử Git. Xóa file khỏi working tree hoặc commit hiện tại không tự động xóa nội dung khỏi các commit cũ.
- **Bằng chứng:** Thông tin commit, diff của commit và kết quả quét Gitleaks.
- **Biện pháp xử lý:** Với token thật, cần thu hồi hoặc xoay vòng credential ngay, sau đó làm sạch lịch sử Git theo quy trình được phê duyệt và phối hợp cập nhật các bản clone/fork. Với token giả của bài lab, ghi nhận bằng chứng và không sử dụng token đó cho hệ thống thật.
- **Rule ID phát hiện:** lab24-synthetic-token.
