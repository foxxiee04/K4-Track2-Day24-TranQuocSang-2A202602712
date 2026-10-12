# Verification — Báo Cáo Kiểm Tra Trước Khi Nộp

- **OS / Python / Gitleaks version:** Windows 11 (win32) / Python 3.11.9 / Gitleaks v8.30.1 (pin trong `.pre-commit-config.yaml`).
- **`python -m pytest tests/ -q`:**
  ```text
  .................................                                        [100%]
  33 passed in 3.00s
  ```
- **`pre-commit run --all-files`:**
  ```text
  Detect hardcoded secrets.................................................Passed
  ```
- **Ledger verify (`python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"`):**
  ```text
  True
  ```
- **So sánh Before/After Sink Log:**
  - `reports/attack-before.log`: 299 bytes (chứa PII synthetic của `KH-000999` bị exfiltrate trước khi sửa).
  - `reports/attack-after.log`: 0 bytes (hoàn toàn rỗng sau khi áp dụng containment runner; sink không nhận request).
- **Các lỗi còn lại:** Không có lỗi nào còn tồn đọng.
  - Toàn bộ 33/33 tests pass (100%).
  - PII evaluation trên `tests/vn_pii_testset.jsonl`: Precision = 1.000, Recall = 1.000 (100% > 95%).
  - Kiểm tra 4/4 lures injection (`python -m agent.check_lure corpus/ticket-90*.md`): 4/4 lure đều sẵn sàng và bị chặn sau containment trên cả hai principal `support_l1` và `dpo`.
  - Mọi bản ghi trong `reports/ledger.jsonl` đều có trường `reason` khác rỗng và hash chain SHA-256 hợp lệ.
  - Không vi phạm bất kỳ điều kiện trượt nào theo `RUBRIC.md`.
