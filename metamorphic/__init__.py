"""
metamorphic – Phase 3.5: Metamorphic Code Engine

Chạy SAU IR Obf, TRƯỚC VM.

Mỗi IRFunction được clone thành N variants.
Mỗi variant nhận một bộ transformation khác nhau (permutation of passes).
Một dispatch wrapper chọn variant dựa trên hash(args, session_key) % N.

Kết quả:
  - Same function call → cùng output (deterministic)
  - Different inputs → different code path (different variant)
  - Static analysis thấy N functions trông hoàn toàn khác nhau
  - Không có "canonical" form để reverse
"""
