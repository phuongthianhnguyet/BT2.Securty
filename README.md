# BT2. AN TOÀN VÀ BẢO MẬT THÔNG TIN
## Họ và tên: Phương Thị Ánh Nguyệt - K225480106098
## CÁC YÊU CẦU CỤ THỂ
### Cấu trúc PDF liên quan chữ ký (Nghiên cứu)
### Thời gian ký được lưu ở đâu?
### Bước tạo và lưu chữ ký trong PDF (đã có private RSA)- Viết script/code thực hiện tuần tự.
### Các bước xác thực chữ ký trên PDF đã ký- Các bước kiểm tra
   
## YÊU CẦU NỘP BÀI
 1. Báo cáo PDF ≤ 6 trang: mô tả cấu trúc, thời gian ký, rủi ro bảo mật.
 2. Code + README (Git repo hoặc zip).
 3. Demo files: original.pdf, signed.pdf, tampered.pdf.
 4. (Tuỳ chọn) Video 3–5 phút demo kết quả.
 1. Báo cáo PDF ≤ 6 trang: mô tả cấu trúc, thời gian ký, rủi ro bảo mật.
 2. Code + README (Git repo hoặc zip).
 3. Demo files: original.pdf, signed.pdf, tampered.pdf.
 4. (Tuỳ chọn) Video 3–5 phút demo kết quả.
## BÀI LÀM
### Sinh Khoá RSA và chứng thư số
**Tạo file:** `BT2.SECUR/gen_keys.py`

**Thao tác:** `cd BT2.SECUR python gen_keys.py`

**Kết quả:**

*keys/signer_cert.pem* (RSA 2048-bit)

*keyssigner_key.pem* (Chứng thư số tự ký)

### Tạo và kí file pdf

**file:** `sign_pdf.py`

**Thực hiện:** `python sign_pdf.py`

**Kết quả:**
**File `Phuong_Anh_Nguyet.pdf`(PDF đã có chữ ký số hợp lệ)**

<img width="1917" height="990" alt="image" src="https://github.com/user-attachments/assets/8d080551-c244-40e0-afb0-172c2404bb7c" />

### Xác minh chữ ký PDF
**Kết quả** khi đã xác minh thành công

<img width="1866" height="536" alt="image" src="https://github.com/user-attachments/assets/0076c635-835a-4bbe-8a66-a78a741107f9" />


