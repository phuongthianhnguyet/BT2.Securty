# BT2.AN TOÀN VÀ BẢO MẬT THÔNG TIN
## Họ và tên: Phương Thị Ánh Nguyệt - K225480106098
## CÁC YÊU CẦU CỤ THỂ
### 1) Cấu trúc PDF liên quan chữ ký (Nghiên cứu)
### 2) Thời gian ký được lưu ở đâu?
### 3)  bước tạo và lưu chữ ký trong PDF (đã có private RSA)- Viết script/code thực hiện tuần tự:
    1. Chuẩn bị file PDF gốc.
    2. Tạo Signature field (AcroForm), reserve vùng /Contents (8192 bytes).
    3. Xác định /ByteRange (loại trừ vùng /Contents khỏi hash).
    4. Tính hash (SHA-256/512) trên vùng ByteRange.
    5. Tạo PKCS#7/CMS detached hoặc CAdES
    6. Chèn blob DER PKCS#7 vào /Contents (hex/binary) đúng offset.
    7. Ghi incremental update.
    8. (LTV) Cập nhật DSS với Certs, OCSPs, CRLs, VRI.
### 4) Các bước xác thực chữ ký trên PDF đã ký- Các bước kiểm tra:
    1. Đọc Signature dictionary: /Contents, /ByteRange.
    2. Tách PKCS#7, kiểm tra định dạng.
    3. Tính hash và so sánh messageDigest.
    4. Verify signature bằng public key trong cert.
    5. Kiểm tra chain → root trusted CA.
    6. Kiểm tra OCSP/CRL.
    7. Kiểm tra timestamp token.
    8. Kiểm tra incremental update (phát hiện sửa đổi).
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
### 1) Cấu trúc PDF liên quan chữ ký (Nghiên cứu)
### 2) Thời gian ký được lưu ở đâu?
- Nêu tất cả vị trí có thể lưu thông tin thời gian:
+ /M trong Signature dictionary (dạng text, không có giá trị pháp lý).
+ Timestamp token (RFC 3161) trong PKCS#7 (attribute timeStampToken).
+ Document timestamp object (PAdES).
+ DSS (Document Security Store) nếu có lưu timestamp và dữ liệu xác minh.
- Giải thích khác biệt giữa thông tin thời gian /M và timestamp RFC3161
<img width="1917" height="990" alt="image" src="https://github.com/user-attachments/assets/8d080551-c244-40e0-afb0-172c2404bb7c" />
### 3)  bước tạo và lưu chữ ký trong PDF (đã có private RSA)- Viết script/code thực hiện tuần tự:
    1. Chuẩn bị file PDF gốc.
    2. Tạo Signature field (AcroForm), reserve vùng /Contents (8192 bytes).
    3. Xác định /ByteRange (loại trừ vùng /Contents khỏi hash).
    4. Tính hash (SHA-256/512) trên vùng ByteRange.
    5. Tạo PKCS#7/CMS detached hoặc CAdES
    6. Chèn blob DER PKCS#7 vào /Contents (hex/binary) đúng offset.
    7. Ghi incremental update.
    8. (LTV) Cập nhật DSS với Certs, OCSPs, CRLs, VRI.

<img width="1866" height="536" alt="image" src="https://github.com/user-attachments/assets/0076c635-835a-4bbe-8a66-a78a741107f9" />


