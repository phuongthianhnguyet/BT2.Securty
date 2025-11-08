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
### 1 Chuẩn bị file PDF gốc cần kí
### 2 Tạo file sinh khoá RSA và chứng thư số
Sinh khoá RSA và chứng thư số mục đích là để xác thực chữ kí số và ký. Tạo một file `gen_keys.py`, sau khi chạy file này sẽ sinh ra hai file `signer_cert.pem` và `signer_key.pem`.
### 3 Tạo chữ kí và kí file PDF
- Ta sẽ thực hiện tạo Signature field (AcroForm) và reserve vùng /Contents (8192 bytes), xác định /ByteRange để loại trừ vùng
/Contents khỏi hash) và tính Hash (SHA-256) trên vùng ByteRange.
Sinh PKCS#7 detached signature và chèn blob DER PKCS#7 vào
/Contents dung offset 
- Sau khi chạy lệnh python sign_pdf. py thì các bước trênđã được thực
hiện và tạo ra một file mới đã được ký chữ ký số hợp
lệ `Phuong_Anh_Nguyet.pdf`
- Đây là kết quả sau khi chạy file có chữ ký số

<img width="959" height="512" alt="3" src="https://github.com/user-attachments/assets/74b8ecb4-6636-4bc9-bcc8-25fddce01d25" />

#### Chèn thêm nội dung vào file PDF

- Tạo một file `chen_noidung.py` sau đó thêm nội dung vào file. Chạy lệnh -> tạo ra 1 file PDF đã được chèn thêm nội dung vào `ThemNDvaoPAN.pdf`

<img width="1902" height="731" alt="image" src="https://github.com/user-attachments/assets/1e09ad78-8b20-4e35-9694-94269c3b6d52" />

- Đây là thông báo từ xác thực đã khác khi thêm nội dung vào file.

<img width="1824" height="944" alt="image" src="https://github.com/user-attachments/assets/fa63a788-a567-456d-9f9c-2378857541c9" />

### 4 Xác định chữ kí trên PDF đã kí.
#### Các bước kiểm tra xác thực chữ kí trên pdf:

- Đọc Signature dictionary:/Contents,/ByteRange.
- Tách PKCS#7, kiểm tra định dạng.
- Tính hash và so sánh messageDigest.
- Verify signature bằng public key trong cert.
- Kiểm tra chain -> root trusted CA.
- Kiểm tra OCSP/CRL.
- Kiểm tra timestamp token.
- Kiểm tra incremental update (phát hiện sửa đổi). Tạo một file `verify_pdf_signature_full.py`để thực hiện chạy các  bước ở trên sau đó sẽ tạo ra file xác minh chữ kí hợp lệ hay không. Kết quả:
  
- *Có chữ kí hợp lệ*

 <img width="577" height="360" alt="OK4" src="https://github.com/user-attachments/assets/dbb5e6b4-9e76-4b0b-9e87-051b0e81449a" />
 
- *Có chữ kí không hợp lệ*
  
<img width="597" height="336" alt="ok5" src="https://github.com/user-attachments/assets/8a7348fb-f33a-4adc-ac64-e86bdd3250b5" />

### 5 Kết quả demo
 #### Sau khi thực hiện yêu cầu của đề bài, tạo ra các file:
 - Baiso2.pdf: file gốc chưa có chữ kí.
 - Phuong_Anh_Nguyet.pdf: file đã kí và chứa chữ kí số hợp lệ.
 - ThemNDvaoPAN.pdf: file chứa nội dung bị thay đổi sau khi đã kí chữ kí hợp lệ.
 - verifyFileDaChinhsua.txt: file chứa kết quả xác minh không hợp lệ do nội dung đã kí không hợp lệ.
 - verifyOK.txt: đây là file chứa kết quả xác minh hợp lệ.
