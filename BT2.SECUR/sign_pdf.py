from datetime import datetime
from pyhanko.sign import signers, fields
from pyhanko.stamp.text import TextStampStyle
from pyhanko.pdf_utils import images
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.pdf_utils.layout import SimpleBoxLayoutRule, AxisAlignment, Margins
from pyhanko.sign.general import load_cert_from_pemder
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
import os

# Cấu hình đường dẫn
BASE_DIR = r"C:\Users\Admin\Desktop\BT2.SECUR"

PDF_IN = os.path.join(BASE_DIR, "Baiso2.pdf")
PDF_OUT = os.path.join(BASE_DIR, "Phuong_Anh_Nguyet.pdf")

# File khóa riêng & chứng chỉ
KEY_FILE = os.path.join(BASE_DIR, "keys", "signer_key.pem")
CERT_FILE = os.path.join(BASE_DIR, "keys", "signer_cert.pem")

# 🖋 Ảnh chữ ký (nếu có)
SIG_IMG = os.path.join(BASE_DIR, "assets", "ten.jpg")

# ---------------------------- BẮT ĐẦU QUY TRÌNH ---------------------------- #

print("Bước 1: Chuẩn bị file PDF gốc:", PDF_IN)
print("Bước 2: Tạo trường chữ ký (AcroForm), reserve /Contents ~8192 bytes.")
print("Bước 3: Xác định ByteRange (vùng hash trừ /Contents).")
print("Bước 4: Tính hash SHA-256 trên ByteRange.")
print("Bước 5: Sinh PKCS#7 detached (messageDigest, signingTime, cert chain).")

# Tải khóa & chứng chỉ
signer = signers.SimpleSigner.load(KEY_FILE, CERT_FILE, key_passphrase=None)
vc = ValidationContext(trust_roots=[load_cert_from_pemder(CERT_FILE)])

# Đọc file PDF gốc
with open(PDF_IN, "rb") as inf:
    writer = IncrementalPdfFileWriter(inf)

    # Xác định số trang
    try:
        pages = writer.root["/Pages"]
        num_pages = int(pages["/Count"])
    except Exception:
        num_pages = 1
    target_page = num_pages - 1

    # Thêm trường chữ ký vào cuối PDF
    fields.append_signature_field(
        writer,
        SigFieldSpec(
            sig_field_name="SigField1",
            box=(240, 50, 550, 150),
            on_page=target_page
        )
    )

    # Ảnh chữ ký và bố cục
    background_img = images.PdfImage(SIG_IMG)
    bg_layout = SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MIN,
        y_align=AxisAlignment.ALIGN_MID,
        margins=Margins(right=20)
    )
    text_layout = SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MIN,
        y_align=AxisAlignment.ALIGN_MID,
        margins=Margins(left=150)
    )
    text_style = TextBoxStyle(font_size=13)
    ngay_ky = datetime.now().strftime("%d/%m/%Y")

    # Nội dung chữ ký
    stamp_text = (
        "Phuong Anh Nguyet"
        "\nSDT: 0366771009"
        "\nMSSV: K225480106098"
        f"\nNgày ký: {ngay_ky}"
    )

    stamp_style = TextStampStyle(
        stamp_text=stamp_text,
        background=background_img,
        background_layout=bg_layout,
        inner_content_layout=text_layout,
        text_box_style=text_style,
        border_width=1,
        background_opacity=1.0,
    )

    # Metadata chữ ký
    meta = signers.PdfSignatureMetadata(
        field_name="SigField1",
        reason="Nộp bài: Chữ ký số PDF - 58KTP",
        location="Thái Nguyên, VN",
        md_algorithm="sha256",
    )

    pdf_signer = signers.PdfSigner(
        signature_meta=meta,
        signer=signer,
        stamp_style=stamp_style,
    )

    # Thực hiện ký PDF
    with open(PDF_OUT, "wb") as outf:
        pdf_signer.sign_pdf(writer, output=outf)

print("Bước 6: Chèn blob DER PKCS#7 vào /Contents offset.")
print("Bước 7: Ghi incremental update (SigDict + cross-ref).")
print(" Đã ký PDF thành công:", PDF_OUT)

# ----------------------------- DSS / LTV ----------------------------------- #
print("Bước 8: Thêm DSS (Long-Term Validation) nếu có thông tin xác thực...")

#try:
    #with open(PDF_OUT, "rb+") as doc:
        #writer = IncrementalPdfFileWriter(doc)
        # Tạo DSS giả lập (trong thực tế cần OCSP/CRL thực)
        #validate_pdf_signature(writer, "SigField1", vc=vc)
        #writer.write_in_place()
        #print(" Đã thêm thông tin LTV/DSS (Cert chain, CRL, OCSP).")
#except Exception as e:
    #print(" Không thể thêm DSS:", e)

print(" Hoàn tất quy trình ký PDF.")
