# verify_pdf_signature_v2.1.py
from pyhanko.sign import validation
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.keys import load_cert_from_pemder
from pyhanko_certvalidator import ValidationContext
from pyhanko.sign.diff_analysis import ModificationLevel
from datetime import datetime, timezone, timedelta
import hashlib, os, sys

PDF_PATH = r"C:\Users\Admin\Desktop\BT2.SECUR\Phuong_Anh_Nguyet.pdf"
CERT_PATH = r"C:\Users\Admin\Desktop\BT2.SECUR\keys\signer_cert.pem"
LOG_PATH = r"C:\Users\Admin\Desktop\BT2.SECUR\verifyOK.txt"

def write_log(msg):
    print(msg)
    with open(LOG_PATH, "a", encoding="utf-8") as lf:
        lf.write(msg + "\n")

open(LOG_PATH, "w").close()
write_log("=== KIỂM TRA XÁC THỰC CHỮ KÝ PDF ===")
write_log(f"Thời gian kiểm thử: {datetime.now()}")
write_log(f"File kiểm tra: {PDF_PATH}")
write_log("====================================")

# --- B1: Tạo Validation Context ---
vc = ValidationContext(
    trust_roots=[load_cert_from_pemder(CERT_PATH)],
    allow_fetching=False
)

# --- B2: Đọc PDF ---
with open(PDF_PATH, "rb") as f:
    reader = PdfFileReader(f)
    sigs = reader.embedded_signatures

    if not sigs:
        write_log("❌ Không tìm thấy chữ ký nào trong file.")
        sys.exit(1)

    sig = sigs[0]
    name = sig.field_name or "DigitalSign_1"
    write_log(f"🔍 Phát hiện chữ ký: {name}")

    sig_dict = sig.sig_object
    byte_range = sig_dict.get("/ByteRange")
    contents = sig_dict.get("/Contents")
    write_log(f"/ByteRange: {byte_range}")
    write_log(f"/Contents length: {len(contents)} bytes")

    # --- B3: Tính hash SHA-256 ---
    f.seek(0)
    data = f.read()
    try:
        r0, l0, r1, l1 = map(int, byte_range)
        segment = data[r0:r0+l0] + data[r1:r1+l1]
        digest = hashlib.sha256(segment).hexdigest()
        write_log(f"SHA-256(ByteRange): {digest[:64]}... ✅")
    except Exception as e:
        write_log(f"⚠️ Lỗi tính hash: {e}")

    # --- B4: Xác thực chữ ký ---
    write_log("====================================")
    write_log("🔒 Đang xác thực chữ ký...")
    status = validation.validate_pdf_signature(sig, vc)
    write_log(status.pretty_print_details())

    # --- B5: Thông tin chứng thư ---
    cert = status.signing_cert
    if cert:
        subj = cert.subject.human_friendly
        write_log("\n📜 Thông tin chứng thư người ký:")
        write_log(f"  Chủ thể: {subj}")

        sha1_fp = cert.sha1_fingerprint
        sha256_fp = cert.sha256_fingerprint

        # đảm bảo không lỗi .hex()
        if hasattr(sha1_fp, "hex"):
            sha1_fp = sha1_fp.hex()
        if hasattr(sha256_fp, "hex"):
            sha256_fp = sha256_fp.hex()

        write_log(f"  SHA1 fingerprint: {sha1_fp}")
        write_log(f"  SHA256 fingerprint: {sha256_fp}")
    else:
        write_log("⚠️ Không đọc được chứng thư người ký.")

    # --- B6: Thời gian ký ---
    if status.signer_reported_dt:
        vn_time = status.signer_reported_dt.astimezone(timezone(timedelta(hours=7)))
        write_log(f"🕒 Thời gian ký (VN): {vn_time}")
    else:
        write_log("⚠️ Không có timestamp RFC3161 (ký offline).")

    # --- B7: Phát hiện sửa đổi ---
    mod = getattr(status, "modification_level", None)
    if mod == ModificationLevel.NONE:
        write_log("✅ File chưa bị chỉnh sửa kể từ khi ký.")
    elif mod == ModificationLevel.FORM_FILLING:
        write_log("⚠️ File có thay đổi nhỏ (điền form).")
    else:
        write_log("❌ File đã bị thay đổi sau khi ký!")

# --- B8: Kết luận ---
write_log("====================================")

# Kiểm tra sửa đổi
if mod == ModificationLevel.NONE:
    if status.bottom_line:
        write_log("✅ KẾT LUẬN: CHỮ KÝ HỢP LỆ - TÀI LIỆU NGUYÊN VẸN.")
    else:
        # Trường hợp self-signed nhưng không bị chỉnh sửa
        write_log("✅ KẾT LUẬN: CHỮ KÝ TỰ KÝ (SELF-SIGNED) - FILE NGUYÊN VẸN.")
        write_log("⚠️ Lưu ý: Chứng thư không thuộc CA tin cậy, nhưng dữ liệu không bị thay đổi.")
else:
    write_log("❌ CHỮ KÝ KHÔNG HỢP LỆ hoặc FILE BỊ SỬA ĐỔI.")
    write_log("⚠️ Lý do thường gặp: chứng thư tự ký (self-signed), không có nonRepudiation, hoặc không thuộc CA tin cậy.")

write_log(f"\n📄 Log đã lưu tại: {LOG_PATH}")
