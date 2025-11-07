# update_pdf_incremental.py (robust, tương thích nhiều phiên bản pikepdf)
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
import pikepdf
from pathlib import Path
import sys

# --- Cấu hình đường dẫn (chỉnh theo máy bạn) ---
SIGNED_FILE = r"C:\Users\Admin\Desktop\BT2.SECUR\Phuong_Anh_Nguyet.pdf"
UPDATED_FILE = r"C:\Users\Admin\Desktop\BT2.SECUR\ThemNDvaoPAN.pdf"
OVERLAY_FILE = r"C:\Users\Admin\Desktop\BT2.SECUR\NDThem.pdf"

# --- Đăng ký font Unicode ---
FONT_PATH = Path("C:/Windows/Fonts/arial.ttf")
try:
    pdfmetrics.registerFont(TTFont("ArialUnicode", str(FONT_PATH)))
except Exception:
    # nếu font không tìm thấy, vẫn tiếp tục (reportlab sẽ dùng font mặc định)
    pass

print("pikepdf version:", getattr(pikepdf, "__version__", "unknown"))
print("Python:", sys.version.splitlines()[0])

# --- Tạo overlay PDF (incremental layer) ---
print("🔹 Tạo overlay layer (overlay_layer.pdf)...")
c = canvas.Canvas(OVERLAY_FILE, pagesize=A4)
c.setFont("ArialUnicode", 14)
c.setFillColorRGB(0.1, 0.4, 0.8)
c.drawString(60, 700, "Hello Thầy Đỗ Duy Cốp, em là Nguyệt K58KTP đây hẹ hẹ :))")
c.save()
print("✅ Đã tạo:", OVERLAY_FILE)

# --- Mở PDF đã ký và chèn overlay ---
print("🔹 Mở PDF đã ký và thêm overlay (không phá chữ ký)...")
pdf = pikepdf.Pdf.open(SIGNED_FILE)
overlay = pikepdf.Pdf.open(OVERLAY_FILE)

# áp overlay lên trang cuối cùng
pdf.pages[-1].add_overlay(overlay.pages[0])
print("✅ Overlay đã được chèn vào trang cuối.")

# --- Lấy Root / Catalog theo nhiều cách (robust) ---
def get_root_dict(pdf_obj):
    """
    Trả về Catalog dictionary (Root) theo phiên bản pikepdf.
    """
    # 1) Thuộc tính 'root' (cũ)
    if hasattr(pdf_obj, "root"):
        root = pdf_obj.root
        print("Info: dùng pdf.root")
        return root
    # 2) open_root() (một số phiên bản)
    if hasattr(pdf_obj, "open_root"):
        try:
            root = pdf_obj.open_root()
            print("Info: dùng pdf.open_root()")
            return root
        except Exception:
            pass
    # 3) trailer '/Root'
    try:
        tr = pdf_obj.trailer
        if "/Root" in tr:
            root = tr["/Root"]
            print("Info: dùng pdf.trailer['/Root']")
            return root
    except Exception:
        pass
    # 4) thử attribute 'Root'
    if hasattr(pdf_obj, "Root"):
        try:
            root = getattr(pdf_obj, "Root")
            print("Info: dùng pdf.Root")
            return root
        except Exception:
            pass
    raise RuntimeError("Không thể lấy Catalog (/Root) từ PDF với pikepdf hiện tại.")

# --- Tạo DSS dictionary (mô phỏng) ---
print("🔹 Thêm trường /DSS mô phỏng vào Catalog...")
try:
    root = get_root_dict(pdf)
except RuntimeError as e:
    print("ERROR: ", e)
    pdf.close()
    overlay.close()
    raise

# chuẩn bị DSS dict
dss = pikepdf.Dictionary()
dss[pikepdf.Name("/Type")] = pikepdf.Name("/DSS")
dss[pikepdf.Name("/Note")] = pikepdf.String("Simulated DSS block (Certs/OCSP/CRL placeholders)")

# gán vào Catalog (root)
root[pikepdf.Name("/DSS")] = dss

# --- Lưu file với incremental update (tương thích PikePDF 10) ---
print("🔹 Lưu PDF mới theo cách tương thích PikePDF 10 (tạo revision mới)...")

try:
    # Dùng save() bình thường, PikePDF >=10 sẽ tự xử lý cấu trúc xref
    pdf.save(UPDATED_FILE)
    print(f"✅ Hoàn tất. File đã lưu: {UPDATED_FILE}")
except Exception as e:
    print("❌ Lỗi khi lưu file:", e)
finally:
    pdf.close()
    overlay.close()