import io
import base64
import qrcode
from PIL import Image

def generate_qr_png_bytes(data: str) -> bytes:
    """
    Generates a PNG image of a QR code containing the provided text data.
    """
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()

def generate_qr_base64(data: str) -> str:
    """
    Generates a base64 Data URI string for rendering in HTML <img> tags.
    """
    png_bytes = generate_qr_png_bytes(data)
    b64_str = base64.b64encode(png_bytes).decode("utf-8")
    return f"data:image/png;base64,{b64_str}"
