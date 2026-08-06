from io import BytesIO

from PIL import Image

from tests.base import AppTestCase
from app.services.qr_analyzer import decode_qr_image


class QrAnalyzerTests(AppTestCase):
    def test_rejects_non_image_content(self):
        with self.assertRaisesRegex(ValueError, "supported image"):
            decode_qr_image(b"not-an-image")

    def test_rejects_excessive_image_dimensions_before_decoding(self):
        image = Image.new("RGB", (4097, 100), "white")
        buffer = BytesIO()
        image.save(buffer, format="PNG")

        with self.assertRaisesRegex(ValueError, "dimensions are too large"):
            decode_qr_image(buffer.getvalue())
