import qrcode


def create_qr(
    content,
    filename,
):
    image = qrcode.make(content)
    image.save(filename)

    print(
        f"Created: {filename}"
    )


create_qr(
    "https://www.google.com",
    "safe_qr.png",
)

create_qr(
    "http://verify-account-security.example.xyz/login",
    "suspicious_qr.png",
)

create_qr(
    "Welcome to PhishGuard AI and ML",
    "text_qr.png",
)