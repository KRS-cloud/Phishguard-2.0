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


if __name__ == "__main__":
    create_qr(
        "https://example.com",
        "low_risk_example_qr.png",
    )

    create_qr(
        "http://training-risk.invalid/verify",
        "risk_example_qr.png",
    )

    create_qr(
        "PhishGuard defensive QR demonstration",
        "text_example_qr.png",
    )
