import pyotp
import qrcode
import os

# This function generates a TOTP secret for a user and returns the provisioning URI
def generate_totp_secret(username):
    secret = pyotp.random_base32()
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="YourAppName")

    # Generate and save the QR code
    qr = qrcode.QRCode(box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    qr_code_path = f"{username}_totp_qr.png"
    img.save(qr_code_path)
    print(f"QR code saved as '{qr_code_path}'. Scan it with your authenticator app.")

    return secret


# This function verifies the OTP entered by the user
def verify_totp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)
