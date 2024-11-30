import pyotp
import qrcode

secret = pyotp.random_base32()
print(f"Your TOTP secret key: {secret}")

totp = pyotp.TOTP(secret)

provisioning_uri = totp.provisioning_uri(name="user@example.com", issuer_name="YourAppName")
print(f"Provisioning URI: {provisioning_uri}")

qr = qrcode.QRCode(box_size=10, border=5)
qr.add_data(provisioning_uri)
qr.make(fit=True)

img = qr.make_image(fill="black", back_color="white")
img.save("totp_qr.png")
print("QR code saved as 'totp_qr.png'. Scan it with Microsoft Authenticator.")

print("\nScan the QR code with your authenticator app (e.g., Microsoft Authenticator).")
print("Enter the 6-digit code from your app to verify:")

while True:
    user_otp = input("Enter OTP: ")
    if totp.verify(user_otp):
        print("Hello! OTP is correct.")
        break
    else:
        print("No! Invalid OTP. Please try again.")
