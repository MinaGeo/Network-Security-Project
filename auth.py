import pyotp
import qrcode
from PIL import Image, ImageTk
import tkinter as tk

# This function generates a TOTP secret for a user and displays the QR code in a GUI window
def generate_totp_secret(username):
    secret = pyotp.random_base32()
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="YourAppName")

    # Generate the QR code
    qr = qrcode.QRCode(box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")

    # Display the QR code in a GUI window
    display_qr_in_gui(img, username)

    print("QR code displayed. Scan it with your authenticator app.")

    return secret

# This function displays the QR code in a tkinter GUI window
def display_qr_in_gui(qr_image, username):
    # Create a tkinter window
    window = tk.Tk()
    window.title(f"TOTP QR Code for {username}")
    window.geometry("400x400")
    window.resizable(False, False)

    # Convert the QR code image to a format tkinter can use
    qr_image_tk = ImageTk.PhotoImage(qr_image)

    # Add the QR code to the window
    qr_label = tk.Label(window, image=qr_image_tk)
    qr_label.pack(expand=True)

    # Add an instruction label
    instruction_label = tk.Label(
        window,
        text="Scan this QR code with your authenticator app.",
        font=("Arial", 12),
        pady=10,
    )
    instruction_label.pack()

    # Add a close button
    close_button = tk.Button(window, text="Close", command=window.destroy)
    close_button.pack(pady=10)

    # Run the tkinter event loop
    window.mainloop()

# This function verifies the OTP entered by the user
def verify_totp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)
