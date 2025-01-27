# Chat Application with Encryption and Two-Factor Authentication

This is a secure chat application that allows users to chat with encryption and two-factor authentication (2FA). The application uses MongoDB for storing user data, including credentials and 2FA secrets.

## Requirements

1. **Download the required libraries:**
   Install the required libraries using the `requirements.txt` file:
   ```bash
   pip install -r requirements.txt
   ```
2. MongoDB: You must have MongoDB installed and running on your system to store user data.


## Running the Application

1. **Run the Server:**
   Start the server by running the following command in your terminal:
   ```bash
   python server.py

2. **Run the Client**:
   Open two separate terminals and run the client in each terminal: 
   ```bash
   python client.py
   ```
			
3. **Choose Ciphering Method**: Select your preferred ciphering method for secure communication (AES or RSA).


4. **Enjoy Chatting!**

## Libraries Used

* `pyotp`: For generating and verifying Time-based One-Time Passwords (TOTP) for 2FA.
* `qrcode`: For generating QR codes for authentication app scanning.
* `tkinter`: For displaying the QR code in a GUI window.
* `pymongo`: For MongoDB interactions.
* `cryptography`: For encryption/decryption methods (RSA, AES).


## Notes

* This application supports both RSA and AES encryption.
* Ensure MongoDB is properly set up before running the application. 

