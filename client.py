import re
import socket
import threading
import pickle  # For serialization
from Crypto.Random import get_random_bytes
from BlockCipher import BlockCipher
from db import DB
import getpass  # For password input
from hashing import MD5
import sys  # For exiting the program
import auth  # Importing the auth module
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

ClientBlockCipherObj = BlockCipher()
CipherSelected = "RSA"  # Default block cipher


def write_key_to_file(key, filename):
    with open(filename, "wb") as file:
        file.write(key)

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key





def connect_to_server():
    global CipherSelected, symmetric_key
    db = DB()  # Create an instance of DB
    hasher = MD5()  # Create an instance of the MD5 class

    print("Do you want to login or signup?")
    action = input("Type 'login' or 'signup': ").strip().lower()

    username = input("Enter your username: ").strip()
    if not username:
        print("Error: Username cannot be empty.")
        return

    if action == "signup":
        if db.is_account_exist(username):
            print("Username already exists. Please login.")
            return

        password = getpass.getpass("Enter your password: ")
        totp_secret = auth.generate_totp_secret(username)  # Generate and store the TOTP secret
        db.register(username, password, totp_secret)
        print("Signup successful. You can now login.")

    elif action == "login":
        if not db.is_account_exist(username):
            print("Account does not exist. Please signup first.")
            return

        """password = getpass.getpass("Enter your password: ")
        hashed_password = hasher.calculate_md5(password)
        stored_password = db.get_password(username)
        if hashed_password != stored_password:
            print("Invalid credentials. Please try again.")
            return"""

        # TOTP verification
        """totp_secret = db.get_totp_secret(username)
        while True:
            user_otp = input("Enter OTP from your authenticator app: ")
            if auth.verify_totp(totp_secret, user_otp):
                print("OTP verified successfully!")
                break
            else:
                print("Invalid OTP. Please try again.")"""

        print("Login successful.")

    else:
        print("Invalid action. Please type 'login' or 'signup'.")
        return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(("127.0.0.1", 5560))

        client_socket.send(username.encode())  # Send username
        PreConfig = client_socket.recv(1024).decode()
        CipherSelected = PreConfig.split(":")[0]
        print(f"Connected using {CipherSelected}")

        if CipherSelected == "RSA":
            private_key, public_key = generate_rsa_key_pair()

            # Serialize public key
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Send public key to server
            client_socket.send(public_key_pem)
            other_client_public_key_pem = client_socket.recv(2048)
            other_client_public_key = serialization.load_pem_public_key(other_client_public_key_pem)

            # Start receiving and sending threads
            threading.Thread(target=receive_message, args=(client_socket, private_key)).start()
            send_message(client_socket, username, public_key, other_client_public_key)

        elif CipherSelected == "AES" or CipherSelected == "DES":
            # Generate a symmetric key based on the selected block cipher
            symmetric_key = get_random_bytes(16 if CipherSelected == "AES" else 8)
            write_key_to_file(symmetric_key, "symmetric.key")
            # Start receiving and sending threads
            threading.Thread(target=receive_message, args=(client_socket,)).start()
            send_message(client_socket, username)

    except Exception as e:
        print(f"Connection error: {e}")
        client_socket.close()


def send_message(client_socket, username, rsa_public_key, other_client_public_key):
    try:
        while True:
            message = input(f"{username}: ")
            if message.lower() == "q":  # Check if the user wants to quit
                print("Exiting chat...")
                client_socket.close()
                sys.exit()

            plaintext = f"{username}: {message}"
            # Encrypt message based on block cipher selection
            if CipherSelected == "RSA":
                encrypted_data = rsa_encrypt(other_client_public_key, plaintext)
            elif CipherSelected == "AES":
                # Read symmetric key from file
                with open("symmetric.key", "rb") as file:
                    symmetric_key1 = file.read()
                    encrypted_data = ClientBlockCipherObj.encrypt_AES_EAX(plaintext.encode("utf-8"), symmetric_key1)
            else:
                # Read symmetric key from file
                with open("symmetric.key", "rb") as file:
                    symmetric_key1 = file.read()
                    encrypted_data = ClientBlockCipherObj.encrypt_DES_EAX(plaintext.encode("utf-8"), symmetric_key1)

            client_socket.sendall(pickle.dumps(encrypted_data))
            print("Message sent!")
    except KeyboardInterrupt:
        print("\nExiting... Goodbye!")
        client_socket.close()
        sys.exit()


def receive_message(client_socket, rsa_private_key):
    try:
        while True:

            data = pickle.loads(client_socket.recv(4096))  # Deserialize data

            if CipherSelected == "RSA":
                plaintext = rsa_decrypt(rsa_private_key, data)
            elif CipherSelected == "AES":
                ciphertext, tag, nonce = data
                with open("symmetric.key", "rb") as file:
                    symmetric_key = file.read()
                    plaintext = ClientBlockCipherObj.decrypt_AES_EAX(ciphertext, symmetric_key, nonce, tag)
            else:
                ciphertext, tag, nonce = data
                with open("symmetric.key", "rb") as file:
                    symmetric_key = file.read()
                    plaintext = ClientBlockCipherObj.decrypt_DES_EAX(ciphertext, symmetric_key, nonce, tag)

            print(f"\nReceived: {plaintext}")
    except Exception as e:
        print(f"Error receiving message: {e}")
        client_socket.close()


def load_rsa_private_key(filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key


def load_rsa_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key


def rsa_encrypt(public_key, message):
    encrypted = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def rsa_decrypt(private_key, ciphertext):
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')


if __name__ == "__main__":
    connect_to_server()
