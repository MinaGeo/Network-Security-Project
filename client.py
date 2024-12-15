import socket
import threading
import pickle  # For serialization
from BlockCipher import BlockCipher
from db import DB
import getpass  # For password input
from hashing import MD5
import sys  # For exiting the program
import auth  # Importing the auth module
from cryptography.hazmat.primitives import serialization
from rsa import *
from DiffieHellman import *
from pem import *
from clieditor import *
online_users = []
def connect_to_server():
    global CipherSelected, symmetric_key, BlockCipherObj
    db = DB()  # Create an instance of DB
    hasher = MD5()  # Create an instance of the MD5 class

    while True:
        yellow_message("Do you want to login or signup?")
        action = input("Type 'login' or 'signup': ").strip().lower()

        if action not in ['login', 'signup']:
            red_message("Invalid action. Please type 'login' or 'signup'.")
            continue

        username = input("Enter your username: ").strip()
        if not username:
            red_message("Error: Username cannot be empty.")
            continue

        if action == "signup":
            if db.is_account_exist(username):
                red_message("Username already exists. Please login.")
                continue

            password = getpass.getpass("Enter your password: ")
            totp_secret = auth.generate_totp_secret(username)
            db.register(username, password, totp_secret)
            green_message("Signup successful. You can now login.")

        elif action == "login":
            if not db.is_account_exist(username):
                red_message("Account does not exist. Please signup first.")
                continue
            if username in online_users:
                red_message("User already logged in.")
                continue

            password = getpass.getpass("Enter your password: ")
            hashed_password = hasher.calculate_md5(password)
            stored_password = db.get_password(username)
            if hashed_password != stored_password:
                red_message("Invalid credentials. Please try again.")
                continue

            totp_secret = db.get_totp_secret(username)
            while True:
                user_otp = input("Enter OTP from your authenticator app: ")
                if auth.verify_totp(totp_secret, user_otp):
                    online_users.append(username)
                    green_message("OTP verified successfully!")
                    break
                else:
                    red_message("Invalid OTP. Please try again.")

        break

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(("127.0.0.1", 5560))
        while True:
            CipherSelected = input("Enter the block cipher you want to use (AES, DES, or RSA): ").strip().upper()
            if CipherSelected not in ["AES", "DES", "RSA"]:
                red_message("Invalid cipher selection. Choose AES, DES, or RSA.")
                continue
            break

        message = f"{CipherSelected},{username}"
        client_socket.sendall(message.encode())
        blue_message(f"Connected using {CipherSelected}")

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

            if other_client_public_key is None:
                red_message("Error receiving public key.")
                client_socket.close()
                sys.exit()
            else:
                yellow_message("Chat started!")

            # Start receiving and sending threads
            threading.Thread(target=receive_message, args=(client_socket, private_key, None)).start()
            send_message(client_socket, username, other_client_public_key, None)

        if CipherSelected == "AES" or CipherSelected == "DES":
            dh_private_key = generate_private_key()
            symmetric_key = generate_public_key(dh_private_key)
            BlockCipherObj = BlockCipher(dh_private_key, symmetric_key)

            dh_public_key_bytes = int_to_pem(symmetric_key, "INTEGER")
            client_socket.send(dh_public_key_bytes)

            dh_other_client_public_key_pem = client_socket.recv(2048)
            dh_other_client_public_key = pem_to_int(dh_other_client_public_key_pem)
            if dh_other_client_public_key is None:
                red_message("Error receiving public key.")
                client_socket.close()
                sys.exit()
            else:
                yellow_message("Chat started!")
            # Start receiving and sending threads
            threading.Thread(target=receive_message,
                             args=(client_socket, dh_other_client_public_key, BlockCipherObj)).start()
            send_message(client_socket, username, dh_other_client_public_key, BlockCipherObj)


    except Exception as e:
        red_message(f"Connection error: {e}")
        client_socket.close()


def send_message(client_socket, username, other_client_public_key, BlockCipherObj):
    try:
        while True:
            message = input()
            if message.lower() == "q":  # Check if the user wants to quit
                # Send an exit message to the server
                exit_message = f"{username} has left the chat."
                client_socket.sendall(pickle.dumps({"exit": True, "username": username, "message": exit_message}))
                yellow_message("Exiting chat...")
                client_socket.close()
                sys.exit()

            plaintext = f"{username}: {message}"
            # Encrypt message based on block cipher selection
            if CipherSelected == "RSA":
                encrypted_data = rsa_encrypt(other_client_public_key, plaintext)
            elif CipherSelected == "AES":
                encrypted_data = BlockCipherObj.encrypt_AES_EAX(plaintext.encode("utf-8"), other_client_public_key)
            else:
                encrypted_data = BlockCipherObj.encrypt_DES_EAX(plaintext.encode("utf-8"), other_client_public_key)

            client_socket.sendall(pickle.dumps(encrypted_data))
            # green_message("Message sent!")
    except KeyboardInterrupt:
        exit_message = f"{username} has left the chat."
        client_socket.sendall(pickle.dumps({"exit": True, "username": username, "message": exit_message}))
        yellow_message("Exiting chat...")
        client_socket.close()
        sys.exit()


def receive_message(client_socket, rsa_private_key, BlockCipherObj):
    try:
        while True:

            data = pickle.loads(client_socket.recv(4096))  # Deserialize data

            if CipherSelected == "RSA":
                plaintext = rsa_decrypt(rsa_private_key, data)
            elif CipherSelected == "AES":
                ciphertext, tag, nonce = data
                plaintext = BlockCipherObj.decrypt_AES_EAX(ciphertext, rsa_private_key, nonce, tag)
                plaintext = plaintext.decode("utf-8")
            else:
                ciphertext, tag, nonce = data
                plaintext = BlockCipherObj.decrypt_DES_EAX(ciphertext, rsa_private_key, nonce, tag)
                plaintext = plaintext.decode("utf-8")

            format_message(activate_link(plaintext))
    except Exception as e:
        red_message(f"Error receiving message: {e}")
        client_socket.close()


if __name__ == "__main__":
    connect_to_server()
