import socket
import threading
import pickle  # For serialization
from Crypto.Random import get_random_bytes
from BlockCipher import BlockCipher
from db import DB
import getpass  # For password input
from hashing import MD5
import sys  # For exiting the program

ClientBlockCipherObj = BlockCipher()
blockCipherSelected = "AES"  # Default block cipher
def write_key_to_file(key, filename):
    with open(filename, "wb") as file:
        file.write(key)

def connect_to_server():
    global blockCipherSelected, symmetric_key
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
        db.register(username, password)
        print("Signup successful. You can now login.")

    elif action == "login":
        if not db.is_account_exist(username):
            print("Account does not exist. Please signup first.")
            return

        password = getpass.getpass("Enter your password: ")
        hashed_password = hasher.calculate_md5(password)
        stored_password = db.get_password(username)
        if hashed_password != stored_password:
            print("Invalid credentials. Please try again.")
            return
        print("Login successful.")

    else:
        print("Invalid action. Please type 'login' or 'signup'.")
        return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(("127.0.0.1", 5560))

        client_socket.send(username.encode())  # Send username
        PreConfig = client_socket.recv(1024).decode()
        blockCipherSelected = PreConfig.split(":")[0]
        print(f"Connected using {blockCipherSelected}")

        # Generate a symmetric key based on the selected block cipher
        symmetric_key = get_random_bytes(16 if blockCipherSelected == "AES" else 8)
        write_key_to_file(symmetric_key, "symmetric.key")

        # Start receiving and sending threads
        threading.Thread(target=receive_message, args=(client_socket,)).start()
        send_message(client_socket, username)
    except KeyboardInterrupt:
        print("\nExiting... Goodbye!")
        client_socket.close()
        sys.exit()
    except Exception as e:
        print(f"Connection error: {e}")
        client_socket.close()


def send_message(client_socket, username):
    global symmetric_key
    try:
        while True:
            message = input(f"{username}: ")
            if message.lower() == "q":  # Check if the user wants to quit
                print("Exiting chat...")
                client_socket.close()
                sys.exit()

            plaintext = f"{username}: {message}".encode("utf-8")

            # Read symmetric key from file
            with open("symmetric.key", "rb") as file:
                symmetric_key1 = file.read()

            # Encrypt message based on block cipher selection
            if blockCipherSelected == "AES":
                encrypted_data = ClientBlockCipherObj.encrypt_AES_EAX(plaintext, symmetric_key1)
            else:
                encrypted_data = ClientBlockCipherObj.encrypt_DES_EAX(plaintext, symmetric_key1)

            client_socket.sendall(pickle.dumps(encrypted_data))
            print("Message sent!")
    except KeyboardInterrupt:
        print("\nExiting... Goodbye!")
        client_socket.close()
        sys.exit()


def receive_message(client_socket):
    try:
        while True:
            data = pickle.loads(client_socket.recv(4096))  # Deserialize data
            ciphertext, tag, nonce = data

            # Read symmetric key from file
            with open("symmetric.key", "rb") as file:
                symmetric_key1 = file.read()

            # Decrypt based on block cipher selection
            if blockCipherSelected == "AES":
                plaintext = ClientBlockCipherObj.decrypt_AES_EAX(ciphertext, symmetric_key1, nonce, tag)
            else:
                plaintext = ClientBlockCipherObj.decrypt_DES_EAX(ciphertext, symmetric_key1, nonce, tag)

            print(f"\nReceived: {plaintext.decode('utf-8')}")
    except Exception as e:
        print(f"Error receiving message: {e}")
        client_socket.close()


if __name__ == "__main__":
    connect_to_server()
