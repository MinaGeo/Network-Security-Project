import socket
import threading
import pickle  # For serialization
from Crypto.Random import get_random_bytes
from BlockCipher import BlockCipher

ClientBlockCipherObj = BlockCipher()
blockCipherSelected = "AES"  # Default block cipher
def write_key_to_file(key, filename):
    with open(filename, "wb") as file:
        file.write(key)

def connect_to_server():
    global blockCipherSelected, symmetric_key
    username = input("Enter your username: ").strip()
    if not username:
        print("Error: Username cannot be empty.")
        return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 5560))

    client_socket.send(username.encode())  # Send username
    PreConfig = client_socket.recv(1024).decode()
    blockCipherSelected = PreConfig.split(":")[0]
    print(f"Connected using {blockCipherSelected}")

    # Generate a symmetric key based on the selected block cipher
    symmetric_key = get_random_bytes(16 if blockCipherSelected == "AES" else 8)
    write_key_to_file(symmetric_key, "symmetric.key")

    # Send the symmetric key to the server
    # client_socket.send(symmetric_key)  # Send the symmetric key to the server

    # Start receiving and sending threads
    threading.Thread(target=receive_message, args=(client_socket,)).start()
    send_message(client_socket, username)


def send_message(client_socket, username):
    global symmetric_key
    while True:
        message = input(f"{username}: ")
        if message.lower() == "exit":
            client_socket.close()
            break

        plaintext = f"{username}: {message}".encode("utf-8")
        #read symmetric key from file
        with open("symmetric.key", "rb") as file:
            symmetric_key1 = file.read()

        # Encrypt message based on block cipher selection
        if blockCipherSelected == "AES":
            encrypted_data = ClientBlockCipherObj.encrypt_AES_EAX(plaintext, symmetric_key1)
        else:
            encrypted_data = ClientBlockCipherObj.encrypt_DES_EAX(plaintext, symmetric_key1)

        client_socket.sendall(pickle.dumps(encrypted_data))
        print("Message sent!")


def receive_message(client_socket):
    while True:
        try:
            data = pickle.loads(client_socket.recv(4096))  # Deserialize data
            ciphertext, tag, nonce = data

            #read symmetric key from file
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
            break


if __name__ == "__main__":
    connect_to_server()
