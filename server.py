import socket
import threading
import pickle  # For serialization

from BlockCipher import BlockCipher

# List to store connected clients
clients = []
# Global variables for block cipher and encryption method
blockCipherSelected = "AES"
encryptionSelected = "ECC"
connected_clients = 0
# Event to signal the server to stop
stop_server_event = threading.Event()
# Data storage for each client
client_data = []
PUBLICKEYEXECHANGED = 0
ClientBlockCipherObj = BlockCipher()
symmetric_key = None


def PublicKeyExechange(decoded_client_public_key):
    global client_data, clients, PUBLICKEYEXECHANGED
    print(f"Connected clients: {clients}")
    for client in clients:
        try:
            client.send("PK".encode())
            ack = client.recv(1024).decode('utf-8')

            if ack == "ACK":
                if len(clients) > 1:
                    myIndex = clients.index(client)
                    if myIndex == 0:
                        client.send(client_data[1].encode("utf-8"))
                    else:
                        client.send(client_data[0].encode("utf-8"))
                else:
                    client.send(decoded_client_public_key.encode("utf-8"))
        except Exception as e:
            print(f"Broadcast Error: {e}")
            clients.remove(client)
    if len(clients) == 2:
        PUBLICKEYEXECHANGED = 1


def handle_client(client_socket, client_address):
    global blockCipherSelected, symmetric_key
    username = client_socket.recv(1024).decode('utf-8')  # Receive username
    client_socket.send(f"{blockCipherSelected}:NA".encode('utf-8'))
    print(f"User {username} connected!")

    # Receive the symmetric key from the client
    # symmetric_key = client_socket.recv(1024)  # Receive the symmetric key
    # print(f"Received symmetric key from {username}")

    while True:
        try:
            # Receive encrypted message from the client
            data = client_socket.recv(1024)
            if not data:
                break  # No data, disconnecting

            print(f"Received (serialized): {data}")

            # Deserialize the received data
            encrypted_data = pickle.loads(data)

            # Process the encrypted data (decrypt it based on block cipher selection)
            # if blockCipherSelected == "AES":
            #     ciphertext, tag, nonce = encrypted_data
            #     plaintext = ClientBlockCipherObj.decrypt_AES_EAX(ciphertext, symmetric_key, nonce, tag)
            # else:
            #     ciphertext, tag, nonce = encrypted_data
            #     plaintext = ClientBlockCipherObj.decrypt_DES_EAX(ciphertext, symmetric_key, nonce, tag)

            # print(f"encrypted_data: {encrypted_data}, plaintext: {plaintext}, ciphertext: {ciphertext}, tag: {tag}, nonce: {nonce}")
            # print(f"Decrypted message: {plaintext.decode('utf-8')}")
            broadcast(encrypted_data, client_socket)
        except Exception as e:
            print(f"Error with {username}: {e}")
            break


def broadcast(message, client_socket):
    global clients
    for client in clients:
        try:
            if client != client_socket:
                # Serialize the message before broadcasting
                client.sendall(pickle.dumps(message))
        except Exception as e:
            print(f"Broadcast Error: {e}")
            clients.remove(client)

def main():
    global blockCipherSelected, encryptionSelected
    host = '127.0.0.1'
    port = 5560

    # Prompt user for encryption settings
    # blockCipherSelected = input("Select Block Cipher Algorithm (AES/DES): ").strip().upper()
    # encryptionSelected = input("Select Crypto System Algorithm (ECC/AsymmetricCipher.py): ").strip().upper()

    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"Server listening on {host}:{port} ")

    try:
        while not stop_server_event.is_set():
            if len(clients) < 2:  # Limit the number of clients to 2
                client_socket, client_address = server_socket.accept()
                clients.append(client_socket)
                client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
                client_thread.start()
    except KeyboardInterrupt:
        print("Shutting down server...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
