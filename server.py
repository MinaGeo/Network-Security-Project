import socket
import threading
import pickle  # For serialization
from BlockCipher import BlockCipher
from cryptography.hazmat.primitives import serialization

clients = []
public_keys = {}
CipherSelected = "RSA"
encryptionSelected = "ECC"
connected_clients = 0
stop_server_event = threading.Event()
client_data = []
PUBLICKEYEXECHANGED = 0
ClientBlockCipherObj = BlockCipher()
symmetric_key = None
client_ready_event = threading.Event()
def read_key_from_file(filename):
    with open(filename, "rb") as file:
        key = file.read()  # Read the binary data from the file
    return key.decode('utf-8')  # Return the key as a string (utf-8 encoding)


def handle_client(client_socket, client_address):
    username = client_socket.recv(1024).decode('utf-8')
    client_socket.send(f"{CipherSelected}:NA".encode('utf-8'))
    print(f"User {username} connected!")

    # Receive public key from client
    client_public_key_pem = client_socket.recv(2048)
    if not client_public_key_pem:
        print(f"Failed to receive public key from {username}")
        return
    client_public_key = serialization.load_pem_public_key(client_public_key_pem)
    public_keys[username] = client_public_key

    print(f"Public key of {username} received and saved.")

    # If this is the first client (Client 1), wait until the second client connects
    if len(public_keys) == 1:
        print(f"{username} is waiting for the second client to connect...")
        client_ready_event.wait()  # Block until Client 2 connects
        print(f"{username} can proceed now.")

    # Once both clients are connected, send each other's public key to the other client
    if len(public_keys) == 2:
        # Get the other client's public key
        notify_second_client_connected()
        other_username = next(user for user in public_keys if user != username)
        other_client_public_key = public_keys[other_username]

        # Serialize the other client's public key
        other_client_public_key_pem = other_client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Send the other client's public key to the current client
        try:
            print(f"Sending public key of {other_username} to {username}")
            client_socket.sendall(other_client_public_key_pem)
            print(f"Public key of {other_username} sent to {username}")
        except Exception as e:
            print(f"Error sending public key to {username}: {e}")

    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break  # No data, disconnecting

            encrypted_data = pickle.loads(data)
            plaintext = encrypted_data
            broadcast(plaintext, client_socket)
        except Exception as e:
            print(f"Error with {username}: {e}")
            break

# When the second client connects, set the event to allow Client 1 to proceed
def notify_second_client_connected():
    print("Second client connected, notifying Client 1...")
    client_ready_event.set()

def broadcast(message, client_socket):
    for client in clients:
        try:
            if client != client_socket:
                client.sendall(pickle.dumps(message))
        except Exception as e:
            print(f"Broadcast Error: {e}")
            clients.remove(client)

def main():
    global CipherSelected
    host = '127.0.0.1'
    port = 5560

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"Server listening on {host}:{port} ")

    try:
        while True:
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