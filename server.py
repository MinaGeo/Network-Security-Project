import socket
import threading
import pickle  # For serialization
from cryptography.hazmat.primitives import serialization
from pem import *
from clieditor import *

clients = []
public_keys = {}
stop_server_event = threading.Event()
symmetric_key = None
client_ready_event = threading.Event()


def handle_client(client_socket, client_address):
    data = client_socket.recv(1024).decode('utf-8')
    CipherMode, username = data.split(',', 1)  # Split the data into CipherMode and username
    green_message(f"User {username} connected! with {CipherMode} mode.")

    # Receive public key from client
    client_public_key_pem = client_socket.recv(2048)
    if not client_public_key_pem:
        red_message(f"Failed to receive public key from {username}")
        return

    if CipherMode == "RSA":
        client_public_key = serialization.load_pem_public_key(client_public_key_pem)
    else:
        client_public_key = pem_to_int(client_public_key_pem)
    public_keys[username] = client_public_key

    green_message(f"Public key of {username} received and saved.")

    # If this is the first client (Client 1), wait until the second client connects
    if len(public_keys) == 1:
        blue_message(f"{username} is the first client.")
        client_ready_event.wait()  # Block until Client 2 connects
        green_message(f"{username} can proceed now.")

    # Once both clients are connected, send each other's public key to the other client
    if len(public_keys) == 2:
        # Get the other client's public key
        notify_second_client_connected()
        other_username = next(user for user in public_keys if user != username)
        other_client_public_key = public_keys[other_username]

        if CipherMode == "RSA":
            # Serialize the other client's public key
            other_client_public_key_pem = other_client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            other_client_public_key_pem = int_to_pem(other_client_public_key, "INTEGER")
        # Send the other client's public key to the current client
        try:
            blue_message(f"Sending public key of {other_username} to {username}")
            client_socket.sendall(other_client_public_key_pem)
            green_message(f"Public key of {other_username} sent to {username}")
        except Exception as e:
            red_message(f"Error sending public key to {username}: {e}")

    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break  # No data, disconnecting

            # Check for exit message
            message = pickle.loads(data)
            if "exit" in message and message["exit"]:
                username = message["username"]
                print(f"{username} has left the chat.")
                clients.remove(client_socket)  # Remove client from the list
                public_keys.pop(username)  # Remove public key from the dictionary
                client_socket.close()
                break

            encrypted_data = message
            broadcast(encrypted_data, client_socket)

        except Exception as e:
            red_message(f"Error with {username}: {e}")
            break


# When the second client connects, set the event to allow Client 1 to proceed
def notify_second_client_connected():
    blue_message("Second client connected, notifying Client 1...")
    client_ready_event.set()


def broadcast(message, client_socket):
    for client in clients:
        try:
            if client != client_socket:
                client.sendall(pickle.dumps(message))
        except Exception as e:
            red_message(f"Broadcast Error: {e}")
            clients.remove(client)


def main():
    host = '127.0.0.1'
    port = 5560

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    blue_message(f"Server listening on {host}:{port}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            clients.append(client_socket)
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
    except KeyboardInterrupt:
        red_message("Server shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
