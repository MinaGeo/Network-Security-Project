import socket
import threading
from BlockCipher import BlockCipher
import pickle

class Server:
    def __init__(self, host='127.0.0.1', port=5560):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.block_cipher = BlockCipher()
        self.clients = []

    def handle_client(self, client_socket):
        try:
            # Exchange public keys
            client_socket.send(str(self.block_cipher.public_key).encode('utf-8'))
            client_public_key = int(client_socket.recv(1024).decode('utf-8'))

            while True:
                # Receive encrypted data
                data = client_socket.recv(4096)
                if not data:
                    break

                # Extract ciphertext, tag, and nonce
                ciphertext, tag, nonce = pickle.loads(data)

                # Decrypt message
                plaintext = self.block_cipher.decrypt_AES_EAX(ciphertext, client_public_key, nonce, tag)
                print(f"Received: {plaintext.decode('utf-8')}")

                # Broadcast the message to all clients
                self.broadcast(plaintext, client_socket, client_public_key)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()

    def broadcast(self, message, sender_socket, sender_public_key):
        for client in self.clients:
            if client != sender_socket:
                try:
                    # Encrypt message
                    ciphertext, tag, nonce = self.block_cipher.encrypt_AES_EAX(message, sender_public_key)
                    client.send(pickle.dumps((ciphertext, tag, nonce)))
                except Exception as e:
                    print(f"Broadcast Error: {e}")
                    self.clients.remove(client)

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Server listening on {self.host}:{self.port}")

        try:
            while True:
                client_socket, _ = self.server_socket.accept()
                self.clients.append(client_socket)
                threading.Thread(target=self.handle_client, args=(client_socket,)).start()
        except KeyboardInterrupt:
            print("Shutting down server...")
        finally:
            self.server_socket.close()


if __name__ == "__main__":
    server = Server()
    server.start()
