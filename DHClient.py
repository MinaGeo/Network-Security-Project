import socket
import pickle
from BlockCipher import BlockCipher
import threading

class Client:
    def __init__(self, host='127.0.0.1', port=5560):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.block_cipher = BlockCipher()

    def start(self):
        self.client_socket.connect((self.host, self.port))

        # Exchange public keys
        server_public_key = int(self.client_socket.recv(1024).decode('utf-8'))
        self.client_socket.send(str(self.block_cipher.public_key).encode('utf-8'))

        # Start receiving messages in a separate thread
        threading.Thread(target=self.receive_messages, daemon=True).start()

        # Send messages
        try:
            while True:
                message = input("Enter message: ").encode('utf-8')
                ciphertext, tag, nonce = self.block_cipher.encrypt_AES_EAX(message, server_public_key)
                self.client_socket.send(pickle.dumps((ciphertext, tag, nonce)))
        except KeyboardInterrupt:
            print("Closing connection...")
        finally:
            self.client_socket.close()

    def receive_messages(self):
        try:
            while True:
                data = self.client_socket.recv(4096)
                if not data:
                    break

                # Extract ciphertext, tag, and nonce
                ciphertext, tag, nonce = pickle.loads(data)

                # Decrypt message
                plaintext = self.block_cipher.decrypt_AES_EAX(ciphertext, int(self.client_socket.getpeername()[1]), nonce, tag)
                print(f"Message from server: {plaintext.decode('utf-8')}")
        except Exception as e:
            print(f"Error receiving message: {e}")


if __name__ == "__main__":
    client = Client()
    client.start()
