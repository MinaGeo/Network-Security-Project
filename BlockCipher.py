from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from DiffieHellman import *
####
class BlockCipher:
    def __init__(self, private_key, symmetric_key):
        self.private_key = private_key
        self.symmetric_key = symmetric_key

    def encrypt_AES_EAX(self, data, other_public_key):
        shared_secret = compute_shared_secret(self.private_key, other_public_key)
        symmetric_key = generate_symmetric_key(shared_secret, cipher_type="AES")

        cipher = AES.new(symmetric_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(pad(data, AES.block_size))
        return ciphertext, tag, cipher.nonce

    def decrypt_AES_EAX(self, ciphertext, other_public_key, nonce, tag):
        shared_secret = compute_shared_secret(self.private_key, other_public_key)
        symmetric_key = generate_symmetric_key(shared_secret, cipher_type="AES")

        cipher = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
        plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
        return plaintext

    def encrypt_DES_EAX(self, data, other_public_key):
        shared_secret = compute_shared_secret(self.private_key, other_public_key)
        symmetric_key = generate_symmetric_key(shared_secret, cipher_type="DES")

        cipher = DES.new(symmetric_key, DES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(pad(data, DES.block_size))
        return ciphertext, tag, cipher.nonce

    def decrypt_DES_EAX(self, ciphertext, other_public_key, nonce, tag):
        shared_secret = compute_shared_secret(self.private_key, other_public_key)
        symmetric_key = generate_symmetric_key(shared_secret, cipher_type="DES")

        cipher = DES.new(symmetric_key, DES.MODE_EAX, nonce=nonce)
        plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), DES.block_size)
        return plaintext

