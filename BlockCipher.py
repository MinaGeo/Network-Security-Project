from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class BlockCipher:
    def __init__(self):
        pass

    # AES Encryption
    def encrypt_AES_EAX(self, data, key):
        if len(key) not in [16, 24, 32]:
            raise ValueError("AES key must be 16, 24, or 32 bytes.")
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, tag, cipher.nonce

    def decrypt_AES_EAX(self, ciphertext, key, nonce, tag):
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext

    # DES Encryption
    def encrypt_DES_EAX(self, data, key):
        if len(key) != 8:
            raise ValueError("DES key must be 8 bytes.")
        cipher = DES.new(key, DES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(pad(data, DES.block_size))
        return ciphertext, tag, cipher.nonce

    def decrypt_DES_EAX(self, ciphertext, key, nonce, tag):
        cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
        plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), DES.block_size)
        return plaintext
