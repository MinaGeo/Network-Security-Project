from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from DiffieHellman import DiffieHellman
####
class BlockCipher:
    def __init__(self):
        self.diffie_hellman = DiffieHellman()
        self.private_key = self.diffie_hellman.generate_private_key()
        self.public_key = self.diffie_hellman.generate_public_key(self.private_key)

    # AES Encryption
    def encrypt_AES_EAX(self, data, other_public_key):
        shared_secret = self.diffie_hellman.compute_shared_secret(self.private_key, other_public_key)
        symmetric_key = self.diffie_hellman.generate_symmetric_key(shared_secret)
        
        if len(symmetric_key) not in [16, 24, 32]:
            raise ValueError("AES key must be 16, 24, or 32 bytes.")
        cipher = AES.new(symmetric_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, tag, cipher.nonce

    def decrypt_AES_EAX(self, ciphertext, other_public_key, nonce, tag):
        shared_secret = self.diffie_hellman.compute_shared_secret(self.private_key, other_public_key)
        symmetric_key = self.diffie_hellman.generate_symmetric_key(shared_secret)
        
        cipher = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext

    # DES Encryption
    def encrypt_DES_EAX(self, data, other_public_key):
        shared_secret = self.diffie_hellman.compute_shared_secret(self.private_key, other_public_key)
        symmetric_key = self.diffie_hellman.generate_symmetric_key(shared_secret)
        
        if len(symmetric_key) != 8:
            raise ValueError("DES key must be 8 bytes.")
        cipher = DES.new(symmetric_key, DES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(pad(data, DES.block_size))
        return ciphertext, tag, cipher.nonce

    def decrypt_DES_EAX(self, ciphertext, other_public_key, nonce, tag):
        shared_secret = self.diffie_hellman.compute_shared_secret(self.private_key, other_public_key)
        symmetric_key = self.diffie_hellman.generate_symmetric_key(shared_secret)
        
        cipher = DES.new(symmetric_key, DES.MODE_EAX, nonce=nonce)
        plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), DES.block_size)
        return plaintext
    
    
