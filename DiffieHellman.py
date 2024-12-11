from Crypto.PublicKey import DSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

class DiffieHellman:
    def __init__(self):
        # Prime and base values for Diffie-Hellman (safe primes for cryptographic strength)
        self.prime = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        self.base = 2

    def generate_private_key(self):
        return get_random_bytes(256)

    def generate_public_key(self, private_key):
        return pow(self.base, int.from_bytes(private_key, 'big'), self.prime)

    def compute_shared_secret(self, private_key, other_public_key):
        return pow(int.from_bytes(other_public_key, 'big'), int.from_bytes(private_key, 'big'), self.prime)

    def generate_symmetric_key(self, shared_secret):
        shared_secret_int = int.from_bytes(shared_secret, 'big')
        # Hash the shared secret to create a fixed-length key 
        symmetric_key = SHA256.new(str(shared_secret_int).encode()).digest()
        return symmetric_key
