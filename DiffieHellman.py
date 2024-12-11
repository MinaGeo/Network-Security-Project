from Crypto.PublicKey import DSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import random

class DiffieHellman:
    def __init__(self):
        # Using a simple prime and base for simplicity
        # These should ideally be large primes
        self.prime = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        self.base = 2

    def generate_private_key(self):
        # Generate private key using a cryptographically secure random number
        return int.from_bytes(get_random_bytes(256), byteorder='big') % (self.prime - 2) + 2

    def generate_public_key(self, private_key):
        # Compute public key: public_key = base^private_key % prime
        return pow(self.base, private_key, self.prime)

    def compute_shared_secret(self, private_key, other_public_key):
        # Compute shared secret: shared_secret = other_public_key^private_key % prime
        return pow(other_public_key, private_key, self.prime)

    def generate_symmetric_key(self, shared_secret):
        # Derive symmetric key from shared secret (using SHA256)
        shared_secret_bytes = str(shared_secret).encode()
        symmetric_key = SHA256.new(shared_secret_bytes).digest()
        return symmetric_key
