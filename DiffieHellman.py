from Crypto.Random import random
from Crypto.Hash import SHA256


class DiffieHellman:
    def __init__(self):
        # Prime and base values for Diffie-Hellman (2048-bit safe prime recommended)
        self.prime = int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
            "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
            "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
            "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
            "49286651ECE65381FFFFFFFFFFFFFFFF",
            16,
        )  # This is a commonly used safe prime
        self.base = 2  

    def generate_private_key(self):

        return random.randint(2, self.prime - 2)

    def generate_public_key(self, private_key):

        return pow(self.base, private_key, self.prime)

    def compute_shared_secret(self, private_key, other_public_key):

        shared_secret = pow(other_public_key, private_key, self.prime)
        return shared_secret

    def generate_symmetric_key(self, shared_secret):

        shared_secret_bytes = str(shared_secret).encode()  # Convert to bytes
        symmetric_key = SHA256.new(shared_secret_bytes).digest()  # Hash the secret
        return symmetric_key
