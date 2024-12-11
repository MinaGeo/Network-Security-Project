from Crypto.Random import random
from Crypto.Hash import SHA256

prime = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE65381FFFFFFFFFFFFFFFF",
    16,
)  # This is a commonly used safe prime
base = 2


def generate_private_key():
    return random.randint(2, prime - 2)


def generate_public_key(private_key):
    return pow(base, private_key, prime)


def compute_shared_secret(private_key, other_public_key):
    shared_secret = pow(other_public_key, private_key, prime)
    return shared_secret


def generate_symmetric_key(shared_secret):
    shared_secret_bytes = str(shared_secret).encode()  # Convert to bytes
    symmetric_key = SHA256.new(shared_secret_bytes).digest()  # Hash the secret
    return symmetric_key
