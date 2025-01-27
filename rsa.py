import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    encrypted = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Encode the bytes in base64 to safely transmit over text-based protocols
    return base64.b64encode(encrypted).decode('utf-8')


def rsa_decrypt(private_key, ciphertext):
    # Decode the base64 encoded ciphertext back to bytes
    ciphertext_bytes = base64.b64decode(ciphertext)

    # Decrypt the ciphertext using RSA private key
    decrypted = private_key.decrypt(
        ciphertext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')  # Decode the decrypted bytes to string