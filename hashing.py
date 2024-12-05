import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
class MD5:
    def __init__(self):
        pass
    def calculate_md5(self,data):
        md5_hash = hashlib.md5()
        md5_hash.update(data.encode("utf-8"))  # Encode the string as bytes before updating the hash
        return md5_hash.hexdigest()

class SHA_256:
    def hash_data(self,data):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data.encode("utf-8"))
        return digest.finalize()


