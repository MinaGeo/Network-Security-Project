from Crypto.PublicKey import RSA


class AsymmetricCipher:
    def __init__(self):
        pass

    def generate_RSA_key(self):
        key = RSA.generate(2048)
        return key

    def encrypt_RSA(self, data, key):
        cipher = key.publickey().encrypt(data, 32)
        return cipher

    def decrypt_RSA(self, cipher, key):
        data = key.decrypt(cipher)
        return data

    def sign_RSA(self, data, key):
        signature = key.sign(data, 32)
        return signature

    def verify_RSA(self, data, signature, key):
        return key.verify(data, signature)
