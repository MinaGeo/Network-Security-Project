# Main code
from Crypto.Random import get_random_bytes
from BlockCipher import BlockCipher  # Ensure this matches your file structure

# Create an instance of BlockCipher
cipher = BlockCipher()

# Define key and plaintext
key = get_random_bytes(16)  # AES-128 key
plaintext = "Welson".encode()  # Encode string to bytes

# Encrypt the plaintext
ciphertext, tag, nonce = cipher.encrypt_AES_EAX(plaintext, key)

# Output the ciphertext
print("Ciphertext:", ciphertext)

# Decrypt the ciphertext to verify
decrypted_text = cipher.decrypt_AES_EAX(ciphertext, key, nonce, tag)
print("Decrypted Text:", decrypted_text.decode())  # Decode back to string
