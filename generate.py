# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import serialization
#
# def generate_rsa_keys():
#     # Generate RSA private key
#     private_key = rsa.generate_private_key(
#         public_exponent=65537,
#         key_size=2048
#     )
#
#     # Generate RSA public key
#     public_key = private_key.public_key()
#
#     return private_key, public_key
#     # # Save the private key to a file
#     # with open('private.pem', 'wb') as private_key_file:
#     #     private_key_file.write(private_key.private_bytes(
#     #         encoding=serialization.Encoding.PEM,
#     #         format=serialization.PrivateFormat.TraditionalOpenSSL,
#     #         encryption_algorithm=serialization.NoEncryption()
#     #     ))
#     #
#     # # Save the public key to a file
#     # with open('public.pem', 'wb') as public_key_file:
#     #     public_key_file.write(public_key.public_bytes(
#     #         encoding=serialization.Encoding.PEM,
#     #         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     #     ))
#
#     # print("RSA keys generated and saved as 'private.pem' and 'public.pem'.")
#
# # Run the function to generate keys
# generate_rsa_keys()
