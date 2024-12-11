from base64 import b64encode, b64decode


def int_to_pem(integer: int, label: str = "INTEGER") -> bytes:
    """
    Serialize an integer into a PEM-like format.

    Args:
        integer (int): The integer to serialize.
        label (str): The label for the PEM block (default is "INTEGER").

    Returns:
        bytes: The PEM-like byte representation of the integer.
    """
    # Convert integer to bytes (big-endian representation)
    integer_bytes = integer.to_bytes((integer.bit_length() + 7) // 8, byteorder='big')

    # Base64 encode the bytes
    base64_encoded = b64encode(integer_bytes).decode('utf-8')

    # Format as a PEM block
    pem = f"-----BEGIN {label}-----\n"
    for i in range(0, len(base64_encoded), 64):  # Wrap lines at 64 characters
        pem += base64_encoded[i:i + 64] + "\n"
    pem += f"-----END {label}-----\n"

    return pem.encode('utf-8')


def pem_to_int(pem: bytes) -> int:
    """
    Deserialize a PEM-like formatted byte string into an integer.

    Args:
        pem (bytes): The PEM-like formatted byte string.

    Returns:
        int: The deserialized integer.
    """
    # Decode the PEM block to extract the base64-encoded data
    pem_str = pem.decode('utf-8')
    base64_encoded = ''.join(
        line for line in pem_str.splitlines()
        if not line.startswith("-----")
    )
    integer_bytes = b64decode(base64_encoded)

    # Convert bytes back to an integer
    return int.from_bytes(integer_bytes, byteorder='big')
