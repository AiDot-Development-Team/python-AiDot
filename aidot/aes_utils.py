from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import json
from typing import Any, Optional


def aes_encrypt(plaintext, key):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext


def aes_decrypt(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

    return plaintext.decode()


def aes_decrypt_to_json(
    ciphertext: bytes, key: Optional[bytes] = None
) -> dict[str, Any]:
    """Decrypt AES encrypted data and parse to JSON.

    Args:
        ciphertext: AES encrypted data
        key: AES key (optional, if None, assumes data is already decrypted)

    Returns:
        Parsed JSON dict
    """
    if key:
        decrypted_data = aes_decrypt(ciphertext, key)
    else:
        decrypted_data = (
            ciphertext.decode() if isinstance(ciphertext, bytes) else ciphertext
        )
    return json.loads(decrypted_data)
