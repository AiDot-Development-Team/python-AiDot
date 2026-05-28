"""Crypto utilities for AiDot."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import json
from typing import Any, Optional
import base64


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt data using AES ECB mode.

    Args:
        plaintext: Data to encrypt
        key: AES key (16, 24, or 32 bytes)

    Returns:
        Encrypted data
    """
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> str:
    """Decrypt data using AES ECB mode.

    Args:
        ciphertext: Encrypted data
        key: AES key (16, 24, or 32 bytes)

    Returns:
        Decrypted string
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

    return plaintext.decode()


def aes_decrypt_to_json(ciphertext: bytes, key: Optional[bytes] = None) -> dict[str, Any]:
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
        decrypted_data = ciphertext.decode() if isinstance(ciphertext, bytes) else ciphertext
    return json.loads(decrypted_data)


def rsa_encrypt(message: str, public_key: str) -> str:
    """Encrypt message using RSA public key.

    Args:
        message: Message to encrypt
        public_key: PEM format public key

    Returns:
        Base64 encoded encrypted message
    """
    public_key_serialization = serialization.load_pem_public_key(
        public_key.encode() if isinstance(public_key, str) else public_key,
        backend=default_backend()
    )

    encrypted = public_key_serialization.encrypt(
        message.encode("utf-8"),
        asym_padding.PKCS1v15(),
    )

    encrypted_base64 = base64.b64encode(encrypted).decode("utf-8")
    return encrypted_base64
