# Cryptographic utilities: SHA256 key derivation and AES/CBC encryption
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def derive_aes_key(shared_secret):
    """Derive AES IV and key from shared secret using SHA256."""
    Sx, Sy = shared_secret

    # Hash Sx then Sy
    h = hashlib.sha256(str(Sx).encode())
    h = hashlib.sha256(str(Sy).encode())
    hashed = h.hexdigest()  # 64 hex characters

    # IV = first 16 chars, Key = last 16 chars
    iv = hashed[:16].encode()
    key = hashed[-16:].encode()

    return iv, key


def aes_encrypt(plaintext, iv, key):
    """Encrypt plaintext using AES/CBC with PKCS7 padding."""
    # Apply PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8'))
    padded_data += padder.finalize()

    # Encrypt with AES/CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext.hex()


def aes_decrypt(ciphertext_hex, iv, key):
    """Decrypt ciphertext using AES/CBC and remove PKCS7 padding."""
    ciphertext = bytes.fromhex(ciphertext_hex)

    # Decrypt with AES/CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data)
    plaintext += unpadder.finalize()

    return plaintext.decode('utf-8')
