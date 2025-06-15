# encryption_utils.py
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

def derive_key(password, salt):
    """Derives a key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=salt,
        iterations=100000,  # Increased iterations for better security
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_vault_key(vault_key_bytes, mpdk_bytes):
    """Encrypts the Vault Key using the Master Password Derived Key."""
    iv = os.urandom(16)  # AES block size
    cipher = Cipher(algorithms.AES(mpdk_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS7 padding for the 32-byte vault key
    pad_len = 16 - (len(vault_key_bytes) % 16)
    padded_vault_key = vault_key_bytes + bytes([pad_len]) * pad_len

    encrypted_vk = encryptor.update(padded_vault_key) + encryptor.finalize()

    return {
        'ciphertext': base64.b64encode(encrypted_vk).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8')
    }

def decrypt_vault_key(encrypted_vk_b64, iv_b64, mpdk_bytes):
    """Decrypts the Vault Key using the Master Password Derived Key."""
    encrypted_vk = base64.b64decode(encrypted_vk_b64)
    iv = base64.b64decode(iv_b64)

    cipher = Cipher(algorithms.AES(mpdk_bytes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_vault_key = decryptor.update(encrypted_vk) + decryptor.finalize()

    # Remove PKCS7 padding
    pad_len = padded_vault_key[-1]
    vault_key_bytes = padded_vault_key[:-pad_len]
    return vault_key_bytes

def encrypt_entry(plaintext_password, vault_key):
    """Encrypts a password entry using the Vault Key."""
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(vault_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS7 padding
    pad_len = 16 - (len(plaintext_password.encode('utf-8')) % 16)
    padded_data = plaintext_password.encode('utf-8') + bytes([pad_len]) * pad_len

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8')
    }

def decrypt_entry(ciphertext_b64, salt_b64, iv_b64, vault_key):
    """Decrypts a password entry using the Vault Key."""
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)

        cipher = Cipher(algorithms.AES(vault_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        pad_len = padded_data[-1]
        plaintext = padded_data[:-pad_len]

        return plaintext.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        raise