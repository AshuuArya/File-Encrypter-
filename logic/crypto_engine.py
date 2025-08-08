# ==============================================================================
# File: crypto_engine.py
# Location: FileEncrypter/logic/
# Description: Handles all core cryptographic operations.
#              This file does not interact with the UI directly.
# ==============================================================================

import os
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from . import vault_manager
from config import (PBKDF2_ITERATIONS, SALT_SIZE, AES_KEY_SIZE,
                    GCM_NONCE_SIZE, ENCRYPTED_FILE_EXT, MAGIC_PW_HEADER,
                    MAGIC_KF_HEADER, MAGIC_HEADER_SIZE)

# --- Password-Based Encryption (Symmetric) ---

def _derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit AES key from a password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_file_with_password(file_path: str, password: str) -> dict:
    """
    Encrypts a file using AES-256-GCM derived from a password.
    The output file format is: [MAGIC_HEADER][SALT][NONCE][CIPHERTEXT+TAG]
    """
    try:
        salt = os.urandom(SALT_SIZE)
        aes_key = _derive_key_from_password(password, salt)
        nonce = os.urandom(GCM_NONCE_SIZE)
        cipher = aead.AESGCM(aes_key)
        
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        encrypted_data = cipher.encrypt(nonce, plaintext, None)

        output_path = file_path + ENCRYPTED_FILE_EXT
        with open(output_path, 'wb') as f:
            f.write(MAGIC_PW_HEADER)
            f.write(salt)
            f.write(nonce)
            f.write(encrypted_data)
            
        return {"success": True, "output_path": output_path}
    except Exception as e:
        return {"success": False, "error": f"Password encryption failed: {e}"}

def decrypt_file_with_password(file_path: str, password: str) -> dict:
    """Decrypts a file that was encrypted using the password-based method."""
    try:
        with open(file_path, 'rb') as f:
            # 1. Verify the file header to ensure correct decryption method
            header = f.read(MAGIC_HEADER_SIZE)
            if header != MAGIC_PW_HEADER:
                return {"success": False, "error": "Decryption failed: This file was not encrypted using the 'Password' method. Please try the 'Key Pair' method instead."}

            # 2. Read the components from the encrypted file
            salt = f.read(SALT_SIZE)
            nonce = f.read(GCM_NONCE_SIZE)
            encrypted_data = f.read()
            
        aes_key = _derive_key_from_password(password, salt)
        cipher = aead.AESGCM(aes_key)
        decrypted_data = cipher.decrypt(nonce, encrypted_data, None)
        
        output_path = file_path.rsplit(ENCRYPTED_FILE_EXT, 1)[0]
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
            
        return {"success": True, "output_path": output_path}
    except Exception as e:
        return {"success": False, "error": f"Decryption failed. Please check your password and file integrity. Details: {e}"}

# --- Key-Based (Asymmetric) Hybrid Encryption ---

def encrypt_file_with_key(file_path: str, key_name: str) -> dict:
    """
    Encrypts a file using a hybrid RSA+AES-GCM scheme.
    Output format: [MAGIC_HEADER][WRAPPED_KEY_LEN (2b)][WRAPPED_AES_KEY][NONCE][CIPHERTEXT+TAG]
    """
    try:
        public_key = vault_manager.get_public_key(key_name)
        if not public_key:
            return {"success": False, "error": f"Could not load public key for '{key_name}'. Ensure the key exists."}

        aes_key = aead.AESGCM.generate_key(bit_length=AES_KEY_SIZE * 8)
        nonce = os.urandom(GCM_NONCE_SIZE)

        wrapped_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = aead.AESGCM(aes_key)
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        encrypted_data = cipher.encrypt(nonce, plaintext, None)

        output_path = file_path + ENCRYPTED_FILE_EXT
        with open(output_path, 'wb') as f:
            f.write(MAGIC_KF_HEADER)
            f.write(len(wrapped_aes_key).to_bytes(2, 'big'))
            f.write(wrapped_aes_key)
            f.write(nonce)
            f.write(encrypted_data)

        return {"success": True, "output_path": output_path}
    except Exception as e:
        return {"success": False, "error": f"Key-based encryption failed: {e}"}

def decrypt_file_with_key(file_path: str, key_name: str, password: str) -> dict:
    """Decrypts a file encrypted with an RSA key pair."""
    try:
        private_key = vault_manager.get_private_key(key_name, password)
        if not private_key:
            return {"success": False, "error": f"Could not load private key for '{key_name}'. Please check your password."}

        with open(file_path, 'rb') as f:
            # 1. Verify the file header to ensure correct decryption method
            header = f.read(MAGIC_HEADER_SIZE)
            if header != MAGIC_KF_HEADER:
                return {"success": False, "error": "Decryption failed: This file was not encrypted using the 'Key Pair' method. Please try the 'Password' method instead."}

            # 2. Read the components from the encrypted file
            wrapped_key_len = int.from_bytes(f.read(2), 'big')
            wrapped_aes_key = f.read(wrapped_key_len)
            nonce = f.read(GCM_NONCE_SIZE)
            encrypted_data = f.read()

        aes_key = private_key.decrypt(
            wrapped_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = aead.AESGCM(aes_key)
        decrypted_data = cipher.decrypt(nonce, encrypted_data, None)

        output_path = file_path.rsplit(ENCRYPTED_FILE_EXT, 1)[0]
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        return {"success": True, "output_path": output_path}
    except Exception as e:
        return {"success": False, "error": f"Key-based decryption failed. Check key, password, or file integrity. Details: {e}"}
