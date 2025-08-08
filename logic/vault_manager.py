# ==============================================================================
# File: vault_manager.py
# Location: FileEncrypter/logic/
# Description: Manages the key vault, including creation, storage,
#              and retrieval of RSA key pairs.
# ==============================================================================

import os
import json
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from config import (VAULT_FILE, KEYS_DIR, APP_DATA_DIR, RSA_KEY_SIZE,
                    RSA_PUBLIC_EXPONENT, PUBLIC_KEY_EXT, PRIVATE_KEY_EXT)

def ensure_app_data_dir():
    """Creates the application data and keys directories if they don't exist."""
    os.makedirs(KEYS_DIR, exist_ok=True)

def _load_vault():
    """Loads the vault data from the JSON file."""
    if not os.path.exists(VAULT_FILE):
        return {}
    try:
        with open(VAULT_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}

def _save_vault(data):
    """Saves the vault data to the JSON file."""
    with open(VAULT_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def get_all_key_names():
    """Returns a sorted list of all key names in the vault."""
    vault = _load_vault()
    return sorted(list(vault.keys()))

def create_key_pair(name: str, password: str, description: str = "") -> dict:
    """Generates, saves, and registers a new RSA key pair in the vault."""
    vault = _load_vault()
    if name in vault:
        return {"success": False, "error": f"A key pair with the name '{name}' already exists."}

    try:
        # Generate the RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=RSA_KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Define strong encryption for the private key file
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode('utf-8'))

        # Serialize the keys into PEM format
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Save key files to the dedicated keys directory
        private_key_path = os.path.join(KEYS_DIR, name + PRIVATE_KEY_EXT)
        public_key_path = os.path.join(KEYS_DIR, name + PUBLIC_KEY_EXT)
        with open(private_key_path, "wb") as f:
            f.write(pem_private)
        with open(public_key_path, "wb") as f:
            f.write(pem_public)

        # Add metadata to the vault JSON file
        vault[name] = {
            "public_key_path": public_key_path,
            "private_key_path": private_key_path,
            "description": description,
            "created_on": datetime.now().isoformat()
        }
        _save_vault(vault)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}

def get_public_key(name: str):
    """Loads a public key object from a file specified in the vault."""
    vault = _load_vault()
    meta = vault.get(name)
    if not meta: return None
    try:
        with open(meta["public_key_path"], 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())
    except (FileNotFoundError, KeyError, ValueError):
        return None

def get_private_key(name: str, password: str):
    """Loads a private key object from a file, decrypting it with the password."""
    vault = _load_vault()
    meta = vault.get(name)
    if not meta: return None
    try:
        with open(meta["private_key_path"], 'rb') as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=password.encode('utf-8'),
                backend=default_backend()
            )
    except (FileNotFoundError, KeyError, ValueError, TypeError):
        # ValueError/TypeError can be raised for an incorrect password
        return None
