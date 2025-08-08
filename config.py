# ==============================================================================
# File: config.py
# Location: FileEncrypter/
# Description: Central configuration file for the application.
# ==============================================================================

import os

# --- Application Info ---
APP_NAME = "FileEncrypter"
APP_VERSION = "1.0.0"

# --- Directory and File Paths ---
# Use os.path.expanduser('~') to get the user's home directory.
# This is a robust way to store app data across different systems.
# The folder will be hidden on Linux/macOS (e.g., ".fileencrypter")
APP_DATA_DIR = os.path.join(os.path.expanduser('~'), f".{APP_NAME.lower()}")
KEYS_DIR = os.path.join(APP_DATA_DIR, "keys")
VAULT_FILE = os.path.join(APP_DATA_DIR, "vault.json")

# --- Cryptographic Constants ---
RSA_KEY_SIZE = 4096
RSA_PUBLIC_EXPONENT = 65537
# NIST recommendation for PBKDF2 with HMAC-SHA256 is at least 100,000, we use more.
PBKDF2_ITERATIONS = 600000
SALT_SIZE = 16 # bytes
AES_KEY_SIZE = 32 # 256-bit AES
GCM_NONCE_SIZE = 12 # bytes (96 bits) - recommended for AES-GCM
GCM_TAG_SIZE = 16 # bytes (128 bits) - standard for AES-GCM

# --- File Format Headers (Magic Numbers) ---
# These headers identify the encryption method used for a file.
MAGIC_PW_HEADER = b'PWFORT' # Password Fortress
MAGIC_KF_HEADER = b'KFFORT' # KeyFile Fortress
MAGIC_HEADER_SIZE = 6

# --- File Extensions ---
ENCRYPTED_FILE_EXT = ".encrypted"
SIGNATURE_FILE_EXT = ".sig"
PUBLIC_KEY_EXT = "_public.pem"
PRIVATE_KEY_EXT = "_private.pem"
