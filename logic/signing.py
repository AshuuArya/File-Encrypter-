# ==============================================================================
# File: signing.py
# Location: FileEncrypter/logic/
# Description: Handles file signing and verification. (Not used in UI but kept for completeness)
# ==============================================================================

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from . import vault_manager
from config import SIGNATURE_FILE_EXT

def sign_file(file_path: str, key_name: str, password: str) -> dict:
    # This function is not currently wired up to the UI but is kept for future use.
    # ... implementation ...
    return {"success": False, "error": "Not implemented in UI"}

def verify_signature(file_path: str, signature_path: str, key_name: str) -> dict:
    # This function is not currently wired up to the UI but is kept for future use.
    # ... implementation ...
    return {"success": False, "error": "Not implemented in UI"}
