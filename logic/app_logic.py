# ==============================================================================
# File: app_logic.py
# Location: FileEncrypter/logic/
# Description: Acts as a bridge between the UI and the backend crypto/vault
#              modules. Handles application flow and state.
# ==============================================================================

import os
import threading
from tkinter import messagebox

from . import crypto_engine, vault_manager
from config import ENCRYPTED_FILE_EXT

class AppLogic:
    """
    Handles the core application logic, separating UI events from backend operations.
    This class orchestrates calls to the cryptographic and vault modules and sends
    results back to the UI via a callback mechanism.
    """
    def __init__(self, ui_callback):
        self.ui_callback = ui_callback

    def _run_in_thread(self, target, args=()):
        """Helper to run a function in a separate thread to avoid freezing the GUI."""
        thread = threading.Thread(target=target, args=args)
        thread.daemon = True
        thread.start()

    def generate_keys(self, key_name, password, description):
        """Validates input and starts the key generation task in a new thread."""
        if not key_name or not password:
            self.ui_callback("show_error", "Input Error", "Key Name and Password cannot be empty.")
            return
        self._run_in_thread(self._generate_keys_task, (key_name, password, description))

    def _generate_keys_task(self, key_name, password, description):
        """The actual key generation process, run in a background thread."""
        self.ui_callback("update_status", f"Generating '{key_name}' keys... This may take a moment.")
        result = vault_manager.create_key_pair(key_name, password, description)
        if result["success"]:
            self.ui_callback("show_info", "Success", f"Key pair '{key_name}' has been created and added to your vault.")
            self.ui_callback("refresh_ui")
        else:
            self.ui_callback("show_error", "Key Generation Failed", result["error"])
        self.ui_callback("update_status", "Ready")

    def get_key_list(self):
        """Retrieves the list of key names from the vault."""
        return vault_manager.get_all_key_names()

    def encrypt_file(self, file_path, method, options):
        """Validates input and starts the encryption task in a new thread."""
        if not file_path or not os.path.exists(file_path):
            self.ui_callback("show_error", "File Error", "Please select a valid file to encrypt.")
            return
        self._run_in_thread(self._encrypt_file_task, (file_path, method, options))

    def _encrypt_file_task(self, file_path, method, options):
        """The actual file encryption process, run in a background thread."""
        self.ui_callback("update_status", f"Encrypting {os.path.basename(file_path)}...")
        
        if method == "password":
            password = options.get("password")
            if not password:
                self.ui_callback("show_error", "Input Error", "Password cannot be empty.")
                self.ui_callback("update_status", "Ready")
                return
            result = crypto_engine.encrypt_file_with_password(file_path, password)
        else: # keyfile
            key_name = options.get("key_name")
            if not key_name:
                self.ui_callback("show_error", "Input Error", "Please select a key pair to encrypt with.")
                self.ui_callback("update_status", "Ready")
                return
            result = crypto_engine.encrypt_file_with_key(file_path, key_name)

        if not result["success"]:
            self.ui_callback("show_error", "Encryption Failed", result["error"])
            self.ui_callback("update_status", "Ready")
            return

        output_path = result["output_path"]
        self.ui_callback("show_info", "Success", f"File encrypted successfully!\n\nOutput: {output_path}")
        self.ui_callback("update_status", "Ready")

    def decrypt_file(self, file_path, method, options):
        """Validates input and starts the decryption task in a new thread."""
        if not file_path or not os.path.exists(file_path):
            self.ui_callback("show_error", "File Error", "Please select a valid file to decrypt.")
            return
        self._run_in_thread(self._decrypt_file_task, (file_path, method, options))

    def _decrypt_file_task(self, file_path, method, options):
        """The actual file decryption process, run in a background thread."""
        self.ui_callback("update_status", f"Decrypting {os.path.basename(file_path)}...")

        if method == "password":
            password = options.get("password")
            if not password:
                self.ui_callback("show_error", "Input Error", "Password cannot be empty.")
                self.ui_callback("update_status", "Ready")
                return
            result = crypto_engine.decrypt_file_with_password(file_path, password)
        else: # keyfile
            key_name = options.get("key_name")
            password = options.get("password")
            if not key_name or not password:
                self.ui_callback("show_error", "Input Error", "A key pair and its password are required for decryption.")
                self.ui_callback("update_status", "Ready")
                return
            result = crypto_engine.decrypt_file_with_key(file_path, key_name, password)

        if result["success"]:
            output_path = result["output_path"]
            self.ui_callback("show_info", "Success", f"File decrypted successfully!\n\nOutput: {output_path}")
        else:
            self.ui_callback("show_error", "Decryption Failed", result["error"])
        
        self.ui_callback("update_status", "Ready")
