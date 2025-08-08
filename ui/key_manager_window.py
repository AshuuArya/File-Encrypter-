# ==============================================================================
# File: key_manager_window.py
# Location: FileEncrypter/ui/
# Description: A separate window for managing RSA key pairs in the vault.
# ==============================================================================

import tkinter as tk
from tkinter import ttk, messagebox

from . import style

class KeyManagerWindow:
    def __init__(self, parent, app_logic):
        self.parent = parent
        self.logic = app_logic
        
        self.window = tk.Toplevel(parent)
        self.window.title("Key Pair Manager")
        self.window.geometry("500x300")
        self.window.resizable(False, False)
        self.window.transient(parent) # Keep window on top of parent
        self.window.grab_set() # Modal behavior

        style.apply_theme(self.window)
        
        # --- Variables ---
        self.key_name = tk.StringVar()
        self.password = tk.StringVar()
        self.password_confirm = tk.StringVar()
        self.description = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.window, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Create New Key Pair", style="Header.TLabel").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 15))

        # Form fields with labels
        ttk.Label(main_frame, text="Key Name:").grid(row=1, column=0, sticky="w", pady=5)
        name_entry = ttk.Entry(main_frame, textvariable=self.key_name)
        name_entry.grid(row=1, column=1, sticky="ew", pady=5)

        ttk.Label(main_frame, text="Description (Optional):").grid(row=2, column=0, sticky="w", pady=5)
        desc_entry = ttk.Entry(main_frame, textvariable=self.description)
        desc_entry.grid(row=2, column=1, sticky="ew", pady=5)

        ttk.Label(main_frame, text="Password:").grid(row=3, column=0, sticky="w", pady=5)
        pass_entry = ttk.Entry(main_frame, textvariable=self.password, show="*")
        pass_entry.grid(row=3, column=1, sticky="ew", pady=5)

        ttk.Label(main_frame, text="Confirm Password:").grid(row=4, column=0, sticky="w", pady=5)
        confirm_entry = ttk.Entry(main_frame, textvariable=self.password_confirm, show="*")
        confirm_entry.grid(row=4, column=1, sticky="ew", pady=5)
        
        # Action Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=1, sticky="e", pady=(20, 0))
        
        create_button = ttk.Button(button_frame, text="Create Keys", command=self.on_create_click, style="Accent.TButton")
        create_button.pack(side=tk.RIGHT)
        
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.window.destroy)
        cancel_button.pack(side=tk.RIGHT, padx=(0, 10))

        main_frame.columnconfigure(1, weight=1)

    def on_create_click(self):
        name = self.key_name.get().strip()
        pwd = self.password.get()
        confirm_pwd = self.password_confirm.get()
        desc = self.description.get().strip()
        
        if not name:
            messagebox.showerror("Input Error", "Key Name cannot be empty.", parent=self.window)
            return
        if len(pwd) < 8:
            messagebox.showerror("Input Error", "Password must be at least 8 characters long for security.", parent=self.window)
            return
        if pwd != confirm_pwd:
            messagebox.showerror("Input Error", "Passwords do not match.", parent=self.window)
            return

        # Pass data to the logic layer to handle generation
        self.logic.generate_keys(name, pwd, desc)
        self.window.destroy()
