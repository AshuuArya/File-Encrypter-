# ==============================================================================
# File: main_window.py
# Location: FileEncrypter/ui/
# Description: The main GUI window for the application.
# ==============================================================================

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from . import style
from . import key_manager_window
from logic.app_logic import AppLogic

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.logic = AppLogic(self.ui_callback)
        
        self.root.title(style.APP_NAME)
        self.root.geometry("650x520")
        self.root.minsize(600, 480)
        style.apply_theme(self.root)

        # --- Member Variables ---
        self.encrypt_file_path = tk.StringVar()
        self.decrypt_file_path = tk.StringVar()
        self.encrypt_method = tk.StringVar(value="password")
        self.decrypt_method = tk.StringVar(value="password")
        self.encrypt_key_name = tk.StringVar()
        self.decrypt_key_name = tk.StringVar()
        self.encrypt_password = tk.StringVar()
        self.decrypt_password = tk.StringVar()
        self.decrypt_key_password = tk.StringVar()

        self.create_widgets()
        self.refresh_key_dropdowns()

    def ui_callback(self, command, *args):
        """Handles callbacks from the logic layer to update the UI safely."""
        def task():
            if command == "update_status":
                self.status_bar.config(text=args[0])
            elif command == "show_error":
                messagebox.showerror(args[0], args[1])
            elif command == "show_info":
                messagebox.showinfo(args[0], args[1])
            elif command == "refresh_ui":
                self.refresh_key_dropdowns()
        # Schedule the UI update to run in the main thread
        self.root.after(0, task)

    def create_widgets(self):
        # --- Main Notebook (Tabs) ---
        notebook = ttk.Notebook(self.root, style="TNotebook")
        notebook.pack(expand=True, fill='both', padx=10, pady=10)

        encrypt_tab = ttk.Frame(notebook, style="TFrame", padding=15)
        decrypt_tab = ttk.Frame(notebook, style="TFrame", padding=15)

        notebook.add(encrypt_tab, text='Encrypt')
        notebook.add(decrypt_tab, text='Decrypt')

        self.create_encrypt_frame(encrypt_tab)
        self.create_decrypt_frame(decrypt_tab)
        
        # --- Status Bar ---
        self.status_bar = ttk.Label(self.root, text="Ready", anchor='w', style="Status.TLabel")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(0, 5))
    
    def create_encrypt_frame(self, parent):
        # File selection
        file_frame = self.create_file_selection_frame(parent, "File to Encrypt:", self.encrypt_file_path)
        file_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 15))
        
        # Method selection
        self.create_method_selection(parent, self.encrypt_method, "encrypt", 1)
        
        # Method-specific options
        self.enc_password_frame = self.create_password_frame(parent, "Enter Password:", self.encrypt_password)
        self.enc_keyfile_frame = self.create_keyfile_frame(parent, "Encrypt with Key:", self.encrypt_key_name)
        self.enc_password_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=10)
        
        # Action button
        enc_button = ttk.Button(parent, text="Encrypt File", command=self.on_encrypt_click, style="Accent.TButton")
        enc_button.grid(row=4, column=0, columnspan=3, sticky="ew", ipady=8, pady=(20, 0))
        
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(3, weight=1) # Spacer row
        self.toggle_encrypt_options()

    def create_decrypt_frame(self, parent):
        # File selection
        file_frame = self.create_file_selection_frame(parent, "File to Decrypt:", self.decrypt_file_path, ".encrypted")
        file_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 15))

        # Method selection
        self.create_method_selection(parent, self.decrypt_method, "decrypt", 1)

        # Method-specific options
        self.dec_password_frame = self.create_password_frame(parent, "Enter Password:", self.decrypt_password)
        self.dec_keyfile_frame = self.create_keyfile_frame(parent, "Decrypt with Key:", self.decrypt_key_name, include_password=True, password_var=self.decrypt_key_password)
        self.dec_password_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=10)

        # Action button
        dec_button = ttk.Button(parent, text="Decrypt File", command=self.on_decrypt_click, style="Accent.TButton")
        dec_button.grid(row=4, column=0, columnspan=3, sticky="ew", ipady=8, pady=(20, 0))
        
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(3, weight=1) # Spacer row
        self.toggle_decrypt_options()

    # --- Reusable Widget Creation Methods ---

    def create_file_selection_frame(self, parent, label_text, text_var, file_ext=""):
        frame = ttk.Frame(parent, style="TFrame")
        ttk.Label(frame, text=label_text, style="Bold.TLabel").pack(side=tk.LEFT, padx=(0, 10))
        entry = ttk.Entry(frame, textvariable=text_var, state='readonly')
        entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        button = ttk.Button(frame, text="Browse...", command=lambda: self.browse_file(text_var, file_ext))
        button.pack(side=tk.LEFT, padx=(5, 0))
        return frame

    def create_method_selection(self, parent, var, mode, row):
        frame = ttk.Frame(parent, style="TFrame")
        frame.grid(row=row, column=0, columnspan=3, sticky="w", pady=5)
        toggle_func = self.toggle_encrypt_options if mode == "encrypt" else self.toggle_decrypt_options
        ttk.Label(frame, text="Method:", style="Bold.TLabel").pack(side=tk.LEFT, padx=(0, 10))
        rb1 = ttk.Radiobutton(frame, text="Password", variable=var, value="password", command=toggle_func, style="TRadiobutton")
        rb1.pack(side=tk.LEFT)
        rb2 = ttk.Radiobutton(frame, text="Key Pair", variable=var, value="keyfile", command=toggle_func, style="TRadiobutton")
        rb2.pack(side=tk.LEFT, padx=10)
        
        key_button = ttk.Button(frame, text="Manage Keys...", command=self.open_key_manager)
        key_button.pack(side=tk.LEFT, padx=(20, 0))

    def create_password_frame(self, parent, label_text, password_var):
        frame = ttk.Frame(parent, style="TFrame")
        ttk.Label(frame, text=label_text, style="TLabel").pack(side=tk.LEFT, padx=(0, 10), anchor='w')
        entry = ttk.Entry(frame, textvariable=password_var, show="*")
        entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        return frame

    def create_keyfile_frame(self, parent, label_text, key_name_var, include_password=False, password_var=None):
        frame = ttk.Frame(parent, style="TFrame")
        
        key_frame = ttk.Frame(frame)
        key_frame.pack(fill=tk.X, expand=True)
        ttk.Label(key_frame, text=label_text, style="TLabel").pack(side=tk.LEFT, padx=(0, 10))
        
        # We assign the dropdown to self so we can update its values later
        dropdown = ttk.Combobox(key_frame, textvariable=key_name_var, state="readonly")
        dropdown.pack(side=tk.LEFT, expand=True, fill=tk.X)
        if label_text.startswith("Encrypt"):
            self.encrypt_key_dropdown = dropdown
        else:
            self.decrypt_key_dropdown = dropdown

        if include_password:
            pass_frame = ttk.Frame(frame)
            pass_frame.pack(fill=tk.X, expand=True, pady=(10,0))
            ttk.Label(pass_frame, text="Key Password:", style="TLabel").pack(side=tk.LEFT, padx=(0, 10))
            pwd_entry = ttk.Entry(pass_frame, textvariable=password_var, show="*")
            pwd_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        return frame

    # --- UI Logic and Event Handlers ---

    def browse_file(self, text_var, file_ext):
        if file_ext:
            filetypes = [(f"Encrypted Files", f"*{file_ext}"), ("All files", "*.*")]
            path = filedialog.askopenfilename(filetypes=filetypes)
        else:
            path = filedialog.askopenfilename()
        if path:
            text_var.set(path)

    def toggle_encrypt_options(self):
        if self.encrypt_method.get() == "password":
            self.enc_password_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=10)
            self.enc_keyfile_frame.grid_remove()
        else:
            self.enc_password_frame.grid_remove()
            self.enc_keyfile_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=10)

    def toggle_decrypt_options(self):
        if self.decrypt_method.get() == "password":
            self.dec_password_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=10)
            self.dec_keyfile_frame.grid_remove()
        else:
            self.dec_password_frame.grid_remove()
            self.dec_keyfile_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=10)

    def refresh_key_dropdowns(self):
        key_list = self.logic.get_key_list()
        self.encrypt_key_dropdown['values'] = key_list
        self.decrypt_key_dropdown['values'] = key_list
        if key_list:
            self.encrypt_key_name.set(key_list[0])
            self.decrypt_key_name.set(key_list[0])
        else:
            self.encrypt_key_name.set("")
            self.decrypt_key_name.set("")

    def open_key_manager(self):
        key_manager_window.KeyManagerWindow(self.root, self.logic)

    def on_encrypt_click(self):
        options = {
            "password": self.encrypt_password.get(),
            "key_name": self.encrypt_key_name.get(),
        }
        self.logic.encrypt_file(self.encrypt_file_path.get(), self.encrypt_method.get(), options)
        
    def on_decrypt_click(self):
        options = {
            "password": self.decrypt_password.get() if self.decrypt_method.get() == 'password' else self.decrypt_key_password.get(),
            "key_name": self.decrypt_key_name.get(),
        }
        self.logic.decrypt_file(self.decrypt_file_path.get(), self.decrypt_method.get(), options)
