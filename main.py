# ==============================================================================
# File: main.py
# Location: FileEncrypter/
# Description: Main entry point for the FileEncrypter application.
#              This script initializes and runs the GUI.
# ==============================================================================

import tkinter as tk
from tkinter import messagebox
from ui.main_window import MainWindow
from logic.vault_manager import ensure_app_data_dir

def main():
    """
    Initializes the application, creates the main window, and starts the
    Tkinter event loop.
    """
    try:
        # Ensure the application's data directory exists before starting the UI
        ensure_app_data_dir()
        
        root = tk.Tk()
        app = MainWindow(root)
        root.mainloop()
    except Exception as e:
        # Fallback for any unexpected critical error during startup.
        # A real application would use a dedicated logging framework.
        print(f"A critical error occurred during application startup: {e}")
        # Display a simple error message if tkinter is available
        try:
            messagebox.showerror("Critical Error", f"An unexpected error occurred and the application must close.\n\nDetails: {e}")
        except:
            pass

if __name__ == "__main__":
    main()
