# ==============================================================================
# File: style.py
# Location: FileEncrypter/ui/
# Description: Defines the visual style and theme for the application.
# ==============================================================================

import tkinter as tk
from tkinter import ttk
from config import APP_NAME as AppName

# --- App Info ---
APP_NAME = AppName

# --- Colors (Modern, accessible palette) ---
PRIMARY_COLOR = "#4f46e5"   # Indigo 600
PRIMARY_LIGHT = "#c7d2fe"   # Indigo 300
PRIMARY_DARK = "#3730a3"    # Indigo 800
BG_COLOR = "#f9fafb"        # Gray 50
FG_COLOR = "#1f2937"        # Gray 800
FG_LIGHT_COLOR = "#6b7280"  # Gray 500
ACCENT_COLOR = "#10b981"    # Emerald 500
BORDER_COLOR = "#e5e7eb"    # Gray 200
WHITE_COLOR = "#ffffff"

# --- Fonts ---
FONT_FAMILY = "Segoe UI"
FONT_NORMAL = (FONT_FAMILY, 10)
FONT_BOLD = (FONT_FAMILY, 10, "bold")
FONT_HEADER = (FONT_FAMILY, 14, "bold")

def apply_theme(root):
    """Applies a consistent, modern theme to the application widgets."""
    style = ttk.Style(root)
    style.theme_use('clam')

    # --- General Widget Styling ---
    root.configure(background=BG_COLOR)
    style.configure(".",
        background=BG_COLOR,
        foreground=FG_COLOR,
        font=FONT_NORMAL,
        fieldbackground=WHITE_COLOR,
        borderwidth=1,
        relief=tk.FLAT)

    style.configure("TFrame", background=BG_COLOR)
    style.configure("TLabel", background=BG_COLOR, foreground=FG_COLOR)
    style.configure("Bold.TLabel", font=FONT_BOLD)
    style.configure("Header.TLabel", font=FONT_HEADER, foreground=PRIMARY_DARK)
    style.configure("Status.TLabel", font=(FONT_FAMILY, 9), foreground=FG_LIGHT_COLOR)
    
    # --- Notebook (Tabs) ---
    style.configure("TNotebook", background=BG_COLOR, borderwidth=0)
    style.configure("TNotebook.Tab",
        padding=[12, 8],
        font=FONT_BOLD,
        background=BG_COLOR,
        foreground=FG_LIGHT_COLOR,
        borderwidth=0)
    style.map("TNotebook.Tab",
        background=[("selected", BG_COLOR)],
        foreground=[("selected", PRIMARY_COLOR)],
        expand=[("selected", [0, 0, 0, 2])]) # Creates bottom border effect

    # --- Button Styling ---
    style.configure("TButton",
        padding=8,
        font=FONT_BOLD,
        background=WHITE_COLOR,
        foreground=FG_COLOR,
        bordercolor=BORDER_COLOR)
    style.map("TButton",
        background=[('active', BORDER_COLOR), ('!disabled', WHITE_COLOR)],
        bordercolor=[('active', FG_LIGHT_COLOR)])

    style.configure("Accent.TButton",
        background=PRIMARY_COLOR,
        foreground=WHITE_COLOR,
        bordercolor=PRIMARY_COLOR)
    style.map("Accent.TButton",
        background=[('active', PRIMARY_DARK), ('!disabled', PRIMARY_COLOR)],
        bordercolor=[('active', PRIMARY_DARK), ('!disabled', PRIMARY_COLOR)])

    # --- Entry and Combobox ---
    style.configure("TEntry", padding=8, bordercolor=BORDER_COLOR)
    style.map("TEntry", bordercolor=[('focus', PRIMARY_COLOR)])
    style.configure("TCombobox", padding=8, arrowsize=15)
    style.map("TCombobox", bordercolor=[('focus', PRIMARY_COLOR)])
    
    # --- Radio and Checkbox ---
    style.configure("TRadiobutton", background=BG_COLOR)
    style.configure("TCheckbutton", background=BG_COLOR)
