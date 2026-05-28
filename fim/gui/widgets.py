"""Reusable Tkinter widgets and dark theme for FIM GUI."""

from __future__ import annotations

import tkinter as tk
from tkinter import scrolledtext, ttk

# Dark palette
BG = "#0d1117"
PANEL = "#161b22"
PANEL_ALT = "#1c2128"
BORDER = "#30363d"
INPUT_BG = "#0d1117"
LOG_BG = "#010409"
TEXT = "#e6edf3"
MUTED = "#8b949e"
STATUS_BG = "#161b22"

ACCENT = "#58a6ff"
GREEN = "#238636"
YELLOW = "#d29922"
ORANGE = "#bd561d"
RED = "#da3633"
PURPLE = "#8957e5"

FONT_UI = ("Segoe UI", 10)
FONT_UI_BOLD = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 22, "bold")
FONT_HEADER = ("Segoe UI", 24, "bold")
FONT_MONO = ("Consolas", 10)
FONT_SMALL = ("Segoe UI", 9, "bold")

SEVERITY_FOREGROUND = {
    "CRITICAL": "#ff7b72",
    "HIGH": "#ffa657",
    "MEDIUM": "#e3b341",
    "LOW": "#3fb950",
}


def setup_theme(root: tk.Misc) -> ttk.Style:
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(
        "Treeview",
        background=PANEL_ALT,
        foreground=TEXT,
        fieldbackground=PANEL_ALT,
        borderwidth=0,
        rowheight=30,
        font=FONT_UI,
    )
    style.configure(
        "Treeview.Heading",
        background="#21262d",
        foreground=TEXT,
        font=FONT_UI_BOLD,
        relief="flat",
    )
    style.map(
        "Treeview",
        background=[("selected", "#1f3a5f")],
        foreground=[("selected", "#ffffff")],
    )

    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure(
        "TNotebook.Tab",
        background=PANEL,
        foreground=MUTED,
        padding=(16, 10),
        font=FONT_UI,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", PANEL_ALT)],
        foreground=[("selected", ACCENT)],
    )

    style.configure(
        "TCombobox",
        fieldbackground=INPUT_BG,
        background=PANEL_ALT,
        foreground=TEXT,
        arrowcolor=MUTED,
        bordercolor=BORDER,
        lightcolor=BORDER,
        darkcolor=BORDER,
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", INPUT_BG)],
        foreground=[("readonly", TEXT)],
    )

    style.configure(
        "Vertical.TScrollbar",
        background=PANEL,
        troughcolor=BG,
        bordercolor=BORDER,
        arrowcolor=MUTED,
    )
    return style


def panel_frame(parent: tk.Misc, **kwargs) -> tk.Frame:
    return tk.Frame(
        parent,
        bg=PANEL,
        highlightbackground=BORDER,
        highlightthickness=1,
        **kwargs,
    )


def _parent_bg(parent: tk.Misc, kwargs: dict) -> str:
    return kwargs.pop("bg", parent.cget("bg"))


def muted_label(parent: tk.Misc, text: str, **kwargs) -> tk.Label:
    return tk.Label(
        parent, text=text, bg=_parent_bg(parent, kwargs), fg=MUTED, font=FONT_SMALL, **kwargs
    )


def body_label(parent: tk.Misc, text: str, **kwargs) -> tk.Label:
    return tk.Label(
        parent, text=text, bg=_parent_bg(parent, kwargs), fg=TEXT, font=FONT_UI, **kwargs
    )


def make_entry(parent: tk.Misc, textvariable: tk.StringVar | None = None, **kwargs) -> tk.Entry:
    return tk.Entry(
        parent,
        textvariable=textvariable,
        bg=INPUT_BG,
        fg=TEXT,
        insertbackground=TEXT,
        relief="flat",
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=ACCENT,
        font=FONT_UI,
        **kwargs,
    )


def make_text(parent: tk.Misc, **kwargs) -> scrolledtext.ScrolledText:
    widget = scrolledtext.ScrolledText(
        parent,
        bg=kwargs.pop("bg", PANEL_ALT),
        fg=TEXT,
        insertbackground=TEXT,
        selectbackground="#1f3a5f",
        selectforeground=TEXT,
        relief="flat",
        highlightthickness=1,
        highlightbackground=BORDER,
        font=kwargs.pop("font", FONT_MONO),
        **kwargs,
    )
    return widget


def make_checkbutton(
    parent: tk.Misc,
    text: str,
    variable: tk.Variable,
    *,
    command=None,
) -> tk.Checkbutton:
    return tk.Checkbutton(
        parent,
        text=text,
        variable=variable,
        command=command,
        bg=BG,
        fg=TEXT,
        selectcolor=PANEL_ALT,
        activebackground=BG,
        activeforeground=TEXT,
        font=FONT_UI,
    )


def styled_button(parent: tk.Misc, text: str, command, color: str) -> tk.Button:
    return tk.Button(
        parent,
        text=text,
        command=command,
        bg=color,
        fg="#ffffff",
        activebackground=_darken(color),
        activeforeground="#ffffff",
        disabledforeground=MUTED,
        relief="flat",
        padx=14,
        pady=8,
        font=FONT_UI_BOLD,
        cursor="hand2",
        borderwidth=0,
        highlightthickness=0,
    )


def _darken(hex_color: str, factor: float = 0.85) -> str:
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i : i + 2], 16) for i in (0, 2, 4))
    r, g, b = (int(c * factor) for c in (r, g, b))
    return f"#{r:02x}{g:02x}{b:02x}"


def make_treeview(
    parent: tk.Misc,
    columns: tuple[str, ...],
    headings: dict[str, str],
    widths: dict[str, int],
    *,
    severity_column: str | None = None,
) -> tuple[ttk.Treeview, ttk.Scrollbar]:
    tree = ttk.Treeview(parent, columns=columns, show="headings")
    for column in columns:
        tree.heading(column, text=headings.get(column, column))
        tree.column(column, width=widths.get(column, 120), anchor="w")

    if severity_column:
        for severity, color in SEVERITY_FOREGROUND.items():
            tree.tag_configure(severity, foreground=color)

    scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    return tree, scrollbar
