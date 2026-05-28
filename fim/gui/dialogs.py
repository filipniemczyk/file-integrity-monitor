"""Dialog helpers for FIM GUI."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from fim.actions import VerifyActionResult
from fim.gui.widgets import BG, make_text
from fim.models import IntegrityEvent


def show_verify_result(parent: tk.Misc, result: VerifyActionResult) -> None:
    lines = [
        f"Status: {result.status}",
        f"Path: {result.path}",
        f"Description: {result.description}",
    ]
    if result.severity:
        lines.append(f"Severity: {result.severity}")
    if result.old_hash:
        lines.append(f"Old hash: {result.old_hash}")
    if result.new_hash:
        lines.append(f"New hash: {result.new_hash}")
    if result.events:
        lines.append("")
        lines.append("Events:")
        for event in result.events:
            lines.append(f"  - {event.severity} / {event.event_type}: {event.description or '-'}")

    messagebox.showinfo("Verify result", "\n".join(lines), parent=parent)


def show_event_details(parent: tk.Misc, event: IntegrityEvent) -> None:
    window = tk.Toplevel(parent)
    window.title(f"Event #{event.id or '-'}")
    window.geometry("680x440")
    window.configure(bg=BG)
    window.transient(parent)

    text = make_text(window, wrap=tk.WORD)
    text.pack(fill=tk.BOTH, expand=True, padx=14, pady=14)

    lines = [
        f"ID: {event.id}",
        f"Timestamp: {event.timestamp}",
        f"Severity: {event.severity}",
        f"Event type: {event.event_type}",
        f"Path: {event.path}",
        f"Description: {event.description or '-'}",
        "",
        f"Old hash: {event.old_hash or '-'}",
        f"New hash: {event.new_hash or '-'}",
    ]
    text.insert("1.0", "\n".join(lines))
    text.configure(state=tk.DISABLED)
