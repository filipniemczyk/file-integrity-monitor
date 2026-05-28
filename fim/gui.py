"""Simple Tkinter GUI for FIM."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from fim.actions import run_export_html_report, run_init, run_scan
from fim.exceptions import ConfigError, DatabaseError, FIMError, ScanError


def launch_gui(default_config: str = "config.example.yaml") -> None:
    """Open the FIM graphical interface."""
    root = tk.Tk()
    root.title("File Integrity Monitor")
    root.minsize(720, 480)

    main = ttk.Frame(root, padding=12)
    main.pack(fill=tk.BOTH, expand=True)

    config_var = tk.StringVar(value=default_config)
    html_var = tk.StringVar(value="reports/report.html")

    ttk.Label(main, text="Config file").grid(row=0, column=0, sticky=tk.W)
    config_entry = ttk.Entry(main, textvariable=config_var, width=60)
    config_entry.grid(row=0, column=1, sticky=tk.EW, padx=(8, 8))

    def browse_config() -> None:
        path = filedialog.askopenfilename(
            title="Select config",
            filetypes=[("YAML files", "*.yaml *.yml"), ("All files", "*.*")],
        )
        if path:
            config_var.set(path)

    ttk.Button(main, text="Browse…", command=browse_config).grid(row=0, column=2)

    ttk.Label(main, text="HTML output").grid(row=1, column=0, sticky=tk.W, pady=(8, 0))
    html_entry = ttk.Entry(main, textvariable=html_var, width=60)
    html_entry.grid(row=1, column=1, sticky=tk.EW, padx=(8, 8), pady=(8, 0))

    def browse_html() -> None:
        path = filedialog.asksaveasfilename(
            title="Save HTML report",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile="report.html",
        )
        if path:
            html_var.set(path)

    ttk.Button(main, text="Browse…", command=browse_html).grid(row=1, column=2, pady=(8, 0))

    log = scrolledtext.ScrolledText(main, height=18, wrap=tk.WORD, font=("Consolas", 10))
    log.grid(row=3, column=0, columnspan=3, sticky=tk.NSEW, pady=(12, 0))
    log.configure(state=tk.DISABLED)

    main.columnconfigure(1, weight=1)
    main.rowconfigure(3, weight=1)

    def append_log(text: str) -> None:
        log.configure(state=tk.NORMAL)
        log.insert(tk.END, text.rstrip() + "\n\n")
        log.see(tk.END)
        log.configure(state=tk.DISABLED)

    def run_action(label: str, callback) -> None:
        config_path = config_var.get().strip()
        if not config_path:
            messagebox.showerror("FIM", "Config path is required.")
            return

        append_log(f"=== {label} ===")
        try:
            result = callback(config_path)
        except (ConfigError, DatabaseError, ScanError, FIMError) as error:
            append_log(f"ERROR: {error}")
            messagebox.showerror(label, str(error))
            return
        except Exception as error:  # pragma: no cover - GUI safety net
            append_log(f"ERROR: {error}")
            messagebox.showerror(label, str(error))
            return

        append_log(result.message)
        if result.changes_detected:
            messagebox.showwarning(label, "Changes detected. See log for details.")

    button_row = ttk.Frame(main)
    button_row.grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=(12, 0))

    ttk.Button(
        button_row,
        text="Init baseline",
        command=lambda: run_action("Init baseline", run_init),
    ).pack(side=tk.LEFT, padx=(0, 8))

    ttk.Button(
        button_row,
        text="Scan",
        command=lambda: run_action("Scan", run_scan),
    ).pack(side=tk.LEFT, padx=(0, 8))

    def export_html_action() -> None:
        output = html_var.get().strip() or "reports/report.html"
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        append_log("=== Export HTML ===")

        config_path = config_var.get().strip()
        if not config_path:
            messagebox.showerror("FIM", "Config path is required.")
            return

        try:
            result = run_export_html_report(config_path, output)
        except (ConfigError, DatabaseError, FIMError) as error:
            append_log(f"ERROR: {error}")
            messagebox.showerror("Export HTML", str(error))
            return

        append_log(result.message)
        if result.success:
            messagebox.showinfo("Export HTML", result.message)

    ttk.Button(button_row, text="Export HTML", command=export_html_action).pack(
        side=tk.LEFT
    )

    append_log("FIM GUI ready. Select a config and run an action.")
    root.mainloop()
