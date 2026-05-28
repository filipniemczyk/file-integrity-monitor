"""Main Tkinter application for File Integrity Monitor."""

from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import END, BOTH, LEFT, RIGHT, X, Y, filedialog, messagebox, ttk

from fim.actions import (
    AddBaselineActionResult,
    InitActionResult,
    ScanActionResult,
    baseline_display_row,
    event_type_choices,
    filter_events,
    format_config_preview,
    is_security_config_path,
    load_config_for_gui,
    run_add_baseline,
    run_export_html_report,
    run_export_json,
    run_init,
    run_load_baseline,
    run_load_events,
    run_scan,
    run_verify,
    security_config_warning,
    severity_choices,
)
from fim.exceptions import ConfigError, DatabaseError, FIMError, ScanError
from fim.gui.dialogs import show_event_details, show_verify_result
from fim.gui.widgets import (
    ACCENT,
    BG,
    BORDER,
    FONT_HEADER,
    FONT_TITLE,
    GREEN,
    LOG_BG,
    MUTED,
    ORANGE,
    PANEL,
    PURPLE,
    RED,
    STATUS_BG,
    TEXT,
    YELLOW,
    body_label,
    make_checkbutton,
    make_entry,
    make_text,
    make_treeview,
    muted_label,
    panel_frame,
    setup_theme,
    styled_button,
)
from fim.models import IntegrityEvent, Severity


class FIMGuiApp(tk.Tk):
    """Graphical interface for FIM using existing backend modules."""

    def __init__(self, default_config: str = "config.example.yaml") -> None:
        super().__init__()
        self.title("File Integrity Monitor")
        self.geometry("1320x820")
        self.minsize(1100, 700)
        self.configure(bg=BG)

        self.config_path = tk.StringVar(value=self._default_config(default_config))
        self.status_text = tk.StringVar(value="Ready")
        self._busy = False

        self.all_events: list[IntegrityEvent] = []
        self.displayed_events: list[IntegrityEvent] = []
        self.baseline_records = []

        setup_theme(self)
        self._build_layout()
        self._log("FIM GUI ready.")
        self._load_config_preview(silent=True)

    def _default_config(self, fallback: str) -> str:
        for name in (fallback, "config.example.yaml", "config.security.yaml"):
            path = Path(name)
            if path.exists():
                return str(path.resolve())
        return fallback

    def _build_layout(self) -> None:
        header = tk.Frame(self, bg=BG)
        header.pack(fill=X, padx=20, pady=(18, 6))
        tk.Label(header, text="File Integrity Monitor", bg=BG, fg=TEXT, font=FONT_HEADER).pack(
            side=LEFT
        )
        tk.Label(
            header,
            text="Security dashboard",
            bg=BG,
            fg=ACCENT,
            font=("Segoe UI", 11, "bold"),
        ).pack(side=LEFT, padx=(14, 0), pady=(12, 0))

        config_bar = panel_frame(self)
        config_bar.pack(fill=X, padx=20, pady=(4, 8))
        inner = tk.Frame(config_bar, bg=PANEL)
        inner.pack(fill=X, padx=12, pady=10)
        muted_label(inner, "CONFIG", bg=PANEL).pack(side=LEFT, padx=(0, 10))
        make_entry(inner, self.config_path).pack(side=LEFT, fill=X, expand=True, ipady=6)
        styled_button(inner, "Browse", self.browse_config, ACCENT).pack(side=LEFT, padx=(8, 4))
        styled_button(inner, "Load config", self._load_config_preview, PURPLE).pack(side=LEFT)

        cards = tk.Frame(self, bg=BG)
        cards.pack(fill=X, padx=20, pady=6)
        self.summary_cards: dict[str, tk.Label] = {}
        for label, color in [
            ("ALL", ACCENT),
            ("CRITICAL", RED),
            ("HIGH", ORANGE),
            ("MEDIUM", YELLOW),
            ("LOW", GREEN),
            ("BASELINE", PURPLE),
        ]:
            card = panel_frame(cards)
            card.pack(side=LEFT, fill=X, expand=True, padx=4)
            tk.Label(card, text=label, bg=PANEL, fg=color, font=("Segoe UI", 9, "bold")).pack(
                anchor="w", padx=14, pady=(12, 0)
            )
            value = tk.Label(card, text="0", bg=PANEL, fg=TEXT, font=FONT_TITLE)
            value.pack(anchor="w", padx=14, pady=(0, 12))
            self.summary_cards[label] = value

        toolbar = tk.Frame(self, bg=BG)
        toolbar.pack(fill=X, padx=20, pady=(4, 8))
        self._action_buttons: list[tk.Button] = []
        for text, command, color in [
            ("Create baseline", self.create_baseline, GREEN),
            ("Run scan", self.run_scan_action, ACCENT),
            ("Export JSON", self.export_json_action, PURPLE),
            ("Export HTML", self.export_html_action, ACCENT),
        ]:
            button = styled_button(toolbar, text, command, color)
            button.pack(side=LEFT, padx=(0, 6))
            self._action_buttons.append(button)

        notebook = ttk.Notebook(self)
        notebook.pack(fill=BOTH, expand=True, padx=20, pady=(0, 6))

        self.alerts_tab = tk.Frame(notebook, bg=BG)
        self.baseline_tab = tk.Frame(notebook, bg=BG)
        self.config_tab = tk.Frame(notebook, bg=BG)
        self.verify_tab = tk.Frame(notebook, bg=BG)
        self.add_tab = tk.Frame(notebook, bg=BG)
        notebook.add(self.alerts_tab, text="  Alerts  ")
        notebook.add(self.baseline_tab, text="  Baseline  ")
        notebook.add(self.config_tab, text="  Configuration  ")
        notebook.add(self.verify_tab, text="  Verify  ")
        notebook.add(self.add_tab, text="  Add to baseline  ")

        self._build_alerts_tab()
        self._build_baseline_tab()
        self._build_config_tab()
        self._build_verify_tab()
        self._build_add_tab()

        log_frame = panel_frame(self)
        log_frame.pack(fill=BOTH, padx=20, pady=(0, 6), ipady=2)
        log_inner = tk.Frame(log_frame, bg=PANEL)
        log_inner.pack(fill=BOTH, expand=True, padx=12, pady=10)
        muted_label(log_inner, "LOG", bg=PANEL).pack(anchor="w", pady=(0, 6))
        self.log_text = make_text(log_inner, height=5, wrap=tk.WORD, font=("Consolas", 9), bg=LOG_BG)
        self.log_text.pack(fill=BOTH, expand=True)
        self.log_text.configure(state=tk.DISABLED)

        status = tk.Frame(self, bg=STATUS_BG, highlightbackground=BORDER, highlightthickness=1)
        status.pack(fill=X, side="bottom")
        tk.Label(
            status,
            textvariable=self.status_text,
            bg=STATUS_BG,
            fg=MUTED,
            anchor="w",
            font=("Segoe UI", 9),
            padx=16,
            pady=10,
        ).pack(fill=X)

    def _build_alerts_tab(self) -> None:
        filters = panel_frame(self.alerts_tab)
        filters.pack(fill=X, padx=10, pady=10)
        row = tk.Frame(filters, bg=PANEL)
        row.pack(fill=X, padx=12, pady=12)

        body_label(row, "Limit").pack(side=LEFT, padx=(0, 6))
        self.filter_limit = tk.StringVar(value="")
        make_entry(row, self.filter_limit, width=8).pack(side=LEFT, padx=(0, 16))

        body_label(row, "Event type").pack(side=LEFT, padx=(0, 6))
        self.filter_event_type = tk.StringVar(value="ALL")
        ttk.Combobox(
            row,
            textvariable=self.filter_event_type,
            values=event_type_choices(),
            width=22,
            state="readonly",
        ).pack(side=LEFT, padx=(0, 16))

        body_label(row, "Severity").pack(side=LEFT, padx=(0, 6))
        self.filter_severity = tk.StringVar(value="ALL")
        ttk.Combobox(
            row,
            textvariable=self.filter_severity,
            values=severity_choices(),
            width=12,
            state="readonly",
        ).pack(side=LEFT, padx=(0, 16))

        styled_button(row, "Apply filters", self.apply_alert_filters, ACCENT).pack(side=LEFT, padx=4)
        styled_button(row, "Clear filters", self.clear_alert_filters, ORANGE).pack(side=LEFT, padx=4)

        table_frame = tk.Frame(self.alerts_tab, bg=BG)
        table_frame.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))
        cols = ("id", "time", "severity", "event", "path", "old", "new", "description")
        self.alerts_tree, alerts_sb = make_treeview(
            table_frame,
            cols,
            {
                "id": "ID",
                "time": "Timestamp",
                "severity": "Severity",
                "event": "Event type",
                "path": "Path",
                "old": "Old hash",
                "new": "New hash",
                "description": "Description",
            },
            {
                "id": 60,
                "time": 180,
                "severity": 90,
                "event": 140,
                "path": 320,
                "old": 110,
                "new": 110,
                "description": 240,
            },
            severity_column="severity",
        )
        self.alerts_tree.pack(side=LEFT, fill=BOTH, expand=True)
        alerts_sb.pack(side=RIGHT, fill=Y)
        self.alerts_tree.bind("<Double-1>", self._on_alert_double_click)

    def _build_baseline_tab(self) -> None:
        controls = panel_frame(self.baseline_tab)
        controls.pack(fill=X, padx=10, pady=10)
        row = tk.Frame(controls, bg=PANEL)
        row.pack(fill=X, padx=12, pady=12)

        styled_button(row, "Load baseline", self.refresh_baseline, PURPLE).pack(side=LEFT, padx=(0, 12))

        body_label(row, "Contains").pack(side=LEFT, padx=(0, 6))
        self.baseline_contains = tk.StringVar(value="")
        make_entry(row, self.baseline_contains, width=20).pack(side=LEFT, padx=(0, 12))

        body_label(row, "Limit").pack(side=LEFT, padx=(0, 6))
        self.baseline_limit = tk.StringVar(value="")
        make_entry(row, self.baseline_limit, width=8).pack(side=LEFT, padx=(0, 12))

        self.baseline_full_hash = tk.BooleanVar(value=False)
        make_checkbutton(row, "Full hash", self.baseline_full_hash, command=self.refresh_baseline).pack(
            side=LEFT, padx=8
        )

        table_frame = tk.Frame(self.baseline_tab, bg=BG)
        table_frame.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))
        cols = ("path", "hash", "size", "mode", "uid", "gid", "mtime")
        self.baseline_tree, baseline_sb = make_treeview(
            table_frame,
            cols,
            {c: c.upper() for c in cols},
            {"path": 420, "hash": 220, "size": 80, "mode": 80, "uid": 70, "gid": 70, "mtime": 140},
        )
        self.baseline_tree.pack(side=LEFT, fill=BOTH, expand=True)
        baseline_sb.pack(side=RIGHT, fill=Y)

    def _build_config_tab(self) -> None:
        wrap = panel_frame(self.config_tab)
        wrap.pack(fill=BOTH, expand=True, padx=10, pady=10)
        inner = tk.Frame(wrap, bg=PANEL)
        inner.pack(fill=BOTH, expand=True, padx=12, pady=12)
        self.config_text = make_text(inner, wrap=tk.NONE)
        self.config_text.pack(fill=BOTH, expand=True)

    def _build_verify_tab(self) -> None:
        top = panel_frame(self.verify_tab)
        top.pack(fill=X, padx=10, pady=10)
        row = tk.Frame(top, bg=PANEL)
        row.pack(fill=X, padx=12, pady=12)
        body_label(row, "File path").pack(side=LEFT, padx=(0, 8))
        self.verify_path = tk.StringVar(value="")
        make_entry(row, self.verify_path).pack(side=LEFT, fill=X, expand=True, ipady=6)
        styled_button(row, "Browse file", self.browse_verify_file, ACCENT).pack(side=LEFT, padx=8)
        styled_button(row, "Verify", self.verify_file_action, GREEN).pack(side=LEFT, padx=4)

        bottom = panel_frame(self.verify_tab)
        bottom.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))
        inner = tk.Frame(bottom, bg=PANEL)
        inner.pack(fill=BOTH, expand=True, padx=12, pady=12)
        self.verify_result = make_text(inner, height=12)
        self.verify_result.pack(fill=BOTH, expand=True)

    def _build_add_tab(self) -> None:
        form_wrap = panel_frame(self.add_tab)
        form_wrap.pack(fill=X, padx=10, pady=10)
        form = tk.Frame(form_wrap, bg=PANEL)
        form.pack(fill=X, padx=12, pady=12)

        body_label(form, "Path").grid(row=0, column=0, sticky="w", padx=4, pady=8)
        self.add_path = tk.StringVar(value="")
        make_entry(form, self.add_path, width=70).grid(row=0, column=1, sticky="ew", padx=4, pady=8)
        styled_button(form, "Browse file", self.browse_add_file, ACCENT).grid(row=0, column=2, padx=4)
        styled_button(form, "Browse dir", self.browse_add_dir, PURPLE).grid(row=0, column=3, padx=4)

        self.add_recursive = tk.BooleanVar(value=False)
        make_checkbutton(
            form, "Recursive (required for directories)", self.add_recursive
        ).grid(row=1, column=1, sticky="w", padx=4, pady=4)
        self.add_force = tk.BooleanVar(value=False)
        make_checkbutton(form, "Force overwrite", self.add_force).grid(row=2, column=1, sticky="w", padx=4, pady=4)

        body_label(form, "Reason (optional)").grid(row=3, column=0, sticky="w", padx=4, pady=8)
        self.add_reason = tk.StringVar(value="")
        make_entry(form, self.add_reason).grid(row=3, column=1, columnspan=2, sticky="ew", padx=4, pady=8)

        styled_button(form, "Add to baseline", self.add_to_baseline_action, GREEN).grid(
            row=4, column=1, sticky="w", padx=4, pady=14
        )
        form.columnconfigure(1, weight=1)

        summary_wrap = panel_frame(self.add_tab)
        summary_wrap.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))
        summary_inner = tk.Frame(summary_wrap, bg=PANEL)
        summary_inner.pack(fill=BOTH, expand=True, padx=12, pady=12)
        self.add_summary = make_text(summary_inner, height=10)
        self.add_summary.pack(fill=BOTH, expand=True)

    def _config_path(self) -> str:
        path = self.config_path.get().strip()
        if not path:
            raise ConfigError("Config path is required.")
        return path

    def _log(self, message: str) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(END, message.rstrip() + "\n")
        self.log_text.see(END)
        self.log_text.configure(state=tk.DISABLED)

    def _set_busy(self, busy: bool, status: str | None = None) -> None:
        self._busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        for button in self._action_buttons:
            button.configure(state=state)
        if status is not None:
            self.status_text.set(status)

    def _run_async(self, label: str, worker, on_success=None) -> None:
        if self._busy:
            messagebox.showwarning("FIM", "Another operation is already in progress.")
            return

        self._set_busy(True, f"{label}...")
        self._log(f"=== {label} ===")

        def runner() -> None:
            try:
                result = worker()
                self.after(0, lambda r=result: self._async_success(label, r, on_success))
            except (ConfigError, DatabaseError, ScanError, FIMError) as error:
                message = str(error)
                self.after(0, lambda msg=message: self._async_error(label, msg))
            except Exception as error:  # pragma: no cover
                message = str(error)
                self.after(0, lambda msg=message: self._async_error(label, msg))

        threading.Thread(target=runner, daemon=True).start()

    def _async_success(self, label: str, result, on_success) -> None:
        self._set_busy(False, "Ready")
        if hasattr(result, "message"):
            self._log(result.message)
        if on_success:
            on_success(result)
        if getattr(result, "changes_detected", False):
            messagebox.showwarning(label, "Changes detected. See log for details.")
        elif isinstance(result, (InitActionResult, ScanActionResult, AddBaselineActionResult)):
            messagebox.showinfo(label, result.message)

    def _async_error(self, label: str, message: str) -> None:
        self._set_busy(False, "Error")
        self._log(f"ERROR: {message}")
        messagebox.showerror(label, message)

    def browse_config(self) -> None:
        path = filedialog.askopenfilename(
            title="Select configuration",
            filetypes=[("YAML", "*.yaml *.yml"), ("All files", "*.*")],
        )
        if path:
            self.config_path.set(path)
            self._load_config_preview()

    def _load_config_preview(self, silent: bool = False) -> None:
        try:
            config_path = self._config_path()
            cfg = load_config_for_gui(config_path)
            preview = format_config_preview(cfg, config_path)
            self.config_text.delete("1.0", END)
            self.config_text.insert("1.0", preview)
            self._log("Configuration loaded.")
            self.status_text.set("Configuration loaded")
            if is_security_config_path(config_path):
                self._log(f"WARNING: {security_config_warning()}")
                if not silent:
                    messagebox.showwarning("Security configuration", security_config_warning())
        except (ConfigError, DatabaseError, FIMError) as error:
            self.config_text.delete("1.0", END)
            self.config_text.insert("1.0", str(error))
            if not silent:
                messagebox.showerror("Load config", str(error))

    def create_baseline(self) -> None:
        def worker():
            return run_init(self._config_path())

        def on_success(result: InitActionResult) -> None:
            self.refresh_baseline(silent=True)
            self.summary_cards["BASELINE"].configure(text=str(result.files_in_baseline))

        self._run_async("Create baseline", worker, on_success)

    def run_scan_action(self) -> None:
        def worker():
            return run_scan(self._config_path())

        def on_success(result: ScanActionResult) -> None:
            self.all_events = run_load_events(self._config_path())
            self.apply_alert_filters(silent=True)
            if result.stats:
                self._log(
                    f"Scan stats: {result.stats.by_event_type} | severity: {result.stats.by_severity}"
                )

        self._run_async("Run scan", worker, on_success)

    def _parse_limit(self, value: str) -> int | None:
        value = value.strip()
        if not value:
            return None
        return max(1, int(value))

    def apply_alert_filters(self, silent: bool = False) -> None:
        try:
            if not silent:
                self.all_events = run_load_events(self._config_path())
            limit = self._parse_limit(self.filter_limit.get())
            self.displayed_events = filter_events(
                self.all_events,
                limit=limit,
                event_type=self.filter_event_type.get(),
                severity=self.filter_severity.get(),
            )
            self._populate_alerts()
            if not silent:
                self._log(
                    f"Loaded {len(self.all_events)} alert(s); "
                    f"showing {len(self.displayed_events)} after filters."
                )
        except (ConfigError, DatabaseError, FIMError) as error:
            if not silent:
                messagebox.showerror("Alerts", str(error))
            self._log(f"ERROR: {error}")
        except ValueError:
            messagebox.showerror("Filters", "Limit must be a positive number.")

    def clear_alert_filters(self) -> None:
        self.filter_limit.set("")
        self.filter_event_type.set("ALL")
        self.filter_severity.set("ALL")
        self.apply_alert_filters()

    def _populate_alerts(self) -> None:
        self.alerts_tree.delete(*self.alerts_tree.get_children())
        counts = {Severity.CRITICAL: 0, Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}
        for event in self.all_events:
            if event.severity in counts:
                counts[event.severity] += 1

        self.summary_cards["ALL"].configure(text=str(len(self.all_events)))
        for severity in counts:
            self.summary_cards[severity].configure(text=str(counts[severity]))

        for event in self.displayed_events:
            self.alerts_tree.insert(
                "",
                END,
                values=(
                    event.id if event.id is not None else "-",
                    (event.timestamp or "-")[:19].replace("T", " "),
                    event.severity,
                    event.event_type,
                    event.path,
                    self._short_hash(event.old_hash),
                    self._short_hash(event.new_hash),
                    event.description or "-",
                ),
                tags=(event.severity,),
            )

    def _short_hash(self, value: str | None, length: int = 12) -> str:
        if not value:
            return "-"
        return value if len(value) <= length else f"{value[:length]}..."

    def _on_alert_double_click(self, _event) -> None:
        selected = self.alerts_tree.selection()
        if not selected:
            return
        index = self.alerts_tree.index(selected[0])
        if 0 <= index < len(self.displayed_events):
            show_event_details(self, self.displayed_events[index])

    def refresh_baseline(self, silent: bool = False) -> None:
        try:
            contains = self.baseline_contains.get().strip() or None
            limit_value = self.baseline_limit.get().strip()
            limit = int(limit_value) if limit_value else None
            self.baseline_records = run_load_baseline(
                self._config_path(),
                contains=contains,
                limit=limit,
            )
            self._populate_baseline()
            if not silent:
                self._log(f"Loaded {len(self.baseline_records)} baseline record(s).")
        except (ConfigError, DatabaseError, FIMError) as error:
            if not silent:
                messagebox.showerror("Load baseline", str(error))
            self._log(f"ERROR: {error}")
        except ValueError:
            messagebox.showerror("Load baseline", "Limit must be a number.")

    def _populate_baseline(self) -> None:
        self.baseline_tree.delete(*self.baseline_tree.get_children())
        full_hash = self.baseline_full_hash.get()
        self.summary_cards["BASELINE"].configure(text=str(len(self.baseline_records)))
        for record in self.baseline_records:
            self.baseline_tree.insert("", END, values=baseline_display_row(record, full_hash=full_hash))

    def browse_verify_file(self) -> None:
        path = filedialog.askopenfilename(title="Select file to verify")
        if path:
            self.verify_path.set(path)

    def verify_file_action(self) -> None:
        path = self.verify_path.get().strip()
        if not path:
            messagebox.showerror("Verify", "File path is required.")
            return

        def worker():
            return run_verify(self._config_path(), path)

        def on_success(result) -> None:
            self.verify_result.delete("1.0", END)
            lines = [
                f"Status: {result.status}",
                f"Path: {result.path}",
                f"Description: {result.description}",
            ]
            if result.old_hash:
                lines.append(f"Old hash: {result.old_hash}")
            if result.new_hash:
                lines.append(f"New hash: {result.new_hash}")
            for event in result.events:
                lines.append(f"- {event.severity} / {event.event_type}: {event.description}")
            self.verify_result.insert("1.0", "\n".join(lines))
            show_verify_result(self, result)

        self._run_async("Verify file", worker, on_success)

    def browse_add_file(self) -> None:
        path = filedialog.askopenfilename(title="Select file to add")
        if path:
            self.add_path.set(path)

    def browse_add_dir(self) -> None:
        path = filedialog.askdirectory(title="Select directory to add")
        if path:
            self.add_path.set(path)
            self.add_recursive.set(True)

    def add_to_baseline_action(self) -> None:
        path = self.add_path.get().strip()
        if not path:
            messagebox.showerror("Add to baseline", "Path is required.")
            return

        def worker():
            return run_add_baseline(
                self._config_path(),
                path,
                recursive=self.add_recursive.get(),
                force=self.add_force.get(),
                reason=self.add_reason.get().strip() or None,
            )

        def on_success(result: AddBaselineActionResult) -> None:
            self.add_summary.delete("1.0", END)
            self.add_summary.insert("1.0", result.message)
            self.refresh_baseline(silent=True)

        self._run_async("Add to baseline", worker, on_success)

    def export_json_action(self) -> None:
        if not self.displayed_events and not self.all_events:
            try:
                self.all_events = run_load_events(self._config_path())
                self.apply_alert_filters(silent=True)
            except (ConfigError, DatabaseError, FIMError) as error:
                messagebox.showerror("Export JSON", str(error))
                return
        events = self.displayed_events or self.all_events
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialdir="reports",
            filetypes=[("JSON", "*.json")],
        )
        if not path:
            return

        def worker():
            return run_export_json(events, path)

        self._run_async("Export JSON", worker)

    def export_html_action(self) -> None:
        if not self.all_events:
            try:
                self.all_events = run_load_events(self._config_path())
                self.apply_alert_filters(silent=True)
            except (ConfigError, DatabaseError, FIMError) as error:
                messagebox.showerror("Export HTML", str(error))
                return
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            initialdir="reports",
            filetypes=[("HTML", "*.html")],
        )
        if not path:
            return

        events = self.displayed_events or self.all_events

        def worker():
            return run_export_html_report(self._config_path(), path, events=events)

        self._run_async("Export HTML", worker)


def launch_gui(default_config: str = "config.example.yaml") -> None:
    """Start the FIM graphical interface."""
    app = FIMGuiApp(default_config=default_config)
    app.mainloop()
