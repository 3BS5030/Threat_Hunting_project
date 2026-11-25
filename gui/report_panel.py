"""Report tree view with a JSON export action."""

from __future__ import annotations

import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any


class ReportPanel(ttk.Frame):
    """Display findings for the most recently completed hunt."""

    def __init__(self, parent: Any) -> None:
        super().__init__(parent)
        self.current_name = ""
        self.current_report: dict[str, Any] = {}

        toolbar = ttk.Frame(self, padding=(4, 4))
        toolbar.pack(fill=tk.X)
        self.title = ttk.Label(toolbar, text="No report yet", font=("TkDefaultFont", 11, "bold"))
        self.title.pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Save JSON", command=self.save_report).pack(side=tk.RIGHT)

        body = ttk.Frame(self)
        body.pack(fill=tk.BOTH, expand=True)

        columns = ("rule", "severity", "technique", "target")
        self.tree = ttk.Treeview(body, columns=columns, show="headings", height=12)
        for column, heading, width in zip(
            columns, ("Rule", "Severity", "ATT&CK", "Target"), (210, 90, 130, 420)
        ):
            self.tree.heading(column, text=heading)
            self.tree.column(column, width=width, anchor=tk.W)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        scrollbar = ttk.Scrollbar(body, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.detail = tk.Text(self, height=10, wrap=tk.WORD)
        self.detail.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        self.detail.insert("1.0", "Select a finding to see the matching evidence.")

    def show_report(self, name: str, report: dict[str, Any]) -> None:
        self.current_name = name
        self.current_report = report
        findings = report.get("findings", [])
        self.title.config(text=f"{name} - {len(findings)} finding(s)")

        self.tree.delete(*self.tree.get_children())
        for index, finding in enumerate(findings):
            self.tree.insert(
                "",
                tk.END,
                iid=str(index),
                values=(
                    finding.get("rule", ""),
                    finding.get("severity", "info"),
                    finding.get("technique", ""),
                    finding.get("target", ""),
                ),
            )

        self.detail.delete("1.0", tk.END)
        self.detail.insert(
            "1.0",
            json.dumps(report, indent=2, ensure_ascii=False) if findings else "No findings.",
        )

    def show_error(self, name: str, message: str) -> None:
        self.current_name = name
        self.current_report = {}
        self.tree.delete(*self.tree.get_children())
        self.title.config(text=f"{name} - hunt failed")
        self.detail.delete("1.0", tk.END)
        self.detail.insert("1.0", message)

    def _on_select(self, _event: Any) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        index = int(selection[0])
        findings = self.current_report.get("findings", [])
        if 0 <= index < len(findings):
            self.detail.delete("1.0", tk.END)
            self.detail.insert(
                "1.0", json.dumps(findings[index], indent=2, ensure_ascii=False)
            )

    def save_report(self) -> None:
        if not self.current_report:
            messagebox.showinfo("No report", "Run a hunt before saving.")
            return
        path = filedialog.asksaveasfilename(
            title="Save hunt report",
            defaultextension=".json",
            initialfile=f"{self.current_name or 'report'}_report.json",
            filetypes=(("JSON", "*.json"), ("All files", "*.*")),
        )
        if not path:
            return
        try:
            Path(path).write_text(
                json.dumps(self.current_report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc))
