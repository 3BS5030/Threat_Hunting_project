"""Optional AI assistant tab (works offline with a local summarizer)."""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable


class AiPanel(ttk.Frame):
    def __init__(
        self, parent: Any, report_provider: Callable[[], dict[str, Any]] | None = None
    ) -> None:
        super().__init__(parent)
        self.report_provider = report_provider or (lambda: {})
        self.busy = False

        self.transcript = tk.Text(self, wrap=tk.WORD, state=tk.DISABLED)
        self.transcript.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        input_row = ttk.Frame(self, padding=4)
        input_row.pack(fill=tk.X)
        self.entry = ttk.Entry(input_row)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.entry.bind("<Return>", lambda _event: self.ask())
        self.ask_button = ttk.Button(input_row, text="Ask", command=self.ask)
        self.ask_button.pack(side=tk.RIGHT, padx=(6, 0))
        self._append("Assistant", "Ask about the current report or ATT&CK techniques.")

    def ask(self) -> None:
        question = self.entry.get().strip()
        if not question or self.busy:
            return
        self.entry.delete(0, tk.END)
        self.busy = True
        self.ask_button.config(state=tk.DISABLED)
        self._append("You", question)
        report = dict(self.report_provider())
        threading.Thread(
            target=self._worker, args=(question, report), daemon=True
        ).start()

    def _worker(self, question: str, report: dict[str, Any]) -> None:
        try:
            from ai.agent import answer

            response = answer(question, report)
        except Exception as exc:  # the AI tab is optional
            response = f"AI assistant unavailable: {type(exc).__name__}: {exc}"
        self.after(0, lambda: self._finish(response))

    def _finish(self, response: str) -> None:
        self.busy = False
        self.ask_button.config(state=tk.NORMAL)
        self._append("Assistant", response)

    def _append(self, speaker: str, text: str) -> None:
        self.transcript.config(state=tk.NORMAL)
        self.transcript.insert(tk.END, f"{speaker}: {text}\n\n")
        self.transcript.see(tk.END)
        self.transcript.config(state=tk.DISABLED)
