"""Main application window, background event queue and UI polling."""

from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Any, Callable

from gui.ai_panel import AiPanel
from gui.report_panel import ReportPanel
from gui.vm_card import VmCard, make_vm_card
from hunting.engine import hunt_vm

ROOT_DIR = Path(__file__).resolve().parent.parent


def _load_json(name: str) -> Any:
    with (ROOT_DIR / name).open(encoding="utf-8") as handle:
        return json.load(handle)


class App:
    """Tkinter shell that keeps long-running hunts off the UI thread."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("VM Threat Hunter")
        self.root.geometry("1180x720")
        self.root.minsize(900, 600)

        self.vms: list[dict[str, Any]] = _load_json("vms.json").get("vms", [])
        self.baseline: dict[str, Any] = _load_json("baseline.json")
        self.events: queue.Queue[dict[str, Any]] = queue.Queue()
        self.cards: dict[str, VmCard] = {}
        self.reports: dict[str, dict[str, Any]] = {}

        self._build_ui()
        self.poll_queue()

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        sidebar = ttk.LabelFrame(main, text="Virtual machines", padding=8)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        sidebar.configure(width=280)
        sidebar.pack_propagate(False)

        self.canvas = tk.Canvas(sidebar, highlightthickness=0)
        scrollbar = ttk.Scrollbar(sidebar, orient=tk.VERTICAL, command=self.canvas.yview)
        self.card_frame = ttk.Frame(self.canvas)
        self.card_frame.bind(
            "<Configure>",
            lambda event: self.canvas.configure(scrollregion=self.canvas.bbox("all")),
        )
        self.canvas.create_window((0, 0), window=self.card_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        on_hunt: Callable[[dict[str, Any]], None] = self.start_hunt
        for vm in self.vms:
            name = vm.get("name", "unnamed")
            self.cards[name] = make_vm_card(self.card_frame, vm, on_hunt)

        notebook = ttk.Notebook(main)
        notebook.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.report_panel = ReportPanel(notebook)
        notebook.add(self.report_panel, text="Report")

        provider: Callable[[], dict[str, Any]] = lambda: self.report_panel.current_report
        self.ai_panel = AiPanel(notebook, provider)
        notebook.add(self.ai_panel, text="AI Assistant")

        self.status = ttk.Label(self.root, text="Ready", anchor=tk.W, padding=(10, 4))
        self.status.pack(fill=tk.X)

    def start_hunt(self, vm: dict[str, Any]) -> None:
        name = vm.get("name", "unnamed")
        card = self.cards.get(name)
        if card is not None:
            card["status_label"].config(text="Hunting...")
            card["hunt_button"].config(state=tk.DISABLED)
        self.status.config(text=f"Hunting {name}...")
        threading.Thread(
            target=self._run_hunt, args=(vm,), daemon=True
        ).start()

    def _run_hunt(self, vm: dict[str, Any]) -> None:
        try:
            report = hunt_vm(vm, self.baseline)
            self.events.put(
                {"type": "report", "vm": vm.get("name", "unnamed"), "report": report}
            )
        except Exception as exc:  # keep the worker thread from dying silently
            self.events.put(
                {
                    "type": "error",
                    "vm": vm.get("name", "unnamed"),
                    "message": f"{type(exc).__name__}: {exc}",
                }
            )

    def poll_queue(self) -> None:
        """Drain worker events on the Tk thread and refresh widgets."""
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break

            name = event.get("vm", "")
            card = self.cards.get(name)
            if event["type"] == "report":
                report = event["report"]
                self.reports[name] = report
                self.report_panel.show_report(name, report)
                if card is not None:
                    card["status_label"].config(
                        text=f"{len(report.get('findings', []))} finding(s)"
                    )
                self.status.config(text=f"Finished {name}")
            elif event["type"] == "error":
                if card is not None:
                    card["status_label"].config(text="Failed")
                self.status.config(text=f"{name}: {event['message']}")
                self.report_panel.show_error(name, event["message"])
            if card is not None:
                card["hunt_button"].config(state=tk.NORMAL)

        self.root.after(120, self.poll_queue)
