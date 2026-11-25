"""Small widget bundle shown for each configured VM."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, TypedDict


class VmCard(TypedDict):
    frame: ttk.Frame
    name_label: ttk.Label
    status_label: ttk.Label
    hunt_button: ttk.Button


def make_vm_card(
    parent: Any, vm: dict[str, Any], on_hunt: Callable[[dict[str, Any]], None]
) -> VmCard:
    """Create the card widgets for one VM and return their handles."""
    name = vm.get("name", "unnamed")
    host = vm.get("host", "")
    enabled = vm.get("enabled", True)

    frame = ttk.LabelFrame(parent, text=name, padding=8)
    frame.pack(fill=tk.X, pady=4)

    name_label = ttk.Label(frame, text=f"{vm.get('os', 'unknown')} @ {host}")
    name_label.pack(anchor=tk.W)

    status_label = ttk.Label(
        frame, text="Idle" if enabled else "Disabled", foreground="#666666"
    )
    status_label.pack(anchor=tk.W, pady=(2, 6))

    hunt_button = ttk.Button(
        frame,
        text="Hunt",
        command=lambda: on_hunt(vm),
        state=tk.NORMAL if enabled else tk.DISABLED,
    )
    hunt_button.pack(fill=tk.X)

    return {
        "frame": frame,
        "name_label": name_label,
        "status_label": status_label,
        "hunt_button": hunt_button,
    }
