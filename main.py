"""Launch the VM threat-hunting GUI."""

import tkinter as tk

from gui.app import App


def main() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
