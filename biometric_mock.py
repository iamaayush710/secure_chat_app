import tkinter as tk
from tkinter import simpledialog


def get_biometric_secret_gui(parent=None) -> str:
    """
    Simulated biometric authentication via GUI.

    Realistic model:
      - Biometric (finger/face) runs at OS level.
      - On success, it unlocks a protected secret.
      - That secret (not the biometric itself) is used to derive encryption keys.

    Here:
      - We prompt for a secret phrase representing that unlocked secret.
    """
    owns_root = False

    if parent is None:
        root = tk.Tk()
        root.withdraw()
        parent = root
        owns_root = True

    secret = simpledialog.askstring(
        "Biometric Verification",
        "Scan fingerprint / face (simulated)\n\nEnter your private unlock secret:",
        show="*",
        parent=parent,
    )

    if owns_root:
        parent.destroy()

    if not secret:
        raise PermissionError("Biometric authentication failed or was cancelled.")

    return secret
