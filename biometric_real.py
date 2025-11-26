import os
import subprocess
import pathlib

HELPER_PATH = str(pathlib.Path(__file__).with_name("biometric_helper"))


def require_biometric_auth():
    """
    Require real macOS biometric/device authentication via the Swift helper.

    If auth succeeds -> return.
    If it fails/unavailable -> raise PermissionError.
    """
    if not os.path.exists(HELPER_PATH):
        raise PermissionError("Biometric helper not found. Build 'biometric_helper' first.")

    result = subprocess.run(
        [HELPER_PATH],
        capture_output=True,
        text=True
    )

    if result.returncode == 0 and "OK" in result.stdout:
        return

    raise PermissionError(
        "Biometric/device authentication failed or is unavailable: "
        + (result.stderr.strip() or "no further details")
    )