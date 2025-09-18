import os
import sys


def _set_tk_env(base_dir: str) -> None:
    candidates = [
        os.path.join(base_dir, "tcl", "tcl8.7"),
        os.path.join(base_dir, "tcl", "tcl8.6"),
    ]
    for cand in candidates:
        if os.path.isdir(cand):
            os.environ.setdefault("TCL_LIBRARY", cand)
            break

    candidates = [
        os.path.join(base_dir, "tcl", "tk8.7"),
        os.path.join(base_dir, "tcl", "tk8.6"),
    ]
    for cand in candidates:
        if os.path.isdir(cand):
            os.environ.setdefault("TK_LIBRARY", cand)
            break


# When running as onefile, PyInstaller extracts to _MEIPASS
base = getattr(sys, "_MEIPASS", None)
if base:
    _set_tk_env(base)

