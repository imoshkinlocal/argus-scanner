#!/usr/bin/env python3
"""Launch the argus desktop GUI from a source checkout.

    ./argus-gui.py

The project virtualenv (``.venv``) is used when present, because scans started
from the GUI run the Java engine and Semgrep from the same interpreter.
"""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV_PYTHON = os.path.join(ROOT, ".venv", "bin", "python")


def _reexec_in_venv() -> None:
    """Restart under the project virtualenv unless we already run inside it."""
    if not os.path.isfile(VENV_PYTHON):
        return
    if os.path.realpath(sys.executable) == os.path.realpath(VENV_PYTHON):
        return
    if os.environ.get("ARGUS_GUI_REEXEC"):
        return
    os.environ["ARGUS_GUI_REEXEC"] = "1"
    os.execv(VENV_PYTHON, [VENV_PYTHON, os.path.abspath(__file__), *sys.argv[1:]])


def main() -> int:
    _reexec_in_venv()
    sys.path.insert(0, ROOT)
    from argus.gui import main as gui_main

    return gui_main()


if __name__ == "__main__":
    raise SystemExit(main())
