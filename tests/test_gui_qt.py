"""Qt front-end checks; skipped when PySide6 or a display is unavailable."""

from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("tkinter")

from PySide6.QtWidgets import QApplication  # noqa: E402

if not os.environ.get("DISPLAY") and not os.environ.get("QT_QPA_PLATFORM"):
    pytest.skip("no display for Qt", allow_module_level=True)

from argus import gui, gui_qt  # noqa: E402


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication([])
    instance.setStyleSheet(gui_qt.STYLESHEET)
    return instance


@pytest.fixture
def window(app, tmp_path):
    win = gui_qt.ArgusWindow()
    report = {
        "target": "/src",
        "summary": {"by_severity": {"high": 2, "medium": 1}, "status": "findings",
                    "total": 3, "by_kind": {"sast": 2, "sca": 1}},
        "findings": [
            {"id": "1", "kind": "sast", "rule_id": "java-sqli-jdbc", "severity": "high",
             "cwe": "CWE-89", "location": {"file": "A.java", "start_line": 7},
             "message": "sql"},
            {"id": "2", "kind": "sast", "rule_id": "python-weak-hash", "severity": "medium",
             "cwe": "CWE-328", "location": {"file": "app.py", "start_line": 10},
             "message": "md5"},
            {"id": "3", "kind": "sca", "rule_id": "CVE-2021-44228", "severity": "high",
             "cwe": "CWE-20", "package": {"name": "log4j-core", "version": "2.14.1",
                                          "purl": "pkg:maven/log4j-core@2.14.1"},
             "location": {"file": "pom.xml"}, "message": "rce"},
        ],
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    win._load_report(str(path))
    yield win
    win.close()


def test_backend_selection_prefers_qt(monkeypatch):
    monkeypatch.setattr(gui, "_qt_available", lambda: True)
    called = {}
    monkeypatch.setattr(gui_qt, "main", lambda argv=None: called.setdefault("qt", 0))
    assert gui.main([]) == 0
    assert "qt" in called


def test_qt_main_reports_missing_display(monkeypatch, capsys):
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "QT_QPA_PLATFORM"):
        monkeypatch.delenv(name, raising=False)
    assert gui_qt.main([]) == 2
    assert "cannot open a display" in capsys.readouterr().err


def test_tk_flag_forces_tk(monkeypatch):
    monkeypatch.setattr(gui, "_qt_available", lambda: True)
    monkeypatch.setattr(gui, "ArgusApp", lambda: type("A", (), {"mainloop": lambda s: None})())
    monkeypatch.setattr(gui_qt, "main", lambda argv=None: pytest.fail("qt must not start"))
    assert gui.main(["--tk"]) == 0


def test_report_loads_rows_and_counts(window):
    assert window.table.rowCount() == 3
    assert window.chips["high"].text() == "high  2"
    assert window.chips["medium"].text() == "medium  1"


def test_severity_chip_filters_rows(window):
    window._toggle_severity("medium")
    assert window.table.rowCount() == 1
    window._toggle_severity("medium")
    assert window.table.rowCount() == 3


def test_search_and_cwe_filter(window):
    window.search_edit.setText("log4j")
    assert window.table.rowCount() == 1
    window.search_edit.clear()
    window.cwe_combo.setCurrentText("CWE-328")
    assert window.table.rowCount() == 1


def test_grouping_adds_header_rows(window):
    window.group_combo.setCurrentText("kind")
    # two group headers (sast, sca) plus three findings
    assert window.table.rowCount() == 5


def test_selection_fills_details_card(window):
    window.table.selectRow(0)
    index = window._selected_index()
    assert index is not None
    assert window.findings[index]["rule_id"] in window.details.toPlainText()


def test_cwe_tab_lists_catalog(window):
    assert window.cwe_list.topLevelItemCount() > 0
