"""Qt (PySide6) front-end for argus, laid out like an application security console.

Same behaviour as the Tk window in :mod:`argus.gui`: the scan runs as the
``argus scan`` child process and the JSON report is loaded back for browsing.
Toolkit-independent logic lives in :mod:`argus.gui_core`.
"""

from __future__ import annotations

import json
import os
import queue
import shlex
import subprocess
import sys
import threading
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QFrame, QGridLayout,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
    QProgressBar, QPushButton, QScrollArea, QSplitter, QStackedWidget, QTableWidget,
    QTableWidgetItem, QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from . import __version__, cwe as cwe_catalog
from .gui_core import (
    ACCENT, ACCENT_DARK, BORDER, CONSOLE_BG, CONSOLE_FG, DEB_SUITE_CHOICES, DEP_COLUMNS,
    DEP_HEADINGS, EXIT_MEANING, FAIL_ON_CHOICES, HELP_TEXT, INK, MUTED, OK, ERROR, WARN,
    PACKAGE_ROOT, RANGE_CHOICES, RESULT_COLUMNS, RESULT_HEADINGS, SEVERITY_COLORS,
    SEVERITY_ORDER, _SEVERITY_PRIORITY, build_scan_command, default_sort_desc,
    dependency_rows, finding_row, format_cwe_entry, format_finding, sort_finding_indices,
)

STYLESHEET = f"""
QMainWindow, QWidget#root {{ background: #eef2f9; }}
QFrame#header {{ background: #111827; }}
QLabel#title {{ color: #ffffff; font-size: 22px; font-weight: 700; }}
QLabel#subtitle {{ color: #93c5fd; font-size: 12px; }}
QLabel#version {{ color: #ffffff; background: {ACCENT_DARK}; border-radius: 4px;
                 padding: 3px 10px; font-size: 11px; }}
QFrame#sidebar {{ background: #0f172a; }}
QPushButton#nav {{ color: #cbd5e1; background: transparent; border: none;
                  text-align: left; padding: 10px 16px; font-size: 13px; }}
QPushButton#nav:hover {{ background: #1e293b; }}
QPushButton#nav:checked {{ background: {ACCENT}; color: #ffffff; font-weight: 600; }}
QFrame.card {{ background: #ffffff; border: 1px solid {BORDER}; border-radius: 8px; }}
QLabel.section {{ color: {ACCENT_DARK}; font-weight: 700; font-size: 13px; }}
QLabel.muted {{ color: {MUTED}; }}
QPushButton {{ background: #e0e7ff; color: {ACCENT_DARK}; border: 1px solid #c7d2fe;
              border-radius: 6px; padding: 6px 12px; font-weight: 600; }}
QPushButton:hover {{ background: #c7d2fe; }}
QPushButton:disabled {{ color: #94a3b8; background: #eef2f9; }}
QPushButton#primary {{ background: {ACCENT}; color: #ffffff; border: 1px solid {ACCENT_DARK};
                      padding: 9px 18px; }}
QPushButton#primary:hover {{ background: {ACCENT_DARK}; }}
QPushButton#stop {{ background: #fee2e2; color: {ERROR}; border: 1px solid #fecaca; }}
QLineEdit, QComboBox {{ background: #ffffff; border: 1px solid {BORDER}; border-radius: 6px;
                       padding: 5px 8px; }}
QTableWidget, QTreeWidget, QTextBrowser, QListWidget {{ background: #ffffff;
    border: 1px solid {BORDER}; border-radius: 8px; gridline-color: #e2e8f0; }}
QHeaderView::section {{ background: {ACCENT_DARK}; color: #ffffff; padding: 6px;
                       border: none; font-weight: 600; }}
QPlainTextEdit#log {{ background: {CONSOLE_BG}; color: {CONSOLE_FG}; border: 1px solid #1e293b;
                     border-radius: 8px; font-family: monospace; }}
QProgressBar {{ border: none; background: #dbe3f0; border-radius: 3px; height: 6px; }}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 3px; }}
QPushButton#chip {{ border-radius: 12px; padding: 4px 12px; font-size: 12px; color: #ffffff;
                   border: 2px solid transparent; }}
QPushButton#chip:checked {{ border: 2px solid {INK}; }}
QLabel#status {{ color: #ffffff; padding: 6px 14px; font-weight: 600; }}
"""

CHIP_COLORS = {name: SEVERITY_COLORS[name]["chip"] for name in SEVERITY_ORDER}


def _card(title: str = "") -> Tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setProperty("class", "card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(14, 12, 14, 12)
    if title:
        label = QLabel(title)
        label.setProperty("class", "section")
        layout.addWidget(label)
    return frame, layout


def _muted(text: str) -> QLabel:
    label = QLabel(text)
    label.setProperty("class", "muted")
    label.setWordWrap(True)
    return label


def _row_color(severity: str) -> Optional[Tuple[QColor, QColor]]:
    colors = SEVERITY_COLORS.get(severity)
    if not colors:
        return None
    return QColor(colors["row"]), QColor(colors["fg"])


class ArgusWindow(QMainWindow):
    """Main window: navigation sidebar, scan form, findings console, card."""

    _log_signal = Signal(str)
    _done_signal = Signal(int)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("argus — SAST + SCA")
        self.resize(1360, 880)
        self.setMinimumSize(1100, 720)

        self.process: Optional[subprocess.Popen] = None
        self.report_path = ""
        self.report: Dict[str, Any] = {}
        self.findings: List[Dict[str, Any]] = []
        self.dep_paths: Dict[str, str] = {}
        self.dep_iids: Dict[str, Any] = {}
        self._results_sort: Optional[Tuple[str, bool]] = None
        self._severity_filter: set = set()
        self._cwe_usage: Dict[int, int] = {}
        self._cwe_entries: Dict[str, "cwe_catalog.CWEEntry"] = {}

        self._build_ui()
        self._log_signal.connect(self._log)
        self._done_signal.connect(self._finished)
        self._load_defaults()
        self._fill_summary({})
        self._fill_dependencies({})
        self._update_cwe_usage({})

    # --------------------------------------------------------------- layout

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._build_header())

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_sidebar())

        self.pages = QStackedWidget()
        self.pages.setContentsMargins(0, 0, 0, 0)
        self.page_scan = self._build_scan_page()
        self.page_results = self._build_results_page()
        self.page_deps = self._build_deps_page()
        self.page_cwe = self._build_cwe_page()
        self.page_help = self._build_help_page()
        for page in (self.page_scan, self.page_results, self.page_deps,
                     self.page_cwe, self.page_help):
            self.pages.addWidget(page)
        body.addWidget(self.pages, 1)
        outer.addLayout(body, 1)

        self.status = QLabel("●  Готов к работе")
        self.status.setObjectName("status")
        self._set_status_tone("idle")
        outer.addWidget(self.status)

        self.setCentralWidget(root)
        self._switch_page(0)

    def _build_header(self) -> QWidget:
        header = QFrame()
        header.setObjectName("header")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(18, 12, 18, 12)
        title = QLabel("argus")
        title.setObjectName("title")
        subtitle = QLabel("SAST + SCA · CycloneDX / SPDX · OWASP Top 10")
        subtitle.setObjectName("subtitle")
        version = QLabel(f"v{__version__}")
        version.setObjectName("version")
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addStretch(1)
        layout.addWidget(version)
        return header

    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(200)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 16, 0, 16)
        layout.setSpacing(2)
        self.nav_buttons: List[QPushButton] = []
        for index, text in enumerate(("Сканирование", "Результаты", "Зависимости",
                                      "Справочник CWE", "Справка")):
            button = QPushButton(text)
            button.setObjectName("nav")
            button.setCheckable(True)
            button.setCursor(Qt.PointingHandCursor)
            button.clicked.connect(lambda _checked=False, i=index: self._switch_page(i))
            layout.addWidget(button)
            self.nav_buttons.append(button)
        layout.addStretch(1)
        self.report_label = _muted("Отчёт не загружен")
        self.report_label.setContentsMargins(16, 0, 16, 0)
        layout.addWidget(self.report_label)
        return sidebar

    def _switch_page(self, index: int) -> None:
        for position, button in enumerate(self.nav_buttons):
            button.setChecked(position == index)
        self.pages.setCurrentIndex(index)

    # --------------------------------------------------------------- scan page

    def _build_scan_page(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)
        page = QScrollArea()
        page.setWidgetResizable(True)
        page.setFrameShape(QFrame.NoFrame)
        page.setWidget(content)

        source, source_layout = _card("1 · Каталог с исходниками")
        row = QHBoxLayout()
        self.target_edit = QLineEdit()
        pick = QPushButton("Выбрать каталог…")
        pick.clicked.connect(self._pick_target)
        row.addWidget(self.target_edit, 1)
        row.addWidget(pick)
        source_layout.addLayout(row)
        source_layout.addWidget(_muted("Рекурсивный обход. SAST — исходный код, SCA — "
                                       "манифесты зависимостей; служебные каталоги пропускаются."))
        layout.addWidget(source)

        options, options_layout = _card("2 · Что проверять и как")
        toggles = QGridLayout()
        self.sast_check = QCheckBox("SAST — анализ кода")
        self.sast_check.setChecked(True)
        self.sca_check = QCheckBox("SCA — уязвимые зависимости (OSV)")
        self.sca_check.setChecked(True)
        self.secrets_check = QCheckBox("Секреты")
        self.secrets_check.setChecked(True)
        self.iac_check = QCheckBox("IaC (Docker/K8s/Terraform)")
        self.iac_check.setChecked(True)
        self.owasp_check = QCheckBox("OWASP Top 10")
        self.owasp_check.setChecked(True)
        self.dev_check = QCheckBox("dev/test-зависимости")
        self.offline_check = QCheckBox("Офлайн: только локальная база OSV")
        for index, widget in enumerate((self.sast_check, self.sca_check, self.secrets_check,
                                        self.iac_check, self.owasp_check, self.dev_check,
                                        self.offline_check)):
            toggles.addWidget(widget, index // 4, index % 4)
        options_layout.addLayout(toggles)

        form = QFormLayout()
        form.setHorizontalSpacing(12)
        self.fail_combo = QComboBox()
        self.fail_combo.addItems(FAIL_ON_CHOICES)
        self.fail_combo.setCurrentText("high")
        self.range_combo = QComboBox()
        self.range_combo.addItems(RANGE_CHOICES)
        self.exclude_edit = QLineEdit()
        self.exclude_edit.setPlaceholderText("подстроки путей через запятую")
        self.owasp_version_combo = QComboBox()
        self.owasp_version_combo.addItems(("2017", "2021", "2025"))
        self.owasp_version_combo.setCurrentText("2021")
        self.owasp_file_edit = QLineEdit()
        self.config_edit = QLineEdit()
        self.baseline_edit = QLineEdit()
        self.fail_new_check = QCheckBox("Только новые находки (нужен baseline)")
        form.addRow("Порог (--fail-on):", self.fail_combo)
        form.addRow("Диапазоны версий:", self.range_combo)
        form.addRow("Исключения:", self.exclude_edit)
        form.addRow("Конфиг argus.toml:", self._with_picker(self.config_edit, "argus.toml"))
        form.addRow("Baseline:", self._with_picker(self.baseline_edit, "baseline.json"))
        form.addRow("OWASP, редакция:", self.owasp_version_combo)
        form.addRow("OWASP, свой файл:", self._with_picker(self.owasp_file_edit,
                                                          "Справочник OWASP Top 10"))
        form.addRow("", self.fail_new_check)
        options_layout.addLayout(form)
        layout.addWidget(options)

        debian, debian_layout = _card("2b · Пакеты Debian/Ubuntu (dpkg и .deb)")
        debian_form = QFormLayout()
        debian_form.setHorizontalSpacing(12)
        self.deb_root_edit = QLineEdit()
        self.deb_status_edit = QLineEdit()
        self.deb_files_edit = QLineEdit()
        self.deb_suite_combo = QComboBox()
        self.deb_suite_combo.setEditable(True)
        self.deb_suite_combo.addItems(("",) + DEB_SUITE_CHOICES)
        debian_form.addRow("Корень системы:", self._with_directory_picker(self.deb_root_edit))
        debian_form.addRow("Статус dpkg:", self._with_picker(self.deb_status_edit, "status"))
        debian_form.addRow("Файлы .deb:", self.deb_files_edit)
        debian_form.addRow("Релиз:", self.deb_suite_combo)
        debian_layout.addLayout(debian_form)
        debian_layout.addWidget(_muted(
            "Без релиза отдельные .deb и status-файлы пропускаются с предупреждением — "
            "иначе можно получить чужие исправления."))
        layout.addWidget(debian)

        output, output_layout = _card("3 · Куда сохранить отчёты")
        out_form = QFormLayout()
        self.output_edit = QLineEdit(os.path.join(os.getcwd(), "argus-report.json"))
        self.summary_edit = QLineEdit(os.path.join(os.getcwd(), "argus-report.md"))
        out_form.addRow("JSON (для автоматики):",
                        self._with_save_picker(self.output_edit, "json"))
        out_form.addRow("Markdown (для человека):",
                        self._with_save_picker(self.summary_edit, "md"))
        output_layout.addLayout(out_form)
        layout.addWidget(output)

        actions = QHBoxLayout()
        self.run_button = QPushButton("▶  Запустить сканирование")
        self.run_button.setObjectName("primary")
        self.run_button.clicked.connect(self._start)
        self.stop_button = QPushButton("■  Остановить")
        self.stop_button.setObjectName("stop")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self._stop)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        self.progress.setFixedWidth(240)
        actions.addWidget(self.run_button)
        actions.addWidget(self.stop_button)
        actions.addWidget(self.progress)
        actions.addStretch(1)
        layout.addLayout(actions)

        log_card, log_layout = _card("Журнал")
        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("log")
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(200)
        log_layout.addWidget(self.log_view)
        layout.addWidget(log_card)
        layout.addStretch(1)
        return page

    def _with_picker(self, edit: QLineEdit, title: str) -> QWidget:
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        button = QPushButton("…")
        button.setFixedWidth(36)
        button.clicked.connect(lambda: self._pick_file(edit, title))
        row.addWidget(edit, 1)
        row.addWidget(button)
        return holder

    def _with_directory_picker(self, edit: QLineEdit) -> QWidget:
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        button = QPushButton("Выбрать…")
        button.clicked.connect(lambda: self._pick_directory(edit))
        row.addWidget(edit, 1)
        row.addWidget(button)
        return holder

    def _with_save_picker(self, edit: QLineEdit, extension: str) -> QWidget:
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        button = QPushButton("…")
        button.setFixedWidth(36)
        button.clicked.connect(lambda: self._pick_save(edit, extension))
        row.addWidget(edit, 1)
        row.addWidget(button)
        return holder

    def _load_defaults(self) -> None:
        self.target_edit.setText("")

    # --------------------------------------------------------------- results page

    def _build_results_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        bar = QHBoxLayout()
        open_button = QPushButton("Открыть JSON-отчёт…")
        open_button.clicked.connect(self._open_report)
        compare_button = QPushButton("Сравнить с отчётом…")
        compare_button.clicked.connect(self._compare_report)
        self.details_button = QPushButton("Развернуть детали")
        self.details_button.clicked.connect(self._toggle_details)
        bar.addWidget(open_button)
        bar.addWidget(compare_button)
        bar.addWidget(self.details_button)
        bar.addStretch(1)
        layout.addLayout(bar)

        filters = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Поиск по правилу, CWE, пакету, файлу…")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self._render_results)
        self.kind_combo = QComboBox()
        self.kind_combo.addItems(("all", "sast", "sca"))
        self.kind_combo.currentIndexChanged.connect(self._render_results)
        self.cwe_combo = QComboBox()
        self.cwe_combo.addItem("all")
        self.cwe_combo.currentIndexChanged.connect(self._render_results)
        self.group_combo = QComboBox()
        self.group_combo.addItems(("none", "severity", "kind", "rule", "cwe", "package"))
        self.group_combo.currentIndexChanged.connect(self._render_results)
        self.new_only_check = QCheckBox("Только новые")
        self.new_only_check.toggled.connect(self._render_results)
        self.suppressed_check = QCheckBox("Suppressed")
        self.suppressed_check.toggled.connect(self._render_results)
        reset = QPushButton("Сбросить")
        reset.clicked.connect(self._reset_filters)
        filters.addWidget(self.search_edit, 2)
        for label, widget in (("Тип:", self.kind_combo), ("CWE:", self.cwe_combo),
                              ("Группировка:", self.group_combo)):
            filters.addWidget(QLabel(label))
            filters.addWidget(widget)
        filters.addWidget(self.new_only_check)
        filters.addWidget(self.suppressed_check)
        filters.addWidget(reset)
        layout.addLayout(filters)

        chips = QHBoxLayout()
        self.chips: Dict[str, QPushButton] = {}
        for severity in SEVERITY_ORDER:
            chip = QPushButton(f"{severity}  0")
            chip.setObjectName("chip")
            chip.setCheckable(True)
            chip.setStyleSheet(f"QPushButton#chip {{ background: {CHIP_COLORS[severity]}; "
                               f"color: #ffffff; }}")
            chip.toggled.connect(lambda _c, s=severity: self._toggle_severity(s))
            chips.addWidget(chip)
            self.chips[severity] = chip
        chips.addStretch(1)
        self.filter_label = _muted("")
        chips.addWidget(self.filter_label)
        layout.addLayout(chips)

        self.summary_view = QTextBrowser()
        self.summary_view.setMaximumHeight(150)
        layout.addWidget(self.summary_view)

        splitter = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, len(RESULT_COLUMNS))
        self.table.setHorizontalHeaderLabels([RESULT_HEADINGS[c] for c in RESULT_COLUMNS])
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(False)
        self.table.setSortingEnabled(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        header.sectionClicked.connect(self._sort_results_by_index)
        self.table.itemSelectionChanged.connect(self._show_selected)
        self.table.itemDoubleClicked.connect(lambda _item: self._locate_in_dependencies())
        splitter.addWidget(self.table)

        self.details = QTextBrowser()
        self.details.setPlainText("Выберите строку, чтобы увидеть детали находки.")
        splitter.addWidget(self.details)
        splitter.setSizes([520, 300])
        layout.addWidget(splitter, 1)
        return page

    # --------------------------------------------------------------- deps page

    def _build_deps_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 16, 18, 16)
        self.deps_label = QLabel("Отчёт не загружен")
        self.deps_label.setProperty("class", "section")
        layout.addWidget(self.deps_label)
        layout.addWidget(_muted(
            "Рёбра и глубина восстанавливаются только из lock-файлов (Gemfile.lock, "
            "package-lock.json, poetry.lock, uv.lock, composer.lock, Cargo.lock). "
            "Без lock-файла пакеты показаны плоским списком: direct — из манифеста, "
            "depth — неизвестна."))
        self.deps_tree = QTreeWidget()
        self.deps_tree.setHeaderLabels(["Пакет"] + [DEP_HEADINGS[c] for c in DEP_COLUMNS])
        header = self.deps_tree.header()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        self.deps_tree.setColumnWidth(0, 360)
        for column, width in enumerate((130, 120, 100, 80), start=1):
            self.deps_tree.setColumnWidth(column, width)
        layout.addWidget(self.deps_tree, 1)
        return page

    # --------------------------------------------------------------- cwe page

    def _build_cwe_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 16, 18, 16)
        bar = QHBoxLayout()
        self.cwe_label = QLabel("")
        self.cwe_label.setProperty("class", "section")
        self.cwe_search = QLineEdit()
        self.cwe_search.setPlaceholderText("Номер, название, категория…")
        self.cwe_search.textChanged.connect(self._fill_cwe_list)
        open_link = QPushButton("Открыть на cwe.mitre.org")
        open_link.clicked.connect(self._open_cwe_link)
        bar.addWidget(self.cwe_label)
        bar.addWidget(self.cwe_search, 1)
        bar.addWidget(open_link)
        layout.addLayout(bar)
        layout.addWidget(_muted(
            "Встроенный офлайн-справочник: номер, название, категория, последствия и меры "
            "защиты. Незнакомый CWE откроется ссылкой на MITRE."))

        splitter = QSplitter(Qt.Horizontal)
        self.cwe_list = QTreeWidget()
        self.cwe_list.setHeaderLabels(["CWE", "Уязвимость", "Категория", "В отчёте"])
        cwe_header = self.cwe_list.header()
        cwe_header.setStretchLastSection(False)
        cwe_header.setSectionResizeMode(QHeaderView.Interactive)
        cwe_header.setSectionResizeMode(1, QHeaderView.Stretch)
        self.cwe_list.setColumnWidth(0, 90)
        self.cwe_list.setColumnWidth(2, 200)
        self.cwe_list.setColumnWidth(3, 80)
        self.cwe_list.setRootIsDecorated(False)
        self.cwe_list.itemSelectionChanged.connect(self._show_cwe_details)
        self.cwe_list.itemDoubleClicked.connect(lambda _item, _c: self._open_cwe_link())
        splitter.addWidget(self.cwe_list)
        self.cwe_details = QTextBrowser()
        splitter.addWidget(self.cwe_details)
        splitter.setSizes([560, 440])
        layout.addWidget(splitter, 1)
        self._fill_cwe_list()
        return page

    # --------------------------------------------------------------- help page

    def _build_help_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 16, 18, 16)
        view = QPlainTextEdit(HELP_TEXT)
        view.setReadOnly(True)
        layout.addWidget(view)
        return page

    # --------------------------------------------------------------- status & log

    def _set_status_tone(self, tone: str) -> None:
        colors = {"idle": "#334155", "running": ACCENT, "ok": OK, "warn": WARN, "error": ERROR}
        self.status.setStyleSheet(f"QLabel#status {{ background: {colors.get(tone, '#334155')}; }}")

    def _set_status(self, text: str, tone: str = "idle") -> None:
        self.status.setText(f"●  {text}")
        self._set_status_tone(tone)

    def _log(self, line: str) -> None:
        self.log_view.appendPlainText(line)

    # --------------------------------------------------------------- pickers

    def _pick_target(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Каталог с исходниками")
        if chosen:
            self.target_edit.setText(chosen)

    def _pick_file(self, edit: QLineEdit, title: str) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, title, "", "Все файлы (*)")
        if chosen:
            edit.setText(chosen)

    def _pick_directory(self, edit: QLineEdit) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Корень системы (/) или chroot")
        if chosen:
            edit.setText(chosen)

    def _pick_save(self, edit: QLineEdit, extension: str) -> None:
        chosen, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт", edit.text(),
                                                f"{extension.upper()} (*.{extension})")
        if chosen:
            edit.setText(chosen)

    # --------------------------------------------------------------- scan

    def _start(self) -> None:
        target = self.target_edit.text().strip()
        if not target or not os.path.isdir(target):
            QMessageBox.critical(self, "argus", "Укажите существующий каталог с исходниками.")
            return
        if not (self.sast_check.isChecked() or self.sca_check.isChecked()):
            QMessageBox.critical(self, "argus", "Включите хотя бы один режим: SAST или SCA.")
            return
        output = self.output_edit.text().strip()
        if not output:
            QMessageBox.critical(self, "argus", "Укажите путь для JSON-отчёта.")
            return
        baseline = self.baseline_edit.text().strip() or None
        if self.fail_new_check.isChecked() and not baseline:
            QMessageBox.critical(self, "argus",
                                 "Для режима «только новые» укажите baseline-файл.")
            return
        excludes = [item.strip() for item in self.exclude_edit.text().split(",") if item.strip()]
        deb_roots = [self.deb_root_edit.text().strip()] if self.deb_root_edit.text().strip() else []
        deb_status = ([self.deb_status_edit.text().strip()]
                      if self.deb_status_edit.text().strip() else [])
        deb_files = [item.strip() for item in self.deb_files_edit.text().split(",")
                     if item.strip()]
        command = build_scan_command(
            target, output, self.summary_edit.text().strip() or None,
            sast=self.sast_check.isChecked(), sca=self.sca_check.isChecked(),
            include_dev=self.dev_check.isChecked(), offline=self.offline_check.isChecked(),
            fail_on=self.fail_combo.currentText(), range_policy=self.range_combo.currentText(),
            excludes=excludes, config=self.config_edit.text().strip() or None,
            baseline=baseline, fail_on_new=self.fail_new_check.isChecked(),
            secrets=self.secrets_check.isChecked(), iac=self.iac_check.isChecked(),
            deb_roots=deb_roots, deb_status=deb_status, deb_files=deb_files,
            deb_suite=self.deb_suite_combo.currentText().strip() or None,
            owasp=self.owasp_check.isChecked(),
            owasp_version=self.owasp_version_combo.currentText() or "2021",
            owasp_file=self.owasp_file_edit.text().strip() or None)

        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            part for part in (PACKAGE_ROOT, env.get("PYTHONPATH", "")) if part)
        try:
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", env=env)
        except OSError as exc:
            QMessageBox.critical(self, "argus", f"Не удалось запустить argus:\n{exc}")
            return

        self.process = process
        self.report_path = output
        self._clear_report()
        self.log_view.clear()
        self._log("$ " + shlex.join(command))
        self.run_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress.setVisible(True)
        self._set_status("Сканирование выполняется…", "running")
        threading.Thread(target=self._pump, args=(process,), daemon=True).start()

    def _pump(self, process: subprocess.Popen) -> None:
        assert process.stdout is not None
        for line in process.stdout:
            self._log_signal.emit(line.rstrip("\n"))
        self._done_signal.emit(process.wait())

    def _stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self._log("— остановка по запросу пользователя…")
            self._set_status("Остановка…", "warn")
            self.process.terminate()

    def _finished(self, code: int) -> None:
        self.process = None
        self.progress.setVisible(False)
        self.run_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self._log(f"\nКод возврата {code}: {EXIT_MEANING.get(code, 'Сканирование прервано.')}")
        tones = {0: ("Готово: чисто (код 0)", "ok"),
                 1: ("Готово: есть находки (код 1)", "warn"),
                 2: ("Ошибка сканирования (код 2)", "error")}
        text, tone = tones.get(code, ("Сканирование прервано", "warn"))
        self._set_status(text, tone)
        if code in (0, 1) and os.path.isfile(self.report_path):
            self._load_report(self.report_path)
            self._switch_page(1)

    def closeEvent(self, event: Any) -> None:  # noqa: N802 - Qt naming
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
        super().closeEvent(event)

    # --------------------------------------------------------------- report

    def _open_report(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, "JSON-отчёт argus", "",
                                                "JSON (*.json);;Все файлы (*)")
        if chosen:
            self._load_report(chosen)

    def _compare_report(self) -> None:
        if not self.report:
            QMessageBox.information(self, "argus",
                                    "Сначала загрузите или выполните сканирование.")
            return
        chosen, _ = QFileDialog.getOpenFileName(self, "Старый JSON-отчёт для сравнения", "",
                                                "JSON (*.json);;Все файлы (*)")
        if not chosen:
            return
        from .baseline import diff_reports, load_report, render_diff
        try:
            diff = diff_reports(load_report(chosen), self.report,
                                include_suppressed=self.suppressed_check.isChecked(),
                                old_path=chosen, new_path=self.report_path)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "argus", f"Не удалось сравнить отчёты:\n{exc}")
            return
        view = QPlainTextEdit(render_diff(diff, "text"))
        view.setReadOnly(True)
        view.setWindowTitle("argus — сравнение отчётов")
        view.resize(900, 600)
        view.show()
        self._diff_view = view

    def _clear_report(self) -> None:
        self.report = {}
        self.findings = []
        self.table.setRowCount(0)
        self.summary_view.clear()
        self.details.setPlainText("Выберите строку, чтобы увидеть детали находки.")
        self.report_label.setText("Отчёт не загружен")
        self._fill_dependencies({})
        self._update_cwe_usage({})
        self._reset_filters(render=False)
        self._fill_summary({})

    def _load_report(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8") as handle:
                report = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            QMessageBox.critical(self, "argus", f"Не удалось прочитать отчёт:\n{exc}")
            return
        self.findings = list(report.get("findings") or [])
        self.report = report
        target = str(report.get("target") or "")
        self.report_label.setText(f"Цель: {target}" if target else f"Отчёт: {path}")
        self._reset_filters(render=False)
        self._update_cwe_filter_values()
        self._fill_summary(report)
        self._fill_dependencies(report)
        self._update_cwe_usage(report)
        self._render_results()
        self.details.setPlainText("Выберите строку, чтобы увидеть детали находки.")
        if target:
            self._set_status(f"Сканировано: {target}", "idle")

    def _fill_summary(self, report: Dict[str, Any]) -> None:
        summary = report.get("summary") or {}
        by_severity = summary.get("by_severity") or {}
        by_kind = summary.get("by_kind") or {}
        by_owasp = summary.get("by_owasp") or {}
        lines = [
            f"<b>Статус:</b> {summary.get('status', 'нет данных')}",
            f"<b>Находок:</b> {summary.get('total', 0)} · максимальная severity: "
            f"{summary.get('max_severity', 'unknown')}",
            "<b>По severity:</b> " + (", ".join(f"{name} {by_severity[name]}"
                                              for name in SEVERITY_ORDER
                                              if by_severity.get(name)) or "нет"),
            f"<b>По типу:</b> SAST {by_kind.get('sast', 0)} · SCA {by_kind.get('sca', 0)}",
            ("<b>OWASP Top 10 " + str(summary.get("owasp_version") or "") + ":</b> "
             + "  ·  ".join(f"{label} ×{count}" for label, count in by_owasp.items()))
            if by_owasp else "<b>OWASP Top 10:</b> нет",
            f"<b>Инвентарь:</b> {summary.get('packages', 0)} пакетов · "
            f"direct {summary.get('packages_direct', 0)} / "
            f"transitive {summary.get('packages_transitive', 0)}",
            f"<b>Ошибки:</b> {summary.get('errors', 0)}",
        ]
        self.summary_view.setHtml("<br>".join(lines))
        for severity in SEVERITY_ORDER:
            self.chips[severity].setText(f"{severity}  {by_severity.get(severity, 0)}")

    def _toggle_severity(self, severity: str) -> None:
        if severity in self._severity_filter:
            self._severity_filter.discard(severity)
        else:
            self._severity_filter.add(severity)
        self._render_results()

    def _reset_filters(self, render: bool = True) -> None:
        self.search_edit.blockSignals(True)
        self.search_edit.clear()
        self.search_edit.blockSignals(False)
        self.kind_combo.setCurrentText("all")
        self.cwe_combo.setCurrentText("all")
        self.group_combo.setCurrentText("none")
        self.new_only_check.setChecked(False)
        self.suppressed_check.setChecked(False)
        self._severity_filter.clear()
        for chip in self.chips.values():
            chip.setChecked(False)
        self._results_sort = None
        if render:
            self._render_results()

    def _update_cwe_filter_values(self) -> None:
        values = {"all"}
        for finding in self.findings:
            cwe = str(finding.get("cwe") or "")
            values.add(cwe if cwe else "(нет)")
        current = self.cwe_combo.currentText()
        self.cwe_combo.blockSignals(True)
        self.cwe_combo.clear()
        self.cwe_combo.addItems(["all"] + sorted(v for v in values if v != "all"))
        self.cwe_combo.setCurrentText(current if current in values else "all")
        self.cwe_combo.blockSignals(False)

    def _finding_matches(self, finding: Dict[str, Any]) -> bool:
        if finding.get("suppressed") and not self.suppressed_check.isChecked():
            return False
        if self.new_only_check.isChecked() and finding.get("baseline") != "new":
            return False
        severity = str(finding.get("severity") or "unknown")
        if self._severity_filter and severity not in self._severity_filter:
            return False
        kind = self.kind_combo.currentText()
        if kind != "all" and str(finding.get("kind") or "") != kind:
            return False
        cwe_filter = self.cwe_combo.currentText()
        if cwe_filter not in ("", "all"):
            cwe = str(finding.get("cwe") or "")
            if cwe_filter == "(нет)":
                if cwe:
                    return False
            elif cwe != cwe_filter:
                return False
        query = self.search_edit.text().strip().lower()
        if query:
            package = finding.get("package") or {}
            location = finding.get("location") or {}
            haystack = " ".join(str(item) for item in (
                finding.get("rule_id"), finding.get("title"), finding.get("message"),
                finding.get("cwe"), finding.get("cwe_name"), finding.get("cwe_name_ru"),
                finding.get("engine"), finding.get("kind"),
                package.get("name"), package.get("version"), location.get("file"),
                " ".join(finding.get("remediation") or ()), finding.get("suggested_fix"),
            ) if item).lower()
            if not all(word in haystack for word in query.split()):
                return False
        return True

    def _filtered_indices(self) -> List[int]:
        indices = [index for index, finding in enumerate(self.findings)
                   if self._finding_matches(finding)]
        column, descending = self._results_sort or ("", False)
        if not column:
            return indices
        subset = [self.findings[index] for index in indices]
        ordered = sort_finding_indices(subset, column, descending)
        return [indices[position] for position in ordered]

    def _group_key(self, finding: Dict[str, Any]) -> Tuple[str, str]:
        group = self.group_combo.currentText()
        package = finding.get("package") or {}
        if group == "severity":
            value = str(finding.get("severity") or "unknown")
            return value, value
        if group == "kind":
            value = str(finding.get("kind") or "unknown")
            return value, value
        if group == "rule":
            value = str(finding.get("rule_id") or "?")
            return value, value
        if group == "cwe":
            cwe = str(finding.get("cwe") or "")
            name = finding.get("cwe_name_ru") or finding.get("cwe_name")
            label = f"{cwe} — {name}" if cwe and name else (cwe or "(нет CWE)")
            return cwe or "(нет)", label
        if group == "package":
            name = str(package.get("name") or "")
            return name.lower() or "zzz", name or "(нет пакета)"
        return "", ""

    def _render_results(self, *_args: Any) -> None:
        """Rebuild the findings table from the active filters and sort order."""
        selected = self._selected_index()
        ordered = self._filtered_indices()
        group = self.group_combo.currentText()
        rows: List[Tuple[Optional[str], Optional[int]]] = []
        if group == "none":
            rows = [(None, index) for index in ordered]
        else:
            groups: Dict[str, List[int]] = {}
            labels: Dict[str, str] = {}
            for index in ordered:
                key, label = self._group_key(self.findings[index])
                groups.setdefault(key, []).append(index)
                labels.setdefault(key, label)

            def group_order(key: str):
                if group == "severity":
                    return (-_SEVERITY_PRIORITY.get(key, 0), key)
                return (key.lower(), key)

            for key in sorted(groups, key=group_order):
                rows.append((f"▸ {labels[key]}  ({len(groups[key])})", None))
                rows.extend((None, index) for index in groups[key])

        self.table.setRowCount(0)
        target_row = -1
        for label, index in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            if label is not None:
                item = QTableWidgetItem(label)
                item.setFlags(Qt.ItemIsEnabled)
                font = QFont()
                font.setBold(True)
                item.setFont(font)
                item.setBackground(QColor("#e2e8f0"))
                item.setForeground(QColor(ACCENT_DARK))
                self.table.setSpan(row, 0, 1, len(RESULT_COLUMNS))
                self.table.setItem(row, 0, item)
                continue
            finding = self.findings[index]
            values = finding_row(finding)
            severity = str(finding.get("severity") or "unknown")
            colors = _row_color(severity)
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setData(Qt.UserRole, index)
                if colors is not None:
                    item.setBackground(colors[0])
                    item.setForeground(colors[1])
                self.table.setItem(row, column, item)
            if index == selected:
                target_row = row
        if target_row >= 0:
            self.table.selectRow(target_row)

        visible = len(ordered)
        total = len(self.findings)
        hidden = sum(1 for finding in self.findings
                     if finding.get("suppressed") and not self.suppressed_check.isChecked())
        extra = f"  ·  suppressed скрыто: {hidden}" if hidden else ""
        self.filter_label.setText(f"Показано {visible} из {total}{extra}")
        self._update_sort_headings()

    def _selected_index(self) -> Optional[int]:
        items = self.table.selectedItems()
        if not items:
            return None
        value = items[0].data(Qt.UserRole)
        return int(value) if value is not None else None

    def _sort_results_by_index(self, section: int) -> None:
        self._sort_results(RESULT_COLUMNS[section])

    def _sort_results(self, column: str) -> None:
        current = self._results_sort
        if current and current[0] == column:
            descending = not current[1]
        else:
            descending = default_sort_desc(column)
        self._results_sort = (column, descending)
        self._render_results()

    def _update_sort_headings(self) -> None:
        results = self._results_sort
        labels = []
        for column in RESULT_COLUMNS:
            arrow = ""
            if results and results[0] == column:
                arrow = " ▼" if results[1] else " ▲"
            labels.append(RESULT_HEADINGS[column] + arrow)
        self.table.setHorizontalHeaderLabels(labels)

    def _show_selected(self) -> None:
        index = self._selected_index()
        if index is None:
            return
        finding = self.findings[index]
        purl = str((finding.get("package") or {}).get("purl") or "")
        self.details.setPlainText(format_finding(finding, self.dep_paths.get(purl)))

    def _toggle_details(self) -> None:
        expanded = self.details_button.text() == "Развернуть детали"
        self.details_button.setText("Свернуть детали" if expanded else "Развернуть детали")

    def _locate_in_dependencies(self) -> None:
        index = self._selected_index()
        if index is None:
            return
        package = self.findings[index].get("package") or {}
        item = self.dep_iids.get(str(package.get("purl") or ""))
        if item is None:
            self._set_status("Для этой находки пакета в дереве зависимостей нет", "warn")
            return
        self._switch_page(2)
        self.deps_tree.setCurrentItem(item)
        self.deps_tree.scrollToItem(item)

    # --------------------------------------------------------------- dependencies

    def _fill_dependencies(self, report: Dict[str, Any]) -> None:
        self.report = report
        self.deps_tree.clear()
        self.dep_paths = {}
        self.dep_iids = {}
        graph = ((report.get("stats") or {}).get("dependency_graph") or {})
        rows = dependency_rows(report)
        unique = {row["ref"]: row for row in rows}
        if unique:
            direct = sum(1 for row in unique.values() if row["direct"] is True)
            transitive = sum(1 for row in unique.values() if row["direct"] is False)
            unknown = sum(1 for row in unique.values() if row["direct"] is None)
            state = "resolved" if graph.get("resolved") else "not resolved"
            self.deps_label.setText(
                f"Пакетов: {len(unique)}  ·  direct {direct} / transitive {transitive} / "
                f"unknown {unknown}  ·  graph {state}")
        else:
            self.deps_label.setText("В отчёте нет данных о зависимостях")

        first: Dict[str, QTreeWidgetItem] = {}
        for row in rows:
            parent_item = first.get(row["parent"]) if row["parent"] else None
            depth = "-" if row["depth"] is None else str(row["depth"])
            direct = {True: "direct", False: "transitive", None: "unknown"}[row["direct"]]
            text = row["name"] + ("  (cycle)" if row["cycle"] else "")
            values = [row["version"], row["ecosystem"], direct, depth,
                      row["severity"] if row["severity"] in SEVERITY_COLORS else "-"]
            item = QTreeWidgetItem(parent_item or self.deps_tree, [text] + values)
            colors = _row_color(row["severity"])
            if colors is not None:
                for column in range(item.columnCount()):
                    item.setBackground(column, colors[0])
                    item.setForeground(column, colors[1])
            item.setExpanded(True)
            first.setdefault(row["ref"], item)

        by_ref: Dict[str, Dict[str, Any]] = {}
        parent_of: Dict[str, str] = {}
        for row in rows:
            by_ref.setdefault(row["ref"], row)
            parent_of.setdefault(row["ref"], row["parent"])

        def path_for(ref: str) -> str:
            chain: List[str] = []
            seen: set = set()
            current = ref
            while current and current not in seen:
                seen.add(current)
                row = by_ref.get(current)
                if row is None:
                    break
                chain.append(f"{row['name']} {row['version']}".strip())
                current = parent_of.get(current, "")
            chain.reverse()
            return " → ".join(chain)

        self.dep_paths = {ref: path_for(ref) for ref in by_ref}
        self.dep_iids = first

    # --------------------------------------------------------------- CWE

    def _fill_cwe_list(self, *_args: Any) -> None:
        selected = self._selected_cwe_id()
        entries = cwe_catalog.search(self.cwe_search.text())
        self.cwe_list.clear()
        self._cwe_entries = {}
        for entry in entries:
            count = self._cwe_usage.get(entry.id, 0)
            item = QTreeWidgetItem([entry.cwe_id, entry.name_ru, entry.category,
                                    str(count) if count else ""])
            if count:
                for column in range(item.columnCount()):
                    item.setBackground(column, QColor("#e0e7ff"))
                    item.setForeground(column, QColor(ACCENT_DARK))
            self.cwe_list.addTopLevelItem(item)
            self._cwe_entries[str(entry.id)] = entry
            item.setData(0, Qt.UserRole, str(entry.id))
            if str(entry.id) == selected:
                self.cwe_list.setCurrentItem(item)
        self.cwe_label.setText(f"Записей: {len(entries)}")

    def _selected_cwe_id(self) -> Optional[str]:
        items = self.cwe_list.selectedItems()
        return items[0].data(0, Qt.UserRole) if items else None

    def _show_cwe_details(self) -> None:
        key = self._selected_cwe_id()
        entry = self._cwe_entries.get(key) if key else None
        if entry is None:
            return
        self.cwe_details.setPlainText(format_cwe_entry(entry, self._cwe_usage.get(entry.id, 0)))

    def _open_cwe_link(self) -> None:
        key = self._selected_cwe_id()
        entry = self._cwe_entries.get(key) if key else None
        if entry is None:
            entry = cwe_catalog.lookup(self.cwe_search.text())
        if entry is None:
            self._set_status("Выберите запись CWE", "warn")
            return
        import webbrowser
        webbrowser.open(entry.url)
        self._set_status(f"Открыто: {entry.url}", "idle")

    def _update_cwe_usage(self, report: Dict[str, Any]) -> None:
        usage: Dict[int, int] = {}
        for finding in report.get("findings") or []:
            entry = cwe_catalog.lookup(finding.get("cwe"))
            if entry is not None:
                usage[entry.id] = usage.get(entry.id, 0) + 1
        self._cwe_usage = usage
        self._fill_cwe_list()


def main(argv: Optional[List[str]] = None) -> int:
    app = QApplication.instance() or QApplication(sys.argv if argv is None else argv)
    app.setStyleSheet(STYLESHEET)
    window = ArgusWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
