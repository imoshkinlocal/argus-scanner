"""Desktop front-end for argus built on tkinter (standard library only).

The window runs the same ``argus scan`` command line that CI uses, in a child
process, so the GUI and the CLI always produce identical reports.  When a scan
finishes, its JSON report is loaded back for browsing.  Toolkit-independent
logic lives in :mod:`argus.gui_core`.
"""

from __future__ import annotations

import json
import os
import queue
import shlex
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, font as tkfont, messagebox, ttk
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__, cwe as cwe_catalog
from .gui_core import (  # noqa: F401  (re-exported for existing callers and tests)
    BG, CARD, BORDER, INK, MUTED, ACCENT, ACCENT_DARK, ACCENT_SOFT, HEADER, HEADER_ACCENT,
    OK, ERROR, WARN, CONSOLE_BG, CONSOLE_FG, STATUS_TONES, SEVERITY_COLORS, HELP_TEXT,
    PACKAGE_ROOT, FAIL_ON_CHOICES, RANGE_CHOICES, DEB_SUITE_CHOICES, SEVERITY_ORDER,
    RESULT_COLUMNS, RESULT_HEADINGS, RESULT_WIDTHS, DEP_COLUMNS, DEP_HEADINGS, DEP_WIDTHS,
    EXIT_MEANING, _SEVERITY_PRIORITY, _DIRECT_PRIORITY, default_sort_desc,
    sort_finding_indices, _dependency_sort_key, build_scan_command, format_summary,
    dependency_label, finding_row, format_finding, format_cwe_entry, dependency_rows,
    _direct_label,
)


class ArgusApp(tk.Tk):
    """Main window: scan configuration, live log and report browser."""

    def __init__(self) -> None:
        super().__init__()
        self.title("argus — SAST + SCA")
        self.geometry("1100x880")
        self.minsize(940, 700)
        self.configure(bg=BG)

        self.events: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        self.process: Optional[subprocess.Popen] = None
        self.report_path = ""
        self.report: Dict[str, Any] = {}
        self.findings: List[Dict[str, Any]] = []
        self.dep_paths: Dict[str, str] = {}
        self.dep_iids: Dict[str, str] = {}
        self._dep_ref_by_iid: Dict[str, str] = {}
        self._results_sort: Optional[Tuple[str, bool]] = None
        self._deps_sort: Optional[Tuple[str, bool]] = None
        self._cwe_usage: Dict[int, int] = {}
        self._cwe_sash_done = False
        self._details_expanded = False

        self.base_family = tkfont.nametofont("TkDefaultFont").actual("family")
        self.mono_family = tkfont.nametofont("TkFixedFont").actual("family")
        self.font_base = (self.base_family, 10)
        self.font_bold = (self.base_family, 10, "bold")
        self.font_small = (self.base_family, 9)
        self.font_chip = (self.base_family, 9, "bold")
        self.font_title = (self.base_family, 20, "bold")
        self.font_mono = (self.mono_family, 9)

        self._configure_styles()

        cwd = os.getcwd()
        self.target_var = tk.StringVar()
        self.output_var = tk.StringVar(value=os.path.join(cwd, "argus-report.json"))
        self.summary_var = tk.StringVar(value=os.path.join(cwd, "argus-report.md"))
        self.sast_var = tk.BooleanVar(value=True)
        self.sca_var = tk.BooleanVar(value=True)
        self.dev_var = tk.BooleanVar(value=False)
        self.offline_var = tk.BooleanVar(value=False)
        self.fail_var = tk.StringVar(value="high")
        self.range_var = tk.StringVar(value="min")
        self.exclude_var = tk.StringVar()
        self.config_var = tk.StringVar()
        self.baseline_var = tk.StringVar()
        self.fail_new_var = tk.BooleanVar(value=False)
        self.secrets_var = tk.BooleanVar(value=True)
        self.iac_var = tk.BooleanVar(value=True)
        self.owasp_var = tk.BooleanVar(value=True)
        self.owasp_version_var = tk.StringVar(value="2021")
        self.owasp_file_var = tk.StringVar()
        self.deb_root_var = tk.StringVar()
        self.deb_status_var = tk.StringVar()
        self.deb_var = tk.StringVar()
        self.deb_suite_var = tk.StringVar()
        self.filter_var = tk.StringVar()
        self.kind_filter_var = tk.StringVar(value="all")
        self.cwe_filter_var = tk.StringVar(value="all")
        self.new_only_var = tk.BooleanVar(value=False)
        self.show_suppressed_var = tk.BooleanVar(value=False)
        self.group_var = tk.StringVar(value="none")
        self._severity_filter: set = set()

        self._build_header()
        self.status = tk.Label(self, text="●  Готов к работе", anchor="w",
                               bg=STATUS_TONES["idle"], fg="#ffffff", padx=14, pady=6,
                               font=self.font_bold)
        self.status.pack(side="bottom", fill="x")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        self.scan_frame = ttk.Frame(self.notebook, padding=12)
        self.results_frame = ttk.Frame(self.notebook, padding=12)
        self.deps_frame = ttk.Frame(self.notebook, padding=12)
        self.cwe_frame = ttk.Frame(self.notebook, padding=12)
        self.help_frame = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.scan_frame, text="  Сканирование  ")
        self.notebook.add(self.results_frame, text="  Результаты  ")
        self.notebook.add(self.deps_frame, text="  Зависимости  ")
        self.notebook.add(self.cwe_frame, text="  CWE  ")
        self.notebook.add(self.help_frame, text="  Справка  ")

        self._build_scan_tab(self.scan_frame)
        self._build_results_tab(self.results_frame)
        self._build_dependencies_tab(self.deps_frame)
        self._build_cwe_tab(self.cwe_frame)
        self._build_help_tab(self.help_frame)
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_events)

    # ------------------------------------------------------------------ styling

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure(".", font=self.font_base, background=BG, foreground=INK)
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=CARD)
        style.configure("TLabel", background=BG, foreground=INK)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("Section.TLabel", background=BG, foreground=ACCENT_DARK,
                        font=self.font_bold)
        style.configure("Card.TLabel", background=CARD, foreground=INK)
        style.configure("CardMuted.TLabel", background=CARD, foreground=MUTED)
        style.configure("Card.TCheckbutton", background=CARD, foreground=INK)
        style.map("Card.TCheckbutton", background=[("active", CARD)])
        style.configure("Option.Toolbutton", background="#f1f5f9", foreground=INK,
                        bordercolor="#cbd5e1", relief="flat", padding=(10, 6),
                        font=self.font_base)
        style.map("Option.Toolbutton",
                  background=[("selected", ACCENT), ("active", "#dbeafe"),
                              ("selected", "active", ACCENT_DARK)],
                  foreground=[("selected", "#ffffff"), ("active", ACCENT_DARK),
                              ("selected", "active", "#ffffff")],
                  bordercolor=[("selected", ACCENT_DARK)])

        style.configure("Card.TLabelframe", background=CARD, bordercolor=BORDER,
                        relief="solid", borderwidth=1)
        style.configure("Card.TLabelframe.Label", background=CARD, foreground=ACCENT_DARK,
                        font=self.font_bold)
        style.configure("Source.TLabelframe", background=CARD, bordercolor="#bfdbfe",
                        relief="solid", borderwidth=1)
        style.configure("Source.TLabelframe.Label", background=CARD, foreground=ACCENT_DARK,
                        font=self.font_bold)
        style.configure("Options.TLabelframe", background=CARD, bordercolor="#ddd6fe",
                        relief="solid", borderwidth=1)
        style.configure("Options.TLabelframe.Label", background=CARD, foreground="#6d28d9",
                        font=self.font_bold)
        style.configure("Output.TLabelframe", background=CARD, bordercolor="#99f6e4",
                        relief="solid", borderwidth=1)
        style.configure("Output.TLabelframe.Label", background=CARD, foreground="#0f766e",
                        font=self.font_bold)
        style.configure("Log.TLabelframe", background=CONSOLE_BG, bordercolor="#1e293b",
                        relief="solid", borderwidth=1)
        style.configure("Log.TLabelframe.Label", background=CONSOLE_BG, foreground="#93c5fd",
                        font=self.font_bold)

        style.configure("TEntry", fieldbackground="#ffffff", bordercolor=BORDER,
                        lightcolor=BORDER, darkcolor=BORDER, padding=5)
        style.configure("TCombobox", fieldbackground="#ffffff", background="#ffffff",
                        bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER, padding=4)
        style.map("TCombobox",
                  fieldbackground=[("readonly", "#ffffff"), ("disabled", "#f1f5f9")],
                  foreground=[("readonly", INK)])

        style.configure("TButton", background=ACCENT_SOFT, foreground=ACCENT_DARK,
                        bordercolor="#c7d2fe", focusthickness=0, padding=(12, 6),
                        font=self.font_bold)
        style.map("TButton", background=[("active", "#c7d2fe"), ("disabled", "#eef2f9")],
                  foreground=[("disabled", "#94a3b8")])
        style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                        bordercolor=ACCENT_DARK, padding=(16, 9), font=self.font_bold)
        style.map("Accent.TButton",
                  background=[("active", ACCENT_DARK), ("disabled", "#93c5fd")],
                  foreground=[("disabled", "#ffffff")])
        style.configure("Stop.TButton", background="#fee2e2", foreground=ERROR,
                        bordercolor="#fecaca", padding=(12, 9), font=self.font_bold)
        style.map("Stop.TButton", background=[("active", "#fecaca")])

        style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(4, 6, 4, 0))
        style.configure("TNotebook.Tab", background="#dbe3f0", foreground=MUTED,
                        padding=(16, 8), font=self.font_bold, borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", ACCENT), ("active", "#dbeafe")],
                  foreground=[("selected", "#ffffff"), ("active", ACCENT_DARK)])

        style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=INK,
                        rowheight=26, bordercolor=BORDER, borderwidth=1,
                        font=self.font_base)
        style.configure("Treeview.Heading", background=ACCENT_DARK, foreground="#ffffff",
                        relief="flat", padding=(6, 7), font=self.font_bold)
        style.map("Treeview.Heading", background=[("active", ACCENT)])
        style.map("Treeview", background=[("selected", "#bfdbfe")],
                  foreground=[("selected", INK)])

        style.configure("Horizontal.TProgressbar", background=ACCENT,
                        troughcolor="#dbe3f0", bordercolor="#dbe3f0",
                        lightcolor=ACCENT, darkcolor=ACCENT)

        self.option_add("*TCombobox*Listbox.background", "#ffffff")
        self.option_add("*TCombobox*Listbox.foreground", INK)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")

    def _build_header(self) -> None:
        header = tk.Frame(self, bg=HEADER)
        header.pack(fill="x")
        inner = tk.Frame(header, bg=HEADER)
        inner.pack(fill="x", padx=18, pady=(13, 11))
        tk.Label(inner, text="argus", bg=HEADER, fg="#ffffff",
                 font=self.font_title).pack(side="left")
        tk.Label(inner, text="SAST + SCA · CycloneDX / SPDX", bg=HEADER,
                 fg=HEADER_ACCENT, font=(self.base_family, 11)).pack(side="left", padx=(12, 0),
                                                                   pady=(6, 0))
        tk.Label(inner, text=f"argus v{__version__}", bg=ACCENT_DARK, fg="#ffffff",
                 font=self.font_small, padx=10, pady=3).pack(side="right")
        tk.Frame(self, bg=ACCENT, height=3).pack(fill="x")

    # ------------------------------------------------------------------ layout

    def _build_scan_tab(self, parent: ttk.Frame) -> None:
        source = ttk.LabelFrame(parent, text="1 · Каталог с исходниками для проверки",
                                style="Source.TLabelframe", padding=10)
        source.pack(fill="x")
        source.columnconfigure(0, weight=1)
        ttk.Entry(source, textvariable=self.target_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(source, text="Выбрать каталог…",
                   command=self._pick_target).grid(row=0, column=1, padx=(8, 0))
        ttk.Label(
            source, style="CardMuted.TLabel", wraplength=1000, justify="left",
            text=("Рекурсивный обход. SAST — исходный код, SCA — манифесты зависимостей; "
                  "служебные каталоги пропускаются."),
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))

        options = ttk.LabelFrame(parent, text="2 · Что проверять и как",
                                 style="Options.TLabelframe", padding=10)
        options.pack(fill="x", pady=(10, 0))
        options.columnconfigure(0, weight=1)
        checks = ttk.Frame(options, style="Card.TFrame")
        checks.grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(checks, text="SAST — анализ кода", style="Option.Toolbutton",
                        variable=self.sast_var).pack(side="left", padx=(0, 16))
        ttk.Checkbutton(checks, text="SCA — уязвимые зависимости (OSV)",
                        style="Option.Toolbutton", variable=self.sca_var).pack(side="left",
                                                                            padx=(0, 16))
        ttk.Checkbutton(checks, text="dev/test-зависимости", style="Option.Toolbutton",
                        variable=self.dev_var).pack(side="left", padx=(0, 16))
        ttk.Checkbutton(checks, text="Офлайн: только локальная база OSV",
                        style="Option.Toolbutton", variable=self.offline_var).pack(side="left")

        controls = ttk.Frame(options, style="Card.TFrame")
        controls.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        controls.columnconfigure(5, weight=1)
        ttk.Label(controls, text="Порог:", style="Card.TLabel").grid(row=0, column=0, sticky="e")
        ttk.Combobox(controls, textvariable=self.fail_var, values=FAIL_ON_CHOICES,
                     state="readonly", width=11).grid(row=0, column=1, sticky="w", padx=(6, 18))
        ttk.Label(controls, text="Диапазоны:", style="Card.TLabel").grid(
            row=0, column=2, sticky="e")
        ttk.Combobox(controls, textvariable=self.range_var, values=RANGE_CHOICES,
                     state="readonly", width=8).grid(row=0, column=3, sticky="w", padx=(6, 18))
        ttk.Label(controls, text="Исключения:", style="Card.TLabel").grid(
            row=0, column=4, sticky="e")
        ttk.Entry(controls, textvariable=self.exclude_var).grid(
            row=0, column=5, sticky="ew", padx=(6, 0))

        workflow_row = ttk.Frame(options, style="Card.TFrame")
        workflow_row.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        workflow_row.columnconfigure(1, weight=1)
        workflow_row.columnconfigure(4, weight=1)
        ttk.Label(workflow_row, text="Конфиг:", style="Card.TLabel").grid(
            row=0, column=0, sticky="e")
        ttk.Entry(workflow_row, textvariable=self.config_var).grid(
            row=0, column=1, sticky="ew", padx=(6, 4))
        ttk.Button(workflow_row, text="…", width=3,
                   command=lambda: self._pick_file(self.config_var, "argus.toml",
                                                   [("Конфиг", "*.toml *.json"),
                                                    ("Все файлы", "*")])).grid(row=0, column=2)
        ttk.Label(workflow_row, text="Baseline:", style="Card.TLabel").grid(
            row=0, column=3, sticky="e", padx=(16, 0))
        ttk.Entry(workflow_row, textvariable=self.baseline_var).grid(
            row=0, column=4, sticky="ew", padx=(6, 4))
        ttk.Button(workflow_row, text="…", width=3,
                   command=lambda: self._pick_file(self.baseline_var, "baseline.json",
                                                   [("JSON", "*.json"),
                                                    ("Все файлы", "*")])).grid(row=0, column=5)

        policy_row = ttk.Frame(options, style="Card.TFrame")
        policy_row.grid(row=3, column=0, sticky="w", pady=(8, 0))
        ttk.Checkbutton(policy_row, text="Только новые находки (нужен baseline)",
                        style="Option.Toolbutton",
                        variable=self.fail_new_var).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(policy_row, text="Секреты", style="Option.Toolbutton",
                        variable=self.secrets_var).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(policy_row, text="IaC (Docker/K8s/Terraform)",
                        style="Option.Toolbutton",
                        variable=self.iac_var).pack(side="left")

        owasp_row = ttk.Frame(options, style="Card.TFrame")
        owasp_row.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        owasp_row.columnconfigure(4, weight=1)
        ttk.Checkbutton(owasp_row, text="OWASP Top 10", style="Option.Toolbutton",
                        variable=self.owasp_var).grid(row=0, column=0, sticky="w")
        ttk.Label(owasp_row, text="Версия:", style="Card.TLabel").grid(
            row=0, column=1, sticky="e", padx=(16, 0))
        ttk.Combobox(owasp_row, textvariable=self.owasp_version_var,
                     values=("2017", "2021", "2025"), state="readonly",
                     width=8).grid(row=0, column=2, sticky="w", padx=(6, 18))
        ttk.Label(owasp_row, text="Свой файл:", style="Card.TLabel").grid(
            row=0, column=3, sticky="e")
        ttk.Entry(owasp_row, textvariable=self.owasp_file_var).grid(
            row=0, column=4, sticky="ew", padx=(6, 4))
        ttk.Button(owasp_row, text="…", width=3,
                   command=lambda: self._pick_file(
                       self.owasp_file_var, "Справочник OWASP Top 10",
                       [("JSON/TOML", "*.json *.toml"), ("Все файлы", "*")])).grid(
            row=0, column=5)

        ttk.Label(
            options, style="CardMuted.TLabel", wraplength=1000, justify="left",
            text=("Порог: находка этого уровня и выше → код 1. min — нижняя граница диапазона, "
                  "skip — только точные версии. Исключения: для SAST подстрока пути, "
                  "для SCA glob по манифесту. Конфиг и baseline можно не указывать — "
                  "argus найдёт argus.toml рядом с проектом. OWASP Top 10 включён по "
                  "умолчанию (2021); свой JSON/TOML-файл обновляет справочник без "
                  "пересборки."),
        ).grid(row=5, column=0, sticky="w", pady=(8, 0))

        debian = ttk.LabelFrame(
            parent, text="2b · Пакеты Debian/Ubuntu (dpkg и .deb)",
            style="Options.TLabelframe", padding=10)
        debian.pack(fill="x", pady=(10, 0))
        debian.columnconfigure(1, weight=1)
        ttk.Label(debian, text="Корень системы:", style="Card.TLabel").grid(
            row=0, column=0, sticky="e")
        ttk.Entry(debian, textvariable=self.deb_root_var).grid(
            row=0, column=1, sticky="ew", padx=6)
        ttk.Button(debian, text="Выбрать…", width=10,
                   command=lambda: self._pick_directory(
                       self.deb_root_var, "Корень системы (/) или chroot")).grid(
            row=0, column=2)
        ttk.Label(debian, text="Статус dpkg:", style="Card.TLabel").grid(
            row=1, column=0, sticky="e", pady=(6, 0))
        ttk.Entry(debian, textvariable=self.deb_status_var).grid(
            row=1, column=1, sticky="ew", padx=6, pady=(6, 0))
        ttk.Button(debian, text="Выбрать…", width=10,
                   command=lambda: self._pick_file(
                       self.deb_status_var, "Файл var/lib/dpkg/status",
                       [("Статус dpkg", "status"), ("Все файлы", "*")])).grid(
            row=1, column=2, pady=(6, 0))
        ttk.Label(debian, text="Файлы .deb:", style="Card.TLabel").grid(
            row=2, column=0, sticky="e", pady=(6, 0))
        ttk.Entry(debian, textvariable=self.deb_var).grid(
            row=2, column=1, sticky="ew", padx=6, pady=(6, 0))
        ttk.Button(debian, text="Выбрать…", width=10,
                   command=lambda: self._pick_files(
                       self.deb_var, "Пакеты .deb",
                       [("Debian-пакеты", "*.deb"), ("Все файлы", "*")])).grid(
            row=2, column=2, pady=(6, 0))
        ttk.Label(debian, text="Релиз:", style="Card.TLabel").grid(
            row=3, column=0, sticky="e", pady=(6, 0))
        suite_row = ttk.Frame(debian, style="Card.TFrame")
        suite_row.grid(row=3, column=1, columnspan=2, sticky="w", padx=6, pady=(6, 0))
        ttk.Combobox(suite_row, textvariable=self.deb_suite_var,
                     values=DEB_SUITE_CHOICES, width=14).pack(side="left")
        ttk.Label(suite_row, style="CardMuted.TLabel",
                  text="— --deb-suite; нужен для .deb и отдельных status-файлов, "
                       "для корня системы определяется сам").pack(side="left", padx=(8, 0))
        ttk.Label(
            debian, style="CardMuted.TLabel", wraplength=1000, justify="left",
            text=("Корень системы читает <корень>/var/lib/dpkg/status и определяет "
                  "Debian/Ubuntu-релиз из /etc/os-release или /etc/debian_version. "
                  "Отдельные .deb и status-файлы не знают релиз: укажите его в поле "
                  "«Релиз» (bookworm, jammy, 12, 22.04). Без релиза пакет пропускается "
                  "с предупреждением — иначе можно получить чужие исправления."),
        ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(8, 0))

        output = ttk.LabelFrame(parent, text="3 · Куда сохранить отчёты",
                                style="Output.TLabelframe", padding=10)
        output.pack(fill="x", pady=(10, 0))
        output.columnconfigure(1, weight=1)
        ttk.Label(output, text="JSON (для автоматики):", style="Card.TLabel").grid(
            row=0, column=0, sticky="w")
        ttk.Entry(output, textvariable=self.output_var).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(output, text="…", width=3,
                   command=lambda: self._pick_save(self.output_var, "json")).grid(row=0, column=2)
        ttk.Label(output, text="Markdown (для человека):", style="Card.TLabel").grid(
            row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(output, textvariable=self.summary_var).grid(row=1, column=1, sticky="ew",
                                                             padx=8, pady=(6, 0))
        ttk.Button(output, text="…", width=3,
                   command=lambda: self._pick_save(self.summary_var, "md")).grid(
            row=1, column=2, pady=(6, 0))

        actions = ttk.Frame(parent)
        actions.pack(fill="x", pady=(10, 0))
        self.run_button = ttk.Button(actions, text="▶  Запустить сканирование",
                                     style="Accent.TButton", command=self._start)
        self.run_button.pack(side="left")
        self.stop_button = ttk.Button(actions, text="■  Остановить", style="Stop.TButton",
                                      command=self._stop)
        self.stop_button.pack(side="left", padx=8)
        self.stop_button.state(["disabled"])
        self.progress = ttk.Progressbar(actions, mode="indeterminate", length=240)
        self.progress.pack(side="left", padx=12)

        log_frame = ttk.LabelFrame(parent, text="Журнал", style="Log.TLabelframe", padding=8)
        log_frame.pack(fill="both", expand=True, pady=(10, 0))
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        self.log_text = tk.Text(log_frame, height=6, wrap="word", state="disabled",
                                bg=CONSOLE_BG, fg=CONSOLE_FG, insertbackground="#ffffff",
                                relief="flat", borderwidth=0, padx=10, pady=8,
                                highlightthickness=0, font=self.font_mono)
        self.log_text.tag_configure("cmd", foreground="#93c5fd")
        self.log_text.tag_configure("ok", foreground="#86efac")
        self.log_text.tag_configure("warn", foreground="#fcd34d")
        self.log_text.tag_configure("err", foreground="#fca5a5")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scroll.grid(row=0, column=1, sticky="ns")

    def _build_results_tab(self, parent: ttk.Frame) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill="x")
        ttk.Button(bar, text="Открыть JSON-отчёт…",
                   command=self._open_report).pack(side="left")
        self.report_label = ttk.Label(bar, text="Отчёт не загружен", style="Muted.TLabel")
        self.report_label.pack(side="left", padx=10)
        ttk.Button(bar, text="Дерево зависимостей →",
                   command=self._show_dependencies_tab).pack(side="right")
        ttk.Button(bar, text="Справочник CWE →",
                   command=self._show_cwe_reference).pack(side="right", padx=(0, 8))
        self.details_button = ttk.Button(bar, text="Развернуть детали",
                                         command=self._toggle_details)
        self.details_button.pack(side="right", padx=(0, 8))
        ttk.Button(bar, text="Сравнить с отчётом…",
                   command=self._compare_report).pack(side="right", padx=(0, 8))

        filters = ttk.Frame(parent)
        filters.pack(fill="x", pady=(8, 0))
        ttk.Label(filters, text="Поиск:").pack(side="left")
        search_entry = ttk.Entry(filters, textvariable=self.filter_var, width=26)
        search_entry.pack(side="left", padx=(6, 10))
        search_entry.bind("<KeyRelease>", lambda _event: self._render_results())
        ttk.Button(filters, text="×", width=3,
                   command=self._reset_filters).pack(side="left", padx=(0, 14))

        ttk.Label(filters, text="Тип:").pack(side="left")
        kind_box = ttk.Combobox(filters, textvariable=self.kind_filter_var,
                                values=("all", "sast", "sca"), state="readonly",
                                width=7)
        kind_box.pack(side="left", padx=(6, 12))
        kind_box.bind("<<ComboboxSelected>>", lambda _event: self._render_results())

        ttk.Label(filters, text="CWE:").pack(side="left")
        self.cwe_filter_box = ttk.Combobox(filters, textvariable=self.cwe_filter_var,
                                           values=("all",), state="readonly", width=13)
        self.cwe_filter_box.pack(side="left", padx=(6, 12))
        self.cwe_filter_box.bind("<<ComboboxSelected>>",
                                 lambda _event: self._render_results())

        ttk.Checkbutton(filters, text="Только новые", variable=self.new_only_var,
                        command=self._render_results).pack(side="left", padx=(0, 10))
        ttk.Checkbutton(filters, text="Suppressed", variable=self.show_suppressed_var,
                        command=self._render_results).pack(side="left", padx=(0, 12))

        ttk.Label(filters, text="Группировка:").pack(side="left")
        group_box = ttk.Combobox(
            filters, textvariable=self.group_var, state="readonly", width=12,
            values=("none", "severity", "kind", "rule", "cwe", "package"))
        group_box.pack(side="left", padx=(6, 12))
        group_box.bind("<<ComboboxSelected>>", lambda _event: self._render_results())

        self.filter_label = ttk.Label(filters, text="", style="Muted.TLabel")
        self.filter_label.pack(side="right")

        legend = ttk.Frame(parent)
        legend.pack(fill="x", pady=(8, 0))
        self.chips: Dict[str, tk.Label] = {}
        for severity in SEVERITY_ORDER:
            colors = SEVERITY_COLORS[severity]
            chip = tk.Label(legend, text=f"{severity}  0", bg=colors["chip"],
                            fg=colors["chip_fg"], font=self.font_chip,
                            padx=10, pady=3, bd=0, cursor="hand2",
                            highlightthickness=2, highlightbackground=colors["chip"])
            chip.pack(side="left", padx=(0, 6))
            chip.bind("<Button-1>", lambda _event, name=severity: self._toggle_severity(name))
            self.chips[severity] = chip

        self.summary_text = tk.Text(parent, height=8, wrap="word", state="disabled",
                                    bg=CARD, fg=INK, relief="flat", borderwidth=0,
                                    padx=12, pady=10, font=self.font_base,
                                    highlightthickness=1, highlightbackground=BORDER,
                                    highlightcolor=BORDER)
        self.summary_text.tag_configure("label", foreground=MUTED)
        self.summary_text.tag_configure("value", foreground=INK)
        self.summary_text.tag_configure("strong", foreground=INK, font=self.font_bold)
        self.summary_text.tag_configure("accent", foreground=ACCENT_DARK)
        self.summary_text.tag_configure("status-findings", foreground=ERROR, font=self.font_bold)
        self.summary_text.tag_configure("status-clean", foreground=OK, font=self.font_bold)
        self.summary_text.tag_configure("status-error", foreground=WARN, font=self.font_bold)
        self.summary_text.tag_configure("status-default", foreground=MUTED, font=self.font_bold)
        self.summary_text.pack(fill="x", pady=(8, 0))

        columns = RESULT_COLUMNS
        widths = RESULT_WIDTHS
        split = ttk.PanedWindow(parent, orient="vertical")
        split.pack(fill="both", expand=True, pady=(8, 0))
        tree_frame = ttk.Frame(split)
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings",
                                 selectmode="browse")
        for column, width in zip(columns, widths):
            self.tree.heading(column, text=RESULT_HEADINGS[column],
                              command=lambda c=column: self._sort_results(c))
            self.tree.column(column, width=width, anchor="w", stretch=column == "message")
        for severity, colors in SEVERITY_COLORS.items():
            self.tree.tag_configure(severity, background=colors["row"],
                                    foreground=colors["fg"])
        self.tree.tag_configure("group", background="#e2e8f0", foreground=ACCENT_DARK,
                                font=self.font_bold)
        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        tree_xscroll = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_scroll.set, xscrollcommand=tree_xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll.grid(row=0, column=1, sticky="ns")
        tree_xscroll.grid(row=1, column=0, sticky="ew")
        self.tree.bind("<<TreeviewSelect>>", self._show_selected)
        self.tree.bind("<Double-1>", self._locate_in_dependencies)
        split.add(tree_frame, weight=3)

        details_frame = ttk.Frame(split)
        details_frame.rowconfigure(0, weight=1)
        details_frame.columnconfigure(0, weight=1)
        self.details = tk.Text(details_frame, height=12, wrap="word", state="disabled",
                               bg=CARD, fg=INK, relief="flat", borderwidth=0,
                               padx=12, pady=10, font=self.font_mono,
                               highlightthickness=1, highlightbackground=BORDER,
                               highlightcolor=BORDER)
        details_scroll = ttk.Scrollbar(details_frame, orient="vertical",
                                       command=self.details.yview)
        self.details.configure(yscrollcommand=details_scroll.set)
        self.details.grid(row=0, column=0, sticky="nsew")
        details_scroll.grid(row=0, column=1, sticky="ns")
        split.add(details_frame, weight=2)
        self.results_split = split
        self.after_idle(self._place_results_sash)
        self._set_text(self.summary_text, "")
        self._fill_summary({})

    def _build_dependencies_tab(self, parent: ttk.Frame) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill="x")
        ttk.Label(bar, text="Дерево зависимостей из lock-файлов",
                  style="Section.TLabel").pack(side="left")
        self.deps_label = ttk.Label(bar, text="Отчёт не загружен", style="Muted.TLabel")
        self.deps_label.pack(side="left", padx=10)

        ttk.Label(
            parent, style="Muted.TLabel", wraplength=1000, justify="left",
            text=("Рёбра и глубина восстанавливаются только из lock-файлов "
                  "(Gemfile.lock, package-lock.json, poetry.lock, uv.lock, composer.lock, "
                  "Cargo.lock). Если lock-файла нет, пакеты показаны плоским списком: "
                  "direct — из манифеста, depth — неизвестна."),
        ).pack(fill="x", pady=(6, 8))

        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        columns = DEP_COLUMNS
        widths = DEP_WIDTHS
        self.deps_tree = ttk.Treeview(frame, columns=columns, show="tree headings",
                                      selectmode="browse")
        self.deps_tree.heading("#0", text=DEP_HEADINGS["#0"],
                               command=lambda: self._sort_dependencies("#0"))
        self.deps_tree.column("#0", width=340, anchor="w", stretch=True)
        for column, width in zip(columns, widths):
            self.deps_tree.heading(column, text=DEP_HEADINGS[column],
                                   command=lambda c=column: self._sort_dependencies(c))
            self.deps_tree.column(column, width=width, anchor="w",
                                  stretch=column == "ecosystem")
        for severity, colors in SEVERITY_COLORS.items():
            self.deps_tree.tag_configure(severity, background=colors["row"],
                                         foreground=colors["fg"])
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.deps_tree.yview)
        xscroll = ttk.Scrollbar(frame, orient="horizontal", command=self.deps_tree.xview)
        self.deps_tree.configure(yscrollcommand=scroll.set, xscrollcommand=xscroll.set)
        self.deps_tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        self._fill_dependencies({})

    def _build_cwe_tab(self, parent: ttk.Frame) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill="x")
        ttk.Label(bar, text="Справочник CWE", style="Section.TLabel").pack(side="left")
        self.cwe_label = ttk.Label(bar, text="", style="Muted.TLabel")
        self.cwe_label.pack(side="left", padx=10)
        ttk.Button(bar, text="Открыть на cwe.mitre.org",
                   command=self._open_cwe_link).pack(side="right")

        search_bar = ttk.Frame(parent)
        search_bar.pack(fill="x", pady=(8, 0))
        ttk.Label(search_bar, text="Поиск:").pack(side="left")
        self.cwe_search_var = tk.StringVar()
        self.cwe_search_entry = ttk.Entry(search_bar, textvariable=self.cwe_search_var)
        self.cwe_search_entry.pack(side="left", fill="x", expand=True, padx=(6, 6))
        self.cwe_search_entry.bind("<Return>", lambda _event: self._fill_cwe_list())
        self.cwe_search_entry.bind("<KeyRelease>", lambda _event: self._fill_cwe_list())
        ttk.Button(search_bar, text="Сбросить",
                   command=self._reset_cwe_search).pack(side="left")

        ttk.Label(
            parent, style="Muted.TLabel", wraplength=1000, justify="left",
            text=("Встроенный офлайн-справочник: номер, название, категория, "
                  "последствия и меры защиты. Поиск идёт по номеру, названию, "
                  "категории и описанию. Незнакомый CWE всё равно откроется "
                  "ссылкой на MITRE."),
        ).pack(fill="x", pady=(6, 8))

        split = ttk.PanedWindow(parent, orient="horizontal")
        split.pack(fill="both", expand=True)

        list_frame = ttk.Frame(split)
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)
        columns = ("cwe", "name", "category", "count")
        headings = ("CWE", "Уязвимость", "Категория", "В отчёте")
        widths = (85, 300, 155, 70)
        self.cwe_tree = ttk.Treeview(list_frame, columns=columns, show="headings",
                                     selectmode="browse")
        for column, heading, width in zip(columns, headings, widths):
            self.cwe_tree.heading(column, text=heading)
            self.cwe_tree.column(column, width=width, anchor="w",
                                 stretch=column == "name")
        self.cwe_tree.tag_configure("used", background=ACCENT_SOFT,
                                    foreground=ACCENT_DARK)
        self.cwe_tree.bind("<<TreeviewSelect>>", self._show_cwe_details)
        self.cwe_tree.bind("<Double-1>", lambda _event: self._open_cwe_link())
        cwe_scroll = ttk.Scrollbar(list_frame, orient="vertical",
                                   command=self.cwe_tree.yview)
        cwe_xscroll = ttk.Scrollbar(list_frame, orient="horizontal",
                                    command=self.cwe_tree.xview)
        self.cwe_tree.configure(yscrollcommand=cwe_scroll.set,
                                xscrollcommand=cwe_xscroll.set)
        self.cwe_tree.grid(row=0, column=0, sticky="nsew")
        cwe_scroll.grid(row=0, column=1, sticky="ns")
        cwe_xscroll.grid(row=1, column=0, sticky="ew")
        list_frame.rowconfigure(1, weight=0)
        split.add(list_frame, weight=2)

        details_frame = ttk.Frame(split)
        details_frame.rowconfigure(0, weight=1)
        details_frame.columnconfigure(0, weight=1)
        self.cwe_details = tk.Text(details_frame, wrap="word", state="disabled",
                                   bg=CARD, fg=INK, relief="flat", borderwidth=0,
                                   padx=12, pady=10, font=self.font_base,
                                   highlightthickness=1, highlightbackground=BORDER,
                                   highlightcolor=BORDER)
        cwe_details_scroll = ttk.Scrollbar(details_frame, orient="vertical",
                                           command=self.cwe_details.yview)
        self.cwe_details.configure(yscrollcommand=cwe_details_scroll.set)
        self.cwe_details.grid(row=0, column=0, sticky="nsew")
        cwe_details_scroll.grid(row=0, column=1, sticky="ns")
        split.add(details_frame, weight=3)
        self.cwe_split = split
        self.after_idle(self._place_cwe_sash)

        self._cwe_entries: Dict[str, "cwe_catalog.CWEEntry"] = {}
        self._fill_cwe_list()

    def _build_help_tab(self, parent: ttk.Frame) -> None:
        text = tk.Text(parent, wrap="word", padx=14, pady=12, bg=CARD, fg=INK,
                       relief="flat", borderwidth=0, font=self.font_base,
                       highlightthickness=1, highlightbackground=BORDER,
                       highlightcolor=BORDER)
        scroll = ttk.Scrollbar(parent, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        text.tag_configure("h", foreground=ACCENT_DARK, font=(self.base_family, 11, "bold"),
                           spacing1=10, spacing3=4)
        text.tag_configure("body", foreground=INK)
        for line in HELP_TEXT.splitlines():
            stripped = line.strip()
            is_heading = bool(stripped) and stripped == stripped.upper() and not line.startswith(" ")
            text.insert("end", line + "\n", "h" if is_heading else "body")
        text.configure(state="disabled")

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _set_text(widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _log(self, line: str) -> None:
        lowered = line.lower()
        if line.startswith("$ "):
            tag = "cmd"
        elif any(word in lowered for word in ("error", "failed", "ошибка", "traceback")):
            tag = "err"
        elif "код возврата 0" in lowered:
            tag = "ok"
        elif "код возврата 1" in lowered:
            tag = "warn"
        elif "код возврата 2" in lowered:
            tag = "err"
        else:
            tag = ""
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _set_status(self, text: str, tone: str = "idle") -> None:
        self.status.configure(text=f"●  {text}", bg=STATUS_TONES.get(tone, STATUS_TONES["idle"]))

    def _pick_target(self) -> None:
        initial = self.target_var.get().strip() or os.getcwd()
        chosen = filedialog.askdirectory(title="Каталог с исходниками",
                                         initialdir=initial, mustexist=True)
        if chosen:
            self.target_var.set(chosen)
            self._set_status(f"Выбран каталог: {chosen}", "idle")

    def _pick_file(self, variable: tk.StringVar, title: str,
                   filetypes: Sequence[Tuple[str, str]]) -> None:
        chosen = filedialog.askopenfilename(title=title, filetypes=list(filetypes))
        if chosen:
            variable.set(chosen)

    def _pick_files(self, variable: tk.StringVar, title: str,
                    filetypes: Sequence[Tuple[str, str]]) -> None:
        chosen = filedialog.askopenfilenames(title=title, filetypes=list(filetypes))
        if chosen:
            variable.set(", ".join(chosen))

    def _pick_directory(self, variable: tk.StringVar, title: str) -> None:
        initial = variable.get().strip() or os.getcwd()
        chosen = filedialog.askdirectory(title=title, initialdir=initial, mustexist=True)
        if chosen:
            variable.set(chosen)

    def _pick_save(self, variable: tk.StringVar, extension: str) -> None:
        chosen = filedialog.asksaveasfilename(
            title="Куда сохранить отчёт", defaultextension=f".{extension}",
            initialfile=os.path.basename(variable.get()) or f"argus-report.{extension}",
            filetypes=[(extension.upper(), f"*.{extension}"), ("Все файлы", "*")])
        if chosen:
            variable.set(chosen)

    def _open_report(self) -> None:
        chosen = filedialog.askopenfilename(
            title="JSON-отчёт argus", filetypes=[("JSON", "*.json"), ("Все файлы", "*")])
        if chosen:
            self._load_report(chosen)

    def _compare_report(self) -> None:
        """Compare the loaded report with an older JSON report."""
        if not self.report:
            messagebox.showinfo("argus", "Сначала загрузите или выполните сканирование.")
            return
        chosen = filedialog.askopenfilename(
            title="Старый JSON-отчёт для сравнения",
            filetypes=[("JSON", "*.json"), ("Все файлы", "*")])
        if not chosen:
            return
        from .baseline import diff_reports, load_report, render_diff

        try:
            old_report = load_report(chosen)
            diff = diff_reports(
                old_report, self.report,
                include_suppressed=self.show_suppressed_var.get(),
                old_path=chosen, new_path=self.report_path)
        except (OSError, ValueError) as exc:
            messagebox.showerror("argus", f"Не удалось сравнить отчёты:\n{exc}")
            return
        window = tk.Toplevel(self)
        window.title("argus — сравнение отчётов")
        window.geometry("980x640")
        window.configure(bg=BG)
        counts = diff.counts
        header = tk.Label(
            window, bg=HEADER, fg="#ffffff", anchor="w", padx=14, pady=8,
            font=self.font_bold,
            text=(f"Новые: {counts['new']}   Исправлено: {counts['fixed']}   "
                  f"Осталось: {counts['unchanged']}   Изменили severity: {counts['changed']}"))
        header.pack(fill="x")
        frame = ttk.Frame(window, padding=10)
        frame.pack(fill="both", expand=True)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        text = tk.Text(frame, wrap="word", bg=CARD, fg=INK, relief="flat",
                       padx=12, pady=10, font=self.font_mono)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        text.insert("1.0", render_diff(diff, "text"))
        text.configure(state="disabled")
        ttk.Button(window, text="Закрыть", command=window.destroy).pack(pady=(0, 10))

    # ------------------------------------------------------------------ scanning

    def _start(self) -> None:
        target = self.target_var.get().strip()
        if not target or not os.path.isdir(target):
            messagebox.showerror("argus", "Укажите существующий каталог с исходниками.")
            return
        if not (self.sast_var.get() or self.sca_var.get()):
            messagebox.showerror("argus", "Включите хотя бы один режим: SAST или SCA.")
            return
        output = self.output_var.get().strip()
        if not output:
            messagebox.showerror("argus", "Укажите путь для JSON-отчёта.")
            return
        summary = self.summary_var.get().strip() or None
        excludes = [item.strip() for item in self.exclude_var.get().split(",") if item.strip()]
        baseline = self.baseline_var.get().strip() or None
        if self.fail_new_var.get() and not baseline:
            messagebox.showerror("argus", "Для режима «только новые» укажите baseline-файл.")
            return
        command = build_scan_command(
            target, output, summary,
            sast=self.sast_var.get(), sca=self.sca_var.get(),
            include_dev=self.dev_var.get(), offline=self.offline_var.get(),
            fail_on=self.fail_var.get(), range_policy=self.range_var.get(),
            excludes=excludes, config=self.config_var.get().strip() or None,
            baseline=baseline, fail_on_new=self.fail_new_var.get(),
            secrets=self.secrets_var.get(), iac=self.iac_var.get(),
            deb_roots=[self.deb_root_var.get().strip()]
            if self.deb_root_var.get().strip() else [],
            deb_status=[self.deb_status_var.get().strip()]
            if self.deb_status_var.get().strip() else [],
            deb_files=[item.strip() for item in self.deb_var.get().split(",")
                       if item.strip()],
            deb_suite=self.deb_suite_var.get().strip() or None,
            owasp=self.owasp_var.get(),
            owasp_version=self.owasp_version_var.get().strip() or "2021",
            owasp_file=self.owasp_file_var.get().strip() or None)

        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            part for part in (PACKAGE_ROOT, env.get("PYTHONPATH", "")) if part)
        try:
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", env=env)
        except OSError as exc:
            messagebox.showerror("argus", f"Не удалось запустить argus:\n{exc}")
            return

        self.process = process
        self.report_path = output
        self._clear_report()
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self._log("$ " + shlex.join(command))
        self.run_button.state(["disabled"])
        self.stop_button.state(["!disabled"])
        self.progress.start(12)
        self._set_status("Сканирование выполняется…", "running")
        threading.Thread(target=self._pump, args=(process,), daemon=True).start()

    def _pump(self, process: subprocess.Popen) -> None:
        """Worker thread: forward child output to the UI queue, then report the exit code."""
        assert process.stdout is not None
        for line in process.stdout:
            self.events.put(("log", line.rstrip("\n")))
        self.events.put(("done", process.wait()))

    def _stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self._log("— остановка по запросу пользователя…")
            self._set_status("Остановка…", "warn")
            self.process.terminate()

    def _poll_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "done":
                    self._finished(payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def _finished(self, code: int) -> None:
        self.process = None
        self.progress.stop()
        self.run_button.state(["!disabled"])
        self.stop_button.state(["disabled"])
        meaning = EXIT_MEANING.get(code, "Сканирование прервано.")
        self._log(f"\nКод возврата {code}: {meaning}")
        tones = {0: ("Готово: чисто (код 0)", "ok"),
                 1: ("Готово: есть находки (код 1)", "warn"),
                 2: ("Ошибка сканирования (код 2)", "error")}
        text, tone = tones.get(code, ("Сканирование прервано", "warn"))
        self._set_status(text, tone)
        if code in (0, 1) and os.path.isfile(self.report_path):
            self._load_report(self.report_path)
            self.notebook.select(self.results_frame)

    def _on_close(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
        self.destroy()

    # ------------------------------------------------------------------ results

    def _clear_report(self) -> None:
        """Forget the previous report so a failed scan never shows stale data."""
        self.report = {}
        self.findings = []
        self.tree.delete(*self.tree.get_children())
        self._set_text(self.summary_text, "")
        self._fill_summary({})
        self._set_text(self.details, "Выберите строку, чтобы увидеть детали находки.")
        self.report_label.configure(text="Отчёт не загружен")
        self._fill_dependencies({})
        self._update_cwe_usage({})
        self.filter_var.set("")
        self.kind_filter_var.set("all")
        self.cwe_filter_var.set("all")
        self.new_only_var.set(False)
        self.show_suppressed_var.set(False)
        self.group_var.set("none")
        self._severity_filter.clear()
        self._update_chip_styles()
        self._update_cwe_filter_values()
        self._update_sort_headings()

    def _load_report(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8") as handle:
                report = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            messagebox.showerror("argus", f"Не удалось прочитать отчёт:\n{exc}")
            return
        self.findings = list(report.get("findings") or [])
        self.report = report
        target = str(report.get("target") or "")
        self.report_label.configure(text=f"Цель: {target}" if target else f"Отчёт: {path}")
        self.filter_var.set("")
        self.kind_filter_var.set("all")
        self.cwe_filter_var.set("all")
        self.new_only_var.set(False)
        self.show_suppressed_var.set(False)
        self.group_var.set("none")
        self._severity_filter.clear()
        self._update_chip_styles()
        self._update_cwe_filter_values()
        self._fill_summary(report)
        self._fill_dependencies(report)
        self._update_cwe_usage(report)
        self._render_results()
        self._set_text(self.details, "Выберите строку, чтобы увидеть детали находки.")
        if target:
            self._set_status(f"Сканировано: {target}", "idle")

    def _fill_summary(self, report: Dict[str, Any]) -> None:
        summary = report.get("summary") or {}
        by_severity = summary.get("by_severity") or {}
        by_kind = summary.get("by_kind") or {}
        status = str(summary.get("status") or "нет данных")
        status_tag = f"status-{status}" if status in ("findings", "clean", "error") else \
            "status-default"
        ecosystems = ", ".join(f"{name}: {count}"
                               for name, count in (summary.get("by_ecosystem") or {}).items()) \
            or "нет"
        rules = summary.get("top_rules") or []

        widget = self.summary_text
        widget.configure(state="normal")
        widget.delete("1.0", "end")

        def row(label: str, value: str, tag: str = "value") -> None:
            widget.insert("end", f"{label}: ", "label")
            widget.insert("end", value + "\n", tag)

        row("Статус", status, status_tag)
        row("Находок", f"{summary.get('total', 0)}  ·  максимальная severity: "
                       f"{summary.get('max_severity', 'unknown')}", "strong")
        if summary.get("suppressed") or summary.get("new") or summary.get("existing"):
            row("Baseline",
                f"new {summary.get('new', 0)}  ·  existing {summary.get('existing', 0)}  ·  "
                f"suppressed {summary.get('suppressed', 0)}", "accent")
        row("По severity", ", ".join(f"{name} {by_severity[name]}"
                                    for name in SEVERITY_ORDER if by_severity.get(name)) or "нет")
        row("По типу", f"SAST {by_kind.get('sast', 0)}  ·  SCA {by_kind.get('sca', 0)}")
        by_owasp = summary.get("by_owasp") or {}
        if by_owasp:
            edition = summary.get("owasp_version") or ""
            row("OWASP Top 10",
                f"{edition}: " + "  ·  ".join(
                    f"{label} ×{count}" for label, count in by_owasp.items()),
                "accent")
        else:
            row("OWASP Top 10", "нет")
        graph_ready = bool(summary.get("dependency_graph"))
        row("Инвентарь",
            f"{summary.get('packages', 0)} пакетов  ·  "
            f"direct {summary.get('packages_direct', 0)} / "
            f"transitive {summary.get('packages_transitive', 0)} / "
            f"unknown {summary.get('packages_unknown', 0)}  ·  "
            f"дерево {'resolved' if graph_ready else 'not resolved'}",
            "accent" if summary.get("packages_transitive", 0) else "value")
        row("Экосистемы", ecosystems)
        row("Ошибки", str(summary.get("errors", 0)))
        if rules:
            row("Топ правил", "; ".join(f"{rule.get('rule_id', '')} ×{rule.get('count', 0)}"
                                       for rule in rules[:5]), "accent")
        widget.configure(state="disabled")

        for severity in SEVERITY_ORDER:
            self.chips[severity].configure(text=f"{severity}  {by_severity.get(severity, 0)}")

    def _toggle_severity(self, severity: str) -> None:
        """Treat severity chips as toggle filters."""
        if severity in self._severity_filter:
            self._severity_filter.discard(severity)
        else:
            self._severity_filter.add(severity)
        self._update_chip_styles()
        self._render_results()

    def _update_chip_styles(self) -> None:
        for severity, chip in self.chips.items():
            colors = SEVERITY_COLORS[severity]
            active = severity in self._severity_filter
            chip.configure(
                highlightbackground=INK if active else colors["chip"],
                highlightthickness=3 if active else 2,
                relief="solid" if active else "flat")

    def _reset_filters(self) -> None:
        self.filter_var.set("")
        self.kind_filter_var.set("all")
        self.cwe_filter_var.set("all")
        self.new_only_var.set(False)
        self.show_suppressed_var.set(False)
        self.group_var.set("none")
        self._severity_filter.clear()
        self._update_chip_styles()
        self._render_results()

    def _update_cwe_filter_values(self) -> None:
        values = {"all"}
        for finding in self.findings:
            cwe = str(finding.get("cwe") or "")
            if cwe:
                values.add(cwe)
            else:
                values.add("(нет)")
        ordered = ["all"] + sorted(value for value in values if value != "all")
        if hasattr(self, "cwe_filter_box"):
            self.cwe_filter_box.configure(values=ordered)
            if self.cwe_filter_var.get() not in ordered:
                self.cwe_filter_var.set("all")

    def _finding_matches(self, finding: Dict[str, Any]) -> bool:
        if finding.get("suppressed") and not self.show_suppressed_var.get():
            return False
        if self.new_only_var.get() and finding.get("baseline") != "new":
            return False
        severity = str(finding.get("severity") or "unknown")
        if self._severity_filter and severity not in self._severity_filter:
            return False
        kind_filter = self.kind_filter_var.get()
        if kind_filter != "all" and str(finding.get("kind") or "") != kind_filter:
            return False
        cwe_filter = self.cwe_filter_var.get()
        if cwe_filter not in ("", "all"):
            cwe = str(finding.get("cwe") or "")
            if cwe_filter == "(нет)":
                if cwe:
                    return False
            elif cwe != cwe_filter:
                return False
        query = self.filter_var.get().strip().lower()
        if query:
            package = finding.get("package") or {}
            location = finding.get("location") or {}
            haystack = " ".join(str(item) for item in (
                finding.get("rule_id"), finding.get("title"), finding.get("message"),
                finding.get("cwe"), finding.get("cwe_name"), finding.get("cwe_name_ru"),
                finding.get("engine"), finding.get("kind"),
                package.get("name"), package.get("version"),
                location.get("file"),
                " ".join(finding.get("remediation") or ()),
                finding.get("suggested_fix"),
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
        group = self.group_var.get()
        package = finding.get("package") or {}
        if group == "severity":
            return str(finding.get("severity") or "unknown"), str(finding.get("severity") or "unknown")
        if group == "kind":
            return str(finding.get("kind") or "unknown"), str(finding.get("kind") or "unknown")
        if group == "rule":
            return str(finding.get("rule_id") or "?"), str(finding.get("rule_id") or "?")
        if group == "cwe":
            cwe = str(finding.get("cwe") or "")
            label = cwe or "(нет CWE)"
            name = finding.get("cwe_name_ru") or finding.get("cwe_name")
            if cwe and name:
                label = f"{cwe} — {name}"
            return cwe or "(нет)", label
        if group == "package":
            name = str(package.get("name") or "")
            return name.lower() or "zzz", name or "(нет пакета)"
        return "", ""

    def _render_results(self) -> None:
        """Rebuild the results table from the active filters and sort order."""
        selection = self.tree.selection()
        keep = selection[0] if selection and not selection[0].startswith("group:") else ""
        self.tree.delete(*self.tree.get_children())
        ordered = self._filtered_indices()
        group = self.group_var.get()
        if group == "none":
            for index in ordered:
                finding = self.findings[index]
                severity = str(finding.get("severity") or "unknown")
                tags = (severity,) if severity in SEVERITY_COLORS else ()
                self.tree.insert("", "end", iid=str(index), values=finding_row(finding),
                                 tags=tags)
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

            for position, key in enumerate(sorted(groups, key=group_order)):
                count = len(groups[key])
                group_iid = f"group:{position}"
                self.tree.insert(
                    "", "end", iid=group_iid, open=True,
                    values=("", "", "", "", "", "", "", f"▸ {labels[key]}  ({count})"),
                    tags=("group",))
                for index in groups[key]:
                    finding = self.findings[index]
                    severity = str(finding.get("severity") or "unknown")
                    tags = (severity,) if severity in SEVERITY_COLORS else ()
                    self.tree.insert(group_iid, "end", iid=str(index),
                                     values=finding_row(finding), tags=tags)
        if keep and self.tree.exists(keep):
            self.tree.selection_set(keep)
        visible = len(ordered)
        total = len(self.findings)
        hidden_suppressed = sum(1 for finding in self.findings
                                if finding.get("suppressed")
                                and not self.show_suppressed_var.get())
        extra = f"  ·  suppressed скрыто: {hidden_suppressed}" if hidden_suppressed else ""
        self.filter_label.configure(
            text=f"Показано {visible} из {total}{extra}"
                 + ("  ·  только новые" if self.new_only_var.get() else ""))
        self._update_sort_headings()

    def _sort_results(self, column: str) -> None:
        current = self._results_sort
        if current and current[0] == column:
            descending = not current[1]
        else:
            descending = default_sort_desc(column)
        self._results_sort = (column, descending)
        self._render_results()

    def _sort_dependencies(self, column: str) -> None:
        current = self._deps_sort
        if current and current[0] == column:
            descending = not current[1]
        else:
            descending = default_sort_desc(column) if column == "severity" else False
        self._deps_sort = (column, descending)
        self._fill_dependencies(self.report, preserve_selection=True)

    def _update_sort_headings(self) -> None:
        """Draw ▲/▼ in the heading of the column that defines the order."""
        results = self._results_sort
        for column in RESULT_COLUMNS:
            arrow = ""
            if results and results[0] == column:
                arrow = " ▼" if results[1] else " ▲"
            self.tree.heading(column, text=RESULT_HEADINGS[column] + arrow)
        deps = self._deps_sort
        for column in ("#0",) + DEP_COLUMNS:
            arrow = ""
            if deps and deps[0] == column:
                arrow = " ▼" if deps[1] else " ▲"
            self.deps_tree.heading(column, text=DEP_HEADINGS[column] + arrow)

    def _fill_dependencies(self, report: Dict[str, Any],
                           preserve_selection: bool = False) -> None:
        selected_ref = ""
        if preserve_selection:
            selection = self.deps_tree.selection()
            if selection:
                selected_ref = self._dep_ref_by_iid.get(selection[0], "")
        self.report = report
        self.deps_tree.delete(*self.deps_tree.get_children())
        self.dep_paths = {}
        self.dep_iids = {}
        self._dep_ref_by_iid = {}
        graph = ((report.get("stats") or {}).get("dependency_graph") or {})
        sort_column, descending = self._deps_sort or ("", False)
        rows = dependency_rows(report, sort_column, descending)
        unique_rows = {row["ref"]: row for row in rows}
        if unique_rows:
            direct = sum(1 for row in unique_rows.values() if row["direct"] is True)
            transitive = sum(1 for row in unique_rows.values() if row["direct"] is False)
            unknown = sum(1 for row in unique_rows.values() if row["direct"] is None)
            state = "resolved" if graph.get("resolved") else "not resolved"
            self.deps_label.configure(
                text=f"Пакетов: {len(unique_rows)}  ·  direct {direct} / "
                     f"transitive {transitive} / unknown {unknown}  ·  graph {state}")
        else:
            self.deps_label.configure(text="В отчёте нет данных о зависимостях")

        first_iid: Dict[str, str] = {}
        for index, row in enumerate(rows):
            parent = first_iid.get(row["parent"], "") if row["parent"] else ""
            severity = row["severity"] if row["severity"] in SEVERITY_COLORS else ""
            depth = "-" if row["depth"] is None else str(row["depth"])
            text = row["name"] + ("  (cycle)" if row["cycle"] else "")
            iid = f"dep-{index}"
            self.deps_tree.insert(
                parent, "end", iid=iid, text=text,
                values=(row["version"], row["ecosystem"], _direct_label(row["direct"]),
                        depth, severity or "-"),
                tags=(severity,) if severity else (),
                open=True,
            )
            first_iid.setdefault(row["ref"], iid)
            self._dep_ref_by_iid[iid] = row["ref"]

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

        self.dep_iids = first_iid
        self.dep_paths = {ref: path_for(ref) for ref in by_ref}
        if selected_ref:
            iid = first_iid.get(selected_ref)
            if iid:
                self.deps_tree.selection_set(iid)
                self.deps_tree.focus(iid)
                self.deps_tree.see(iid)
        self._update_sort_headings()

    def _show_dependencies_tab(self) -> None:
        self.notebook.select(self.deps_frame)

    def _fill_cwe_list(self) -> None:
        """Apply the current search string to the CWE catalog list."""
        if not hasattr(self, "cwe_tree"):
            return
        selected_id = ""
        selection = self.cwe_tree.selection()
        if selection:
            entry = self._cwe_entries.get(selection[0])
            if entry is not None:
                selected_id = f"cwe-{entry.id}"
        entries = cwe_catalog.search(self.cwe_search_var.get())
        self.cwe_tree.delete(*self.cwe_tree.get_children())
        self._cwe_entries = {}
        for entry in entries:
            count = self._cwe_usage.get(entry.id, 0)
            iid = f"cwe-{entry.id}"
            self.cwe_tree.insert(
                "", "end", iid=iid,
                values=(entry.cwe_id, entry.name_ru, entry.category,
                        count if count else ""),
                tags=("used",) if count else (),
            )
            self._cwe_entries[iid] = entry
        total = len(cwe_catalog.all_entries())
        query = self.cwe_search_var.get().strip()
        self.cwe_label.configure(
            text=f"{len(entries)} из {total}" + (f"  ·  фильтр: {query}" if query else ""))
        target = selected_id if selected_id in self._cwe_entries else ""
        if not target and entries:
            target = f"cwe-{entries[0].id}"
        if target:
            self.cwe_tree.selection_set(target)
            self.cwe_tree.focus(target)
            self.cwe_tree.see(target)
            self._show_cwe_details()

    def _show_cwe_details(self, _event: Any = None) -> None:
        selection = self.cwe_tree.selection()
        if not selection:
            return
        entry = self._cwe_entries.get(selection[0])
        if entry is None:
            return
        self._set_text(self.cwe_details,
                       format_cwe_entry(entry, self._cwe_usage.get(entry.id, 0)))

    def _open_cwe_link(self) -> None:
        selection = self.cwe_tree.selection()
        entry = self._cwe_entries.get(selection[0]) if selection else None
        if entry is None:
            entry = cwe_catalog.lookup(self.cwe_search_var.get())
        if entry is None:
            self._set_status("Выберите запись CWE", "warn")
            return
        try:
            webbrowser.open(entry.url)
        except Exception as exc:  # noqa: BLE001 - browser may be unavailable
            messagebox.showerror("argus", f"Не удалось открыть браузер:\n{exc}")
            return
        self._set_status(f"Открыто: {entry.url}", "idle")

    def _reset_cwe_search(self) -> None:
        self.cwe_search_var.set("")
        self._fill_cwe_list()
        self.cwe_search_entry.focus_set()

    def _show_cwe_reference(self) -> None:
        """Open the CWE tab, focusing the weakness of the selected finding."""
        self.notebook.select(self.cwe_frame)
        selection = self.tree.selection()
        entry = None
        if selection and not selection[0].startswith("group:"):
            finding = self.findings[int(selection[0])]
            entry = cwe_catalog.lookup(finding.get("cwe"))
        if entry is None:
            self.cwe_search_entry.focus_set()
            return
        self.cwe_search_var.set("")
        self._fill_cwe_list()
        iid = f"cwe-{entry.id}"
        if self.cwe_tree.exists(iid):
            self.cwe_tree.selection_set(iid)
            self.cwe_tree.focus(iid)
            self.cwe_tree.see(iid)
            self._show_cwe_details()
        self._set_status(f"Справочник CWE: {entry.cwe_id} — {entry.name_ru}", "idle")

    def _update_cwe_usage(self, report: Dict[str, Any]) -> None:
        """Count how often each CWE appears in the loaded report."""
        usage: Dict[int, int] = {}
        for finding in report.get("findings") or []:
            entry = cwe_catalog.lookup(finding.get("cwe"))
            if entry is not None:
                usage[entry.id] = usage.get(entry.id, 0) + 1
        self._cwe_usage = usage
        self._fill_cwe_list()

    def _place_results_sash(self, fraction: float = 0.55) -> None:
        """Give the details pane a comfortable default height."""
        try:
            height = self.results_split.winfo_height()
            if height > 120:
                self.results_split.sashpos(0, max(110, int(height * fraction)))
        except tk.TclError:
            pass

    def _place_cwe_sash(self, fraction: float = 0.60) -> None:
        """Give the catalog list enough width for all columns."""
        try:
            if self.notebook.select() != str(self.cwe_frame):
                return
            width = self.cwe_split.winfo_width()
            if width > 200:
                self.cwe_split.sashpos(0, int(width * fraction))
                self._cwe_sash_done = True
        except tk.TclError:
            pass

    def _on_tab_changed(self, _event: Any = None) -> None:
        if not self._cwe_sash_done and self.notebook.select() == str(self.cwe_frame):
            self.after_idle(self._place_cwe_sash)

    def _toggle_details(self) -> None:
        self._details_expanded = not self._details_expanded
        fraction = 0.25 if self._details_expanded else 0.55
        self._place_results_sash(fraction)
        self.details_button.configure(
            text="Свернуть детали" if self._details_expanded else "Развернуть детали")

    def _locate_in_dependencies(self, event: Any = None) -> None:
        if event is not None:
            row_id = self.tree.identify_row(event.y)
            if row_id:
                self.tree.selection_set(row_id)
                self._show_selected()
        selection = self.tree.selection()
        if not selection or selection[0].startswith("group:"):
            return
        finding = self.findings[int(selection[0])]
        package = finding.get("package") or {}
        purl = str(package.get("purl") or "")
        iid = self.dep_iids.get(purl)
        if not iid:
            self._set_status("Для этой находки пакета в дереве зависимостей нет", "warn")
            return
        self._show_dependencies_tab()
        self.deps_tree.selection_set(iid)
        self.deps_tree.focus(iid)
        self.deps_tree.see(iid)
        self._set_status(f"Дерево зависимостей: {package.get('name', '')} "
                         f"{package.get('version', '')}".strip(), "idle")

    def _show_selected(self, _event: Any = None) -> None:
        selection = self.tree.selection()
        if not selection or selection[0].startswith("group:"):
            return
        finding = self.findings[int(selection[0])]
        purl = str((finding.get("package") or {}).get("purl") or "")
        self._set_text(self.details, format_finding(finding, self.dep_paths.get(purl)))


def _qt_available() -> bool:
    try:
        import PySide6  # noqa: F401
    except ImportError:
        return False
    return True


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--tk" not in args and _qt_available():
        from . import gui_qt
        return gui_qt.main(["argus-gui"] + [a for a in args if a != "--qt"])
    try:
        app = ArgusApp()
    except tk.TclError as exc:
        print(f"argus-gui: cannot open a display ({exc})", file=sys.stderr)
        return 2
    app.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
