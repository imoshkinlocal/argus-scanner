"""Toolkit-independent logic shared by the desktop front-ends.

Everything here is pure Python (no tkinter, no Qt): command assembly, report
formatting, sorting, filtering helpers and palette constants.  The Tk window in
``argus.gui`` and the Qt window in ``argus.gui_qt`` both build on it, so the
two interfaces always show the same data.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__, cwe as cwe_catalog

PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FAIL_ON_CHOICES = ("high", "critical", "medium", "low", "info", "none")
RANGE_CHOICES = ("min", "skip")
#: Releases accepted by ``--deb-suite``; free text stays allowed for others.
DEB_SUITE_CHOICES = (
    "bookworm", "bullseye", "trixie", "stretch", "buster", "forky",
    "jammy", "noble", "focal", "bionic", "xenial", "oracular", "plucky",
    "12", "11", "13", "10", "9", "22.04", "24.04", "20.04",
)
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")
_SEVERITY_PRIORITY = {name: len(SEVERITY_ORDER) - index
                      for index, name in enumerate(SEVERITY_ORDER)}
_DIRECT_PRIORITY = {True: 2, False: 1, None: 0}

RESULT_COLUMNS = ("severity", "kind", "rule", "cwe", "where", "engine", "relation", "message")
RESULT_HEADINGS = {
    "severity": "Severity",
    "kind": "Тип",
    "rule": "Правило / CVE",
    "cwe": "CWE",
    "where": "Место / пакет",
    "engine": "Движок",
    "relation": "Зависимость",
    "message": "Описание",
}
RESULT_WIDTHS = (80, 55, 160, 95, 210, 90, 105, 330)
DEP_COLUMNS = ("version", "ecosystem", "direct", "depth", "severity")
DEP_HEADINGS = {
    "#0": "Пакет",
    "version": "Версия",
    "ecosystem": "Экосистема",
    "direct": "Тип",
    "depth": "Глубина",
    "severity": "Severity",
}
DEP_WIDTHS = (130, 120, 100, 80, 90)


def default_sort_desc(column: str) -> bool:
    """Severity looks best with critical first; other columns ascending."""
    return column == "severity"


def sort_finding_indices(findings: List[Dict[str, Any]], column: str,
                         descending: bool = False) -> List[int]:
    """Return original finding indices ordered by a results-table column."""
    indices = list(range(len(findings)))
    if not column:
        return indices

    def key(index: int):
        finding = findings[index]
        package = finding.get("package") or {}
        severity = str(finding.get("severity") or "unknown")
        if column == "severity":
            primary = _SEVERITY_PRIORITY.get(severity, 0)
        elif column == "kind":
            primary = str(finding.get("kind") or "").lower()
        elif column == "rule":
            primary = str(finding.get("rule_id") or "").lower()
        elif column == "cwe":
            primary = str(finding.get("cwe") or "").lower()
        elif column == "where":
            primary = finding_row(finding)[4].lower()
        elif column == "engine":
            primary = str(finding.get("engine") or "").lower()
        elif column == "relation":
            direct = package.get("direct")
            depth = package.get("depth")
            primary = (_DIRECT_PRIORITY.get(direct, 0),
                       999 if depth is None else int(depth))
        else:  # message
            primary = str(finding.get("message") or finding.get("title") or "").lower()
        rule = str(finding.get("rule_id") or "").lower()
        where = finding_row(finding)[4].lower()
        return (primary, rule, where)

    indices.sort(key=key, reverse=descending)
    return indices


def _dependency_sort_key(node: Dict[str, Any], severity: str,
                         column: str):
    name = str(node.get("name") or "").lower()
    version = str(node.get("version") or "")
    ecosystem = str(node.get("ecosystem") or "").lower()
    if column == "severity":
        primary = _SEVERITY_PRIORITY.get(severity, 0)
    elif column == "direct":
        primary = _DIRECT_PRIORITY.get(node.get("direct"), 0)
    elif column == "depth":
        depth = node.get("depth")
        primary = 999 if depth is None else int(depth)
    elif column == "version":
        primary = version
    elif column == "ecosystem":
        primary = ecosystem
    else:  # name / #0
        primary = name
    return (primary, name, version)


EXIT_MEANING = {
    0: "Чисто: находок на уровне --fail-on и выше нет.",
    1: "Есть находки на уровне --fail-on или выше. Откройте вкладку «Результаты».",
    2: "Ошибка сканирования (нет каталога, нет Semgrep, сетевой сбой). См. журнал.",
}

# --------------------------------------------------------------------------- palette

BG = "#eef2f9"
CARD = "#ffffff"
BORDER = "#d7dfec"
INK = "#1f2937"
MUTED = "#64748b"
ACCENT = "#2563eb"
ACCENT_DARK = "#1d4ed8"
ACCENT_SOFT = "#e0e7ff"
HEADER = "#111827"
HEADER_ACCENT = "#93c5fd"
OK = "#15803d"
ERROR = "#b91c1c"
WARN = "#b45309"
CONSOLE_BG = "#0b1220"
CONSOLE_FG = "#cbd5e1"

STATUS_TONES = {
    "idle": "#334155",
    "running": ACCENT,
    "ok": OK,
    "warn": WARN,
    "error": ERROR,
}

SEVERITY_COLORS: Dict[str, Dict[str, str]] = {
    "critical": {"row": "#ffe4e6", "fg": "#9f1239", "chip": "#e11d48", "chip_fg": "#ffffff"},
    "high": {"row": "#ffedd5", "fg": "#9a3412", "chip": "#f97316", "chip_fg": "#ffffff"},
    "medium": {"row": "#fef9c3", "fg": "#854d0e", "chip": "#eab308", "chip_fg": "#1f2937"},
    "low": {"row": "#dbeafe", "fg": "#1e40af", "chip": "#3b82f6", "chip_fg": "#ffffff"},
    "info": {"row": "#e5e7eb", "fg": "#374151", "chip": "#9ca3af", "chip_fg": "#ffffff"},
    "unknown": {"row": "#f1f5f9", "fg": "#475569", "chip": "#cbd5e1", "chip_fg": "#334155"},
}

HELP_TEXT = """\
argus — SAST + SCA сканер

ЧТО ПРОВЕРЯЕТ
• SAST — статический анализ исходного кода: инъекции (SQL, команды ОС, LDAP, XPath),
  XSS, небезопасные файловые операции, слабая криптография и др.
• Секреты — ключи, токены, приватные ключи и пароли в коде (CWE-798).
• IaC — Dockerfile, Kubernetes-манифесты и Terraform (CWE-16/CWE-250).
• SCA — поиск уязвимых версий зависимостей по базе OSV.dev (CVE, GHSA).
  Для Debian/Ubuntu дополнительно читаются debian/control, dpkg-статус и .deb.

КАК ПОЛЬЗОВАТЬСЯ
1. Выберите каталог с исходниками кнопкой «Выбрать каталог…». Проверяется весь каталог
   рекурсивно. Служебные папки (.git, node_modules, vendor, build, .venv) пропускаются.
2. Отметьте режимы: SAST и/или SCA. SCA нужен доступ к api.osv.dev либо локальная база
   (см. «Офлайн» ниже).
3. Задайте порог --fail-on: при находке этого уровня и выше argus вернёт код 1.
4. Укажите, куда записать JSON и Markdown-отчёты (по умолчанию — текущий каталог).
5. Нажмите «Запустить сканирование». Ход работы виден в журнале; по завершении отчёт
   открывается во вкладке «Результаты». Вкладка «Зависимости» показывает дерево,
   восстановленное из lock-файлов. Двойной клик по SCA-находке сразу открывает
   её пакет в дереве.
6. Панель с деталями находки можно увеличить: потяните мышью за разделитель
   между таблицей и нижним текстовым блоком или нажмите «Развернуть детали».
7. Сортировка: щёлкните по заголовку колонки в «Результатах» или «Зависимостях».
   Повторный клик меняет направление, стрелка ▲/▼ показывает текущий порядок.
   Severity по умолчанию сортируется по убыванию (critical сверху).

ВКЛАДКА «ЗАВИСИМОСТИ»
• Иерархическое дерево «пакет → его зависимости» с версией, экосистемой,
  признаком direct/transitive и глубиной.
• Сортировка переставляет корни и дочерние узлы внутри каждого родителя,
  сохраняя иерархию.
• В таблице находок есть колонка «Зависимость»: direct/transitive и глубина.
  При выборе находки в деталях показывается путь от корня до пакета.
• Двойной клик по строке SCA-находки переключает на дерево и подсвечивает пакет.
• Дерево строится по lock-файлам, где разрешение версий уже зафиксировано:
  Gemfile.lock, package-lock.json, poetry.lock, uv.lock, composer.lock, Cargo.lock.
• Для go.mod известны direct/indirect, но не рёбра: пакеты показываются списком.
• Если lock-файла нет, пакеты из манифестов помечаются direct, а глубина остаётся
  неизвестной — граф не выдумывается.

ВКЛАДКА «CWE»
• Встроенный офлайн-справочник по слабостям CWE из отчёта и правил argus:
  номер, название, категория, описание, последствия и меры защиты.
• Поиск работает по номеру, названию, категории и тексту описания.
• Записи, встречающиеся в текущем отчёте, подсвечены и показывают число находок.
• В деталях находки выводится расшифровка CWE и ссылка на MITRE; кнопка
  «Справочник CWE →» открывает нужную запись. Незнакомый CWE откроется
  заглушкой со ссылкой на официальную страницу.
• В терминале: `argus cwe`, `argus cwe 79 89`, `argus cwe --search sql`,
  `argus cwe 79 -f md|json`.

OWASP TOP 10
• Каждая находка с CWE сопоставляется с категорией OWASP Top 10 (A01…A10).
  В деталях видны категории, названия и ссылки, в сводке — распределение находок.
• Версия выбирается в окне сканирования: 2017, 2021 (по умолчанию) или 2025.
  Свой JSON/TOML-файл заменяет встроенный справочник и позволяет обновить
  сопоставление без пересборки argus.
• В терминале: `argus owasp`, `argus owasp 89 79`, `argus owasp --version 2025`,
  `argus owasp 89 -f json`. Отключение: `--no-owasp`.

КОНФИГ, BASELINE И ПОДАВЛЕНИЯ
• Конфиг — кнопка «…» рядом с полем: argus.toml или argus.json. Без файла argus
  ищет его вверх по дереву (ARGUS_CONFIG тоже учитывается). CLI-флаги важнее
  конфига, относительные пути считаются от каталога конфига.
• Baseline — JSON-снимок находок. «Записать baseline» создаёт его после скана,
  «Baseline» подставляет файл, «Падать только на новом» добавляет --fail-on-new.
  Сравнение идёт по стабильному ключу, поэтому сдвиг строк не делает находки
  новыми.
• Подавления (.argusignore / JSON / TOML) скрывают принятый риск из exit code и
  обычных отчётов; переключатель «Показать подавленные» возвращает их в таблицу.
• Quality gates из [gates]/[policies] (max_total, max_by_severity,
  deny_packages, deny_cwes, max_cvss, deny_licenses) печатаются в журнале;
  нарушение даёт код 1.

DEBIAN / UBUNTU (SCA)
• Блок «2b · Пакеты Debian/Ubuntu»:
  «Корень системы» (--deb-root) читает <корень>/var/lib/dpkg/status и сам
  определяет релиз из /etc/os-release или /etc/debian_version; «/» — текущая система.
  «Статус dpkg» (--deb-status) и «Файлы .deb» (--deb, через запятую) не знают
  релиз, поэтому для них укажите «Релиз» (--deb-suite): bookworm, jammy, 12, 22.04.
• Без релиза такие пакеты пропускаются с предупреждением: OSV публикует
  Debian- и Ubuntu-советники по релизам (Debian:12, Ubuntu:22.04:LTS), и чужая
  ветка дала бы неверные «исправленные» версии.
• Зависимости из debian/control получают релиз из debian/changelog (поле
  distribution) или из явного --deb-suite. В отчётах и SBOM у Debian-пакетов
  есть свойства argus:deb-distro и argus:deb-arch, purl вида
  pkg:deb/debian/… или pkg:deb/ubuntu/….
• Офлайн-база: `argus db update --ecosystem Debian` (~85 МБ) или
  `argus db update --ecosystem Ubuntu` (~800 МБ, включает все релизы).

THREAT INTELLIGENCE
• SCA-находки можно обогатить EPSS (вероятность эксплуатации) и CISA KEV
  (известные эксплуатации, ransomware, дедлайн). Включается в конфиге
  [sca] threat_intel = true или флагом --threat-intel.
• Кэш EPSS/KEV обновляется раз в 12 часов; --no-threat-cache его игнорирует,
  --epss-file/--kev-file задают локальные JSON для офлайна.
• В таблице SCA появляются колонки EPSS и KEV, в SARIF — properties.epss,
  epss_percentile, kev, kev_ransomware, kev_due_date.

SBOM, VEX И DIFF
• SBOM: `argus sbom . -f cyclonedx|spdx|md`; лицензии и хэши берутся из
  lock-файлов, документ всегда содержит SHA-256, а с --sign-key/ARGUS_SBOM_KEY —
  HMAC-SHA256. Проверка: `argus sbom --verify FILE`.
• VEX: `argus vex report.json -o report.vex.json` — OpenVEX 0.2.0 со статусами
  affected / not_affected / fixed.
• Diff: в GUI отчёт можно сравнить с предыдущим JSON (новые, исправленные,
  изменившиеся находки); в терминале — `argus diff old.json new.json`.

ОПЦИИ
• Включить dev/test-зависимости — учитывать зависимости только для разработки и тестов.
• Офлайн — использовать только локальную базу OSV. Сначала выполните в терминале
  `argus db update`.
• Диапазоны версий: min — для «>=» и «~>» берётся нижняя граница версии (такие находки
  помечаются assumed); skip — учитываются только точные версии.
• Исключить пути — через запятую. Для SAST это подстрока пути (например, tests),
  для SCA — glob по пути манифеста (например, */tests/*).
• Секреты и IaC включены по умолчанию; отключаются флагами --no-secrets/--no-iac.
• OWASP Top 10 включён по умолчанию; --owasp-version 2017|2021|2025,
  --owasp-file PATH и --no-owasp управляют сопоставлением.
• Инкрементальный кэш Java-анализа включён по умолчанию (--no-sast-cache его
  отключает). Контекст сниппетов задаётся числом строк; 0 = --no-context.

ЦВЕТА В ТАБЛИЦЕ
• Красный — critical, оранжевый — high, жёлтый — medium, синий — low,
  серый — info/unknown. Цвет строки повторяет severity находки.

ВЫХОДНЫЕ ДАННЫЕ
• JSON (schema 1.1) — машиночитаемый отчёт для CI и парсинга. Ключи верхнего
  уровня: summary, stats, findings, errors. В summary: total (активные), all,
  suppressed, new, existing, by_severity (только активные), by_kind, by_engine,
  by_owasp, owasp_version, by_ecosystem, packages, packages_direct, packages_transitive,
  packages_unknown, dependency_graph, max_severity, errors, status (findings|clean|error),
  top_rules. В stats: dependency_graph, workflow, gate, threat_intel, sast_cache,
  offline_db, secrets/iac. Каждая находка: id, kind (sast|sca), engine, rule_id,
  severity, cwe, cwe_name, owasp (id вида A03:2021, названия и ссылка), message,
  remediation, baseline (new|existing),
  suppressed/suppression, snippet, location (файл и строка) или package
  (имя, версия, fixed_version, purl, direct, depth, licenses), metadata
  (cvss, epss, kev и др.).
• Markdown — человекочитаемый отчёт: статус, gate/baseline/threat intel,
  таблицы по severity, распределение OWASP Top 10, сработавшие правила,
  SAST-находки (файл:строка, CWE, OWASP, сниппет), SCA-находки (EPSS, KEV,
  пакет, версия, исправление), remediation, dependency tree и ошибки.
• SARIF 2.1.0 — для CI-систем: CWE, OWASP-теги owasp/aNN-YYYY, remediation,
  baselineState, suppressions и threat-поля в properties.
• OpenVEX 0.2.0 — `argus vex report.json`.
• Коды возврата: 0 — чисто; 1 — есть находки на уровне --fail-on или выше либо
  не пройден quality gate; 2 — ошибка сканирования или неверная подпись SBOM.

SBOM (CycloneDX 1.5 / SPDX 2.3 / Markdown) формируется командой `argus sbom`;
VEX — командой `argus vex`, сравнение отчётов — `argus diff`.

ОГРАНИЧЕНИЯ
• Анализ внутрифайловый: межфайловые потоки данных не отслеживаются.
• Spring MVC покрыт только на уровне аннотированных параметров контроллера
  (@RequestParam, @RequestBody, @PathVariable и др.), без конфигураций и бинов.
• SCA не разрешает версии онлайн: берутся манифесты и lock-файлы. Транзитивное
  дерево строится только там, где lock-файл содержит рёбра; без него видны только
  direct-зависимости и известная глубина.
• EPSS/KEV — внешние фиды; при отсутствии сети используется кэш, возможно
  устаревший. Локальные --epss-file/--kev-file нужно обновлять самостоятельно.
• SBOM содержит только те лицензии и хэши, которые объявлены в lock-файлах;
  остальное остаётся пустым / NOASSERTION.
• Debian/Ubuntu: советники OSV привязаны к релизу; без --deb-suite (или
  rootfs/changelog) пакеты пропускаются. Ubuntu Pro/ESM-советники
  (Ubuntu:Pro:…) не запрашиваются — определяется только базовый релиз.
• Срабатывание — повод для проверки, а не окончательный вердикт.
"""


def build_scan_command(
    target: str,
    output: str,
    summary: Optional[str] = None,
    *,
    sast: bool = True,
    sca: bool = True,
    include_dev: bool = False,
    offline: bool = False,
    fail_on: str = "high",
    range_policy: str = "min",
    excludes: Sequence[str] = (),
    config: Optional[str] = None,
    baseline: Optional[str] = None,
    fail_on_new: bool = False,
    secrets: bool = True,
    iac: bool = True,
    include_suppressed: bool = False,
    context_lines: int = 2,
    deb_roots: Sequence[str] = (),
    deb_status: Sequence[str] = (),
    deb_files: Sequence[str] = (),
    deb_suite: Optional[str] = None,
    owasp: bool = True,
    owasp_version: str = "2021",
    owasp_file: Optional[str] = None,
) -> List[str]:
    """Return the ``argus scan`` argument vector for the given GUI options."""
    command = [sys.executable, "-m", "argus.cli", "scan", target,
               "-f", "json", "-o", output,
               "--fail-on", fail_on, "--range-policy", range_policy]
    if summary:
        command += ["--summary", summary]
    if not sast:
        command.append("--no-sast")
    if not sca:
        command.append("--no-sca")
    if include_dev:
        command.append("--include-dev")
    if offline:
        command.append("--offline")
    if config:
        command += ["--config", config]
    if baseline:
        command += ["--baseline", baseline]
    if fail_on_new:
        command.append("--fail-on-new")
    if not secrets:
        command.append("--no-secrets")
    if not iac:
        command.append("--no-iac")
    if include_suppressed:
        command.append("--include-suppressed")
    if context_lines <= 0:
        command.append("--no-context")
    elif context_lines != 2:
        command += ["--context-lines", str(context_lines)]
    for pattern in excludes:
        command += ["--exclude", pattern]
    for root in deb_roots:
        command += ["--deb-root", root]
    for status in deb_status:
        command += ["--deb-status", status]
    for archive in deb_files:
        command += ["--deb", archive]
    if deb_suite:
        command += ["--deb-suite", deb_suite]
    if owasp:
        if owasp_version and owasp_version != "2021":
            command += ["--owasp-version", owasp_version]
        if owasp_file:
            command += ["--owasp-file", owasp_file]
    else:
        command.append("--no-owasp")
    return command


def format_summary(report: Dict[str, Any]) -> str:
    """Render the machine ``summary`` block as plain text for the results tab."""
    summary = report.get("summary") or {}
    by_severity = summary.get("by_severity") or {}
    by_kind = summary.get("by_kind") or {}
    severities = ", ".join(f"{name} {by_severity[name]}"
                           for name in SEVERITY_ORDER if by_severity.get(name)) or "нет"
    engines = ", ".join(f"{name}: {count}"
                        for name, count in (summary.get("by_engine") or {}).items()) or "нет"
    ecosystems = ", ".join(f"{name}: {count}"
                           for name, count in (summary.get("by_ecosystem") or {}).items()) or "нет"
    lines = [
        f"Статус: {summary.get('status', 'неизвестно')}",
        f"Находок: {summary.get('total', 0)} "
        f"(максимальная severity: {summary.get('max_severity', 'unknown')})",
        f"По severity: {severities}",
        f"По типу: SAST {by_kind.get('sast', 0)}, SCA {by_kind.get('sca', 0)}",
    ]
    by_owasp = summary.get("by_owasp") or {}
    if by_owasp:
        edition = summary.get("owasp_version") or ""
        lines.append(f"OWASP Top 10 {edition}: " + "; ".join(
            f"{label} ×{count}" for label, count in by_owasp.items()))
    lines.extend([
        f"Движки: {engines}",
        f"Пакетов в инвентаре: {summary.get('packages', 0)}; экосистемы: {ecosystems}",
        f"Классификация: direct {summary.get('packages_direct', 0)}, "
        f"transitive {summary.get('packages_transitive', 0)}, "
        f"unknown {summary.get('packages_unknown', 0)}",
        f"Дерево зависимостей: "
        f"{'построено по lock-файлам' if summary.get('dependency_graph') else 'не восстановлено'}",
        f"Ошибок сканирования: {summary.get('errors', 0)}",
    ])
    rules = summary.get("top_rules") or []
    if rules:
        lines.append("Топ правил: " + "; ".join(
            f"{rule.get('rule_id', '')} ×{rule.get('count', 0)}" for rule in rules[:5]))
    return "\n".join(lines)


def dependency_label(finding: Dict[str, Any]) -> str:
    """Short direct/transitive marker with the BFS depth for SCA findings."""
    if finding.get("kind") != "sca":
        return ""
    package = finding.get("package") or {}
    direct = package.get("direct")
    if direct is True:
        label = "direct"
    elif direct is False:
        label = "transitive"
    else:
        label = "unknown"
    depth = package.get("depth")
    return f"{label} · d{depth}" if depth is not None else label


def finding_row(finding: Dict[str, Any]) -> Tuple[str, str, str, str, str, str, str, str]:
    """Flatten one JSON finding into the columns shown in the results table."""
    location = finding.get("location") or {}
    package = finding.get("package") or {}
    if finding.get("kind") == "sca":
        where = f"{package.get('name', '')} {package.get('version', '')}".strip()
    else:
        where = f"{location.get('file', '-')}:{location.get('start_line', '-')}"
    message = finding.get("message") or finding.get("title") or ""
    return (str(finding.get("severity", "")), str(finding.get("kind", "")),
            str(finding.get("rule_id", "")), str(finding.get("cwe") or ""), where,
            str(finding.get("engine", "")), dependency_label(finding), message)


def format_finding(finding: Dict[str, Any],
                   dependency_path: Optional[str] = None) -> str:
    """Human-readable finding card shown above the raw JSON in the details pane."""
    package = finding.get("package") or {}
    location = finding.get("location") or {}
    lines: List[str] = []
    severity = str(finding.get("severity") or "unknown").upper()
    rule_id = str(finding.get("rule_id") or "")
    lines.append(f"{severity}  ·  {rule_id}".strip())
    title = str(finding.get("title") or "").strip()
    if title:
        lines.append(title)
    if finding.get("suppressed"):
        info = finding.get("suppression") or {}
        reason = info.get("reason") or info.get("justification") or "accepted risk"
        expiry = f", до {info['expires']}" if info.get("expires") else ""
        lines.append(f"Статус: SUPPRESSED — {reason}{expiry}")
    elif finding.get("baseline") == "new":
        lines.append("Baseline: NEW (находки не было в baseline)")
    elif finding.get("baseline") == "existing":
        lines.append("Baseline: existing (уже была в baseline)")
    lines.append("")

    if finding.get("kind") == "sca" or package:
        name = str(package.get("name") or "").strip()
        version = str(package.get("version") or "").strip()
        fixed = str(package.get("fixed_version") or "").strip()
        direct = package.get("direct")
        depth = package.get("depth")
        relation = "unknown"
        if direct is True:
            relation = "direct (объявлена в манифесте)"
        elif direct is False:
            relation = "transitive (притянута другой зависимостью)"
        lines.append(f"Пакет: {name} {version}".strip())
        if fixed:
            lines.append(f"Исправлено в: {fixed}")
        lines.append(f"Тип зависимости: {relation}"
                     + (f", глубина {depth}" if depth is not None else ""))
        if dependency_path:
            lines.append(f"Путь: {dependency_path}")
    else:
        file = str(location.get("file") or "-")
        line = location.get("start_line")
        lines.append(f"Место: {file}" + (f":{line}" if line else ""))

    message = str(finding.get("message") or "").strip()
    if message:
        lines.extend(["", message])
    description = str(finding.get("description") or "").strip()
    if description:
        lines.extend(["", description[:4000]])
    snippet = finding.get("snippet") or {}
    snippet_lines = snippet.get("lines") or []
    if snippet_lines:
        start = int(snippet.get("start_line") or 1)
        width = len(str(start + len(snippet_lines)))
        lines.extend(["", "Код:"])
        for offset, code_line in enumerate(snippet_lines):
            number = start + offset
            marker = ">" if number == location.get("start_line") else " "
            lines.append(f"{marker} {number:>{width}} | {code_line}")
    suggested_fix = str(finding.get("suggested_fix") or "").strip()
    if suggested_fix:
        lines.extend(["", "Предлагаемая замена (не применяется автоматически):", suggested_fix])
    remediation = finding.get("remediation") or []
    if remediation:
        lines.extend(["", "Как исправить:"])
        lines.extend(f"• {item}" for item in remediation)
    if finding.get("cwe"):
        entry = cwe_catalog.lookup(finding["cwe"])
        if entry is not None:
            name = finding.get("cwe_name_ru") or entry.name_ru
            lines.extend([
                f"\nCWE: {entry.cwe_id} — {name}",
                entry.description,
                f"Справочник CWE: {entry.url}",
            ])
        else:
            lines.append(f"\nCWE: {finding['cwe']}")
    owasp_categories = finding.get("owasp") or []
    if owasp_categories:
        lines.append("\nOWASP Top 10:")
        for category in owasp_categories:
            if not isinstance(category, dict):
                continue
            label = str(category.get("id") or category.get("label") or "")
            name = str(category.get("name_ru") or category.get("name") or "")
            lines.append(f"• {label}" + (f" — {name}" if name else ""))
            url = str(category.get("url") or "")
            if url:
                lines.append(f"  {url}")
    aliases = finding.get("aliases") or []
    if aliases:
        lines.append("Aliases: " + ", ".join(str(alias) for alias in aliases))
    references = finding.get("references") or []
    if references:
        lines.append("Ссылки:")
        for reference in references[:8]:
            lines.append(f"  {reference}")

    lines.extend(["", "JSON:", json.dumps(finding, indent=2, ensure_ascii=False)])
    return "\n".join(lines)


def format_cwe_entry(entry: "cwe_catalog.CWEEntry", count: int = 0) -> str:
    """Render one catalog entry for the CWE reference tab."""
    lines = [
        f"{entry.cwe_id}  ·  {entry.category}",
        entry.name_ru,
        entry.name,
        "",
        "Описание:",
        entry.description,
        "",
        "Последствия:",
        entry.consequences,
        "",
        "Меры защиты:",
    ]
    lines.extend(f"• {item}" for item in entry.mitigations)
    if count:
        lines.extend(["", f"В текущем отчёте: {count} находок с этим CWE."])
    lines.extend(["", f"Официальная страница MITRE: {entry.url}"])
    return "\n".join(lines)


def dependency_rows(report: Dict[str, Any], sort_by: Optional[str] = None,
                    descending: bool = False) -> List[Dict[str, Any]]:
    """Flatten ``stats.dependency_graph`` into rows for the dependencies tab.

    Each row has ``ref``, ``parent`` (``""`` for a root), ``name``, ``version``,
    ``ecosystem``, ``direct``, ``depth``, ``severity`` and ``cycle``.  When the
    graph was not recovered from a lock file, every package becomes a root so
    the tab still lists direct and transitive/unknown packages honestly.

    ``sort_by`` orders roots and sibling children independently, so a sorted
    tree keeps every parent above its children and the hierarchy stays intact.
    """
    stats = report.get("stats") or {}
    graph = stats.get("dependency_graph") or {}
    nodes = {str(node.get("ref")): node
             for node in graph.get("nodes") or [] if node.get("ref")}

    severity_by_purl: Dict[str, str] = {}
    for finding in report.get("findings") or []:
        package = finding.get("package") or {}
        purl = str(package.get("purl") or "")
        severity = str(finding.get("severity") or "")
        if not purl or severity not in SEVERITY_ORDER:
            continue
        current = severity_by_purl.get(purl)
        if current is None or SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(current):
            severity_by_purl[purl] = severity

    children: Dict[str, List[str]] = {ref: [] for ref in nodes}
    parents: Dict[str, List[str]] = {ref: [] for ref in nodes}
    for dependency in graph.get("dependencies") or []:
        parent = str(dependency.get("ref"))
        if parent not in nodes:
            continue
        for child in dependency.get("dependsOn") or []:
            child = str(child)
            if child in nodes and child != parent and child not in children[parent]:
                children[parent].append(child)
                parents[child].append(parent)

    resolved = bool(graph.get("resolved"))
    ordered = sorted(nodes, key=lambda ref: (str(nodes[ref].get("ecosystem") or "").lower(),
                                             str(nodes[ref].get("name") or "").lower(),
                                             str(nodes[ref].get("version") or "")))
    if not resolved:
        roots = ordered
    else:
        roots = [str(ref) for ref in graph.get("roots") or [] if str(ref) in nodes]
        if not roots:
            roots = [ref for ref in ordered if not parents[ref]]

    def order(refs: List[str], default_alphabetical: bool = False) -> List[str]:
        if not sort_by:
            if not default_alphabetical:
                return list(refs)
            return sorted(refs, key=lambda ref: (
                str(nodes.get(ref, {}).get("name") or "").lower(),
                str(nodes.get(ref, {}).get("version") or "")))
        return sorted(
            refs,
            key=lambda ref: _dependency_sort_key(
                nodes.get(ref, {}), severity_by_purl.get(ref, ""), sort_by),
            reverse=descending)

    rows: List[Dict[str, Any]] = []
    seen: set = set()

    def walk(ref: str, parent: str) -> None:
        node = nodes.get(ref, {})
        cycle = ref in seen
        rows.append({
            "ref": ref,
            "parent": parent,
            "name": str(node.get("name") or ref),
            "version": str(node.get("version") or ""),
            "ecosystem": str(node.get("ecosystem") or ""),
            "direct": node.get("direct"),
            "depth": node.get("depth"),
            "severity": severity_by_purl.get(ref, ""),
            "cycle": cycle,
        })
        if cycle:
            return
        seen.add(ref)
        for child in order(children.get(ref, []), default_alphabetical=True):
            walk(child, ref)

    for ref in order(roots):
        walk(ref, "")
    return rows


def _direct_label(direct: Any) -> str:
    if direct is True:
        return "direct"
    if direct is False:
        return "transitive"
    return "unknown"


