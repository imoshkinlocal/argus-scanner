# Changelog

Все заметные изменения проекта. Формат — по мотивам Keep a Changelog,
версии — [SemVer](https://semver.org/lang/ru/).

## [1.4.0] — 2026-11-27

### Добавлено

- OWASP Top 10 для находок: CWE сопоставляется с категорией `A01…A10`
  выбранной редакции. Встроены **2017**, **2021** (по умолчанию) и **2025**;
  один CWE может относиться к нескольким категориям (CWE-259 → A02:2021 и
  A07:2021), поэтому `Finding.owasp` — список.
- Флаги `--owasp-version`, `--owasp-file` и `--no-owasp` для `scan`, `sast` и
  `sca`; настройки `owasp`, `owasp_version`, `owasp_file` в `[scan]`/`[report]`.
- Команда `argus owasp [CWE...]` — список категорий редакции или маппинг
  запрошенных CWE, форматы text/Markdown/JSON (`--version`, `--file`, `-f`, `-o`).
- Справочник вынесен в данные: `argus/owasp_top10.json` (+ package-data) и
  генератор `scripts/update_owasp.py` с `--check` и `--repo-dir`; обновление
  из официального `OWASP/Top10` не требует правки кода.
- Отчёты: JSON (`finding.owasp`, `summary.by_owasp`, `summary.owasp_version`,
  `stats.workflow.owasp`), text (`owasp:` и строка сводки), Markdown (колонка
  OWASP и секция `## OWASP Top 10`), SARIF (теги `owasp/aNN-YYYY` и поля
  `owasp`/`owasp_name`/`owasp_url`).
- GUI: переключатель OWASP, выбор редакции и своего файла в окне сканирования;
  категории в деталях находки и распределение в сводке; раздел в справке.
- `tests/test_owasp.py` плюс проверки в `test_cli`, `test_config`, `test_gui`,
  `test_output`, `test_workflow` и `test_threat`.

### Изменено

- Обогащение workflow теперь включает OWASP после CWE и до remediation;
  `stats.workflow.owasp` хранит редакцию и число сопоставленных находок.
- Версия поднята до 1.4.0 (portable, wheel, `.deb`, man-страницы, SBOM).

## [1.3.0] — 2026-11-27

### Добавлено

- Экосистема `Debian` для SCA и SBOM: `debian/control` (build/runtime/
  optional/dev-зависимости), dpkg status (`--deb-root`, `--deb-status`) и
  отдельные `.deb` (`--deb`).
- Экосистема `Ubuntu` в том же Debian-семействе: релизы `Ubuntu:<YY.MM>[:LTS]`
  (22.04:LTS, 24.04:LTS, 24.10…), vendor-aware определение релиза из
  `os-release`/`debian/changelog`, purl `pkg:deb/ubuntu/…`, отдельный
  offline-архив `--ecosystem Ubuntu`.
- GUI: блок «Пакеты Debian/Ubuntu» — корень системы (`--deb-root`), файл
  статуса dpkg (`--deb-status`), список `.deb` (`--deb`) и релиз
  (`--deb-suite`), включая выбор каталога и нескольких файлов.
- Парсер `debian/changelog` задаёт имя и версию проекта в SBOM; purl получает
  `arch` и `distro` qualifiers (`pkg:deb/debian/openssl@…?arch=amd64&distro=bookworm`).
- Компаратор версий dpkg: эпохи, `~`, ревизии Debian, `+deb12u1`; тот же
  порядок используется для Ubuntu (`3.0.2-0ubuntu1.16` > `…1.10`).
- OSV для Debian/Ubuntu использует suite-экосистемы `Debian:<N>` (11/12/13/14)
  и `Ubuntu:<release>`; релиз определяется из `/etc/os-release`,
  `/etc/debian_version`, rootfs или `debian/changelog`, переопределяется
  `--deb-suite` (`bookworm`, `jammy`, `12`, `22.04`).
- `tests/test_debian.py`: deb822, control, changelog, status, `.deb`,
  dpkg-версии, purl, suite-детект Debian и Ubuntu, фильтрация OSV по релизу;
  `tests/test_gui.py` — проверка новых аргументов `build_scan_command`.

### Изменено

- Debian-зависимости без версии (`debian/control` и необязательные поля)
  включаются как unversioned: версия в purl опускается, OSV-запрос не
  выполняется.
- `argus db update` по умолчанию не скачивает архивы Debian (~85 МБ) и Ubuntu
  (~800 МБ); они загружаются явно через `--ecosystem Debian` / `--ecosystem Ubuntu`.
- При неизвестном релизе Debian/Ubuntu-пакеты пропускаются с предупреждением,
  чтобы не подставлять fixed-версии из чужой ветки.
- Offline-база OSV пропускает записи с `withdrawn` (их отфильтровывает и
  online API), поэтому офлайн- и онлайн-результаты совпадают.

## [1.2.0] — 2026-11-27

### Добавлено

- Semgrep-правила могут нести `fix` или `fix-regex`; argus показывает замену
  как `suggested_fix` в JSON, SARIF (`fixes[]`), Markdown, текстовом отчёте
  и GUI.
- Предложения замен для `python-flask-debug`, `python-yaml-load`,
  `python-paramiko-auto-add-policy`, `java-insecure-cookie`,
  `java-httponly-cookie` и `go-tls-insecure-skip-verify`.
- `tests/test_fix_suggestions.py` — сквозная проверка предложений и
  read-only поведения; структурная проверка fix-правил в
  `tests/test_semgrep_rules.py`.

### Изменено

- `Finding` получил поле `suggested_fix`; JSON-отчёт и кэш SAST переносят его
  без потерь.
- Markdown-отчёт: секция `Suggested fixes` и приоритет готовой замены в
  таблице `Remediation`.

### Безопасность

- `fix` никогда не применяется автоматически: сканирование остаётся
  read-only, отдельного autofix-флага нет.

## [1.1.0] — 2026-11-26

### Добавлено

- Портативный архив `argus-1.1.0-linux-x86_64.tar.gz`: собственный CPython
  3.11 и Semgrep, запуск без root, pip и системного Python.
- Универсальный Debian-пакет `argus-scanner_1.1.0-4_all.deb`
  (`Architecture: all`): при установке создаёт приватный runtime в
  `/var/lib/argus-scanner` и ставит актуальный Semgrep с PyPI.
- `argus-setup-runtime` — установка, обновление, закрепление версии,
  просмотр и удаление runtime; офлайн-режим через `--wheelhouse`.
- `update-semgrep.sh` в портативном архиве: обновление Semgrep в overlay
  с автоматическим откатом.
- Пример `examples/vulnerable` с двумя эталонными находками и готовыми
  отчётами text/JSON/SARIF.
- `scripts/demo.sh` — сквозная проверка «сканер работает» за один запуск.
- CI: тесты на Python 3.10–3.13 и end-to-end demo-скан.
- Workflow релиза: сборка архива и `.deb` по тегу, публикация через
  автоматический `GITHUB_TOKEN` (без секретов).

### Изменено

- Минимальная версия Python — 3.10 (требование актуального Semgrep).
- `argus-update-semgrep` заменён на `argus-setup-runtime`.
- Исходный пакет больше не содержит сторонних бинарников: `orig.tar.gz`
  уменьшился с 86 МБ до 231 КБ, Debian Policy 4.13 соблюдается.
- `debian/postinst` удаляет `semgrep-venv` схемы 1.1.0-2 при обновлении.

### Исправлено

- Чтение TOML-конфига на Python 3.10: добавлена зависимость `tomli`
  (в 3.11+ используется стандартный `tomllib`), исправлены падавшие тесты
  `test_config`, `test_suppress`, `test_workflow`.
- Semgrep на минимальных системах без `ca-certificates`: портативный архив
  подставляет `certifi` через `SSL_CERT_FILE`.
- Лаунчеры портативного архива работают через симлинк и после переноса
  каталога.

### Пакетирование

- `argus-scanner_1.1.0-1` — первый Debian-пакет с вендорингом зависимостей.
- `argus-scanner_1.1.0-2` — добавлено обновление Semgrep при установке.
- `argus-scanner_1.1.0-3` — универсальный пакет без вендоринга.
- `argus-scanner_1.1.0-4` — исправление TOML на Python 3.10 (`tomli`).

[1.4.0]: https://github.com/imoshkinlocal/argus-scanner/releases/tag/v1.4.0
[1.3.0]: https://github.com/imoshkinlocal/argus-scanner/releases/tag/v1.3.0
[1.2.0]: https://github.com/imoshkinlocal/argus-scanner/releases/tag/v1.2.0
[1.1.0]: https://github.com/imoshkinlocal/argus-scanner/releases/tag/v1.1.0
