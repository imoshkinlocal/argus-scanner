# Changelog

Все заметные изменения проекта. Формат — по мотивам Keep a Changelog,
версии — [SemVer](https://semver.org/lang/ru/).

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

[1.1.0]: https://github.com/imoshkinlocal/argus-scanner/releases/tag/v1.1.0
