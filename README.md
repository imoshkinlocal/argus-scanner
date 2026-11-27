# argus — SAST + SCA сканер

[![tests](https://github.com/imoshkinlocal/argus-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/imoshkinlocal/argus-scanner/actions/workflows/ci.yml)
[![release](https://github.com/imoshkinlocal/argus-scanner/actions/workflows/release.yml/badge.svg)](https://github.com/imoshkinlocal/argus-scanner/actions/workflows/release.yml)

`argus` ищет проблемы безопасности в коде и зависимостях:

* SAST: taint-движок для Java на tree-sitter и наборы Semgrep-правил для Python,
  JavaScript/TypeScript, Go, PHP, C, C++ и Ruby (включая ERB);
* SCA: проверка манифестов зависимостей по базе [OSV](https://osv.dev) через API
  или локальные архивы для offline-режима;
* бенчмарки: OWASP Benchmark для Java и собственный набор SCA-фикстур;
* отчёты в JSON, SARIF 2.1.0, Markdown и text, плюс OpenVEX;
* работа в CI: конфиг проекта, baseline, подавления, quality gates, сравнение
  отчётов, инкрементальный кэш SAST, EPSS/KEV и подписываемые SBOM.

Веб-панели, Docker-образов и серверной части в проекте нет: это CLI для
пайплайнов.

## Содержание

1. [Архитектура](#архитектура)
2. [Установка](#установка)
3. [Быстрый старт](#быстрый-старт)
4. [GUI](#gui)
5. [Команды CLI](#команды-cli)
6. [Конфиг, baseline, подавления и quality gates](#конфиг-baseline-подавления-и-quality-gates)
7. [Форматы отчётов](#форматы-отчётов)
8. [Threat intelligence: EPSS и KEV](#threat-intelligence-epss-и-kev)
9. [SBOM (CycloneDX / SPDX)](#sbom-cyclonedx--spdx)
10. [VEX](#vex)
11. [Сравнение отчётов](#сравнение-отчётов)
12. [Методика бенчмарков](#методика-бенчмарков)
13. [Результаты](#результаты)
14. [Ограничения](#ограничения)
15. [Тесты](#тесты)
16. [Структура репозитория](#структура-репозитория)

## Архитектура

```
                    ┌──────────────────────────┐
   target ────────► │  argus.cli (dispatcher)  │
                    └──────┬────────────┬──────┘
                           │ SAST       │ SCA
                ┌──────────▼───────┐  ┌─▼─────────────────────┐
                │ argus.sast        │  │ argus.sca             │
                │  ├─ java engine   │  │  ├─ parsers (манифесты)│
                │  │  (tree-sitter) │  │  ├─ versions (range)  │
                │  └─ semgrep       │  │  └─ osv (online/offline)│
                │     rule packs    │  │                       │
                └──────────┬────────┘  └─┬─────────────────────┘
                           │             │
                    ┌──────▼─────────────▼──────┐
                    │  models.Finding / dedupe   │
                    │  output: json|sarif|md|txt│
                    │  sbom: CycloneDX / SPDX   │
                    └───────────────────────────┘
```

Логика выбора движка (`argus/sast/scanner.py`):

| Файлы | Движок |
| --- | --- |
| `.java` (по умолчанию) | `argus-java` — внутрифайловый taint-анализ |
| `.py`, `.js/.ts`, `.go`, `.php`, `.c/.cpp`, `.rb/.erb` | Semgrep + встроенные паки правил |
| `.java` с `--engine semgrep` | Semgrep (для сравнения подходов) |

Semgrep запускается по явному списку файлов, который уже прошёл через
исключения argus (`node_modules`, `vendor`, `.pc`, `build`, …). Если файлов
больше 4000 (лимит длины командной строки), сканируется каталог целиком, и
тогда действуют правила игнорирования самого Semgrep.

Java-движок отслеживает распространение «грязных» значений от источников
(`request.getParameter`, заголовки, cookies, потоки ввода) до стоков
(SQL/LDAP/XPath, `Runtime.exec`, `PrintWriter`, `File*`, `XPath`, cookie-атрибуты
и т.д.), учитывает санитайзеры по CWE (`ESAPI.encoder()`, `Integer.parseInt`,
allow-list'ы), свёртку констант, тернарные ветвления и простые контейнеры
(`List`/`Map`). Модель санитайзеров по-CWE: `Value.clean` содержит набор
закрытых CWE, поэтому очистка для SQL не «лечит» XSS.

Для Spring MVC параметры контроллера с `@RequestParam`, `@PathVariable`,
`@RequestBody`, `@RequestHeader`, `@CookieValue`, `@ModelAttribute`,
`@MatrixVariable` и `@RequestPart` считаются источниками на входе в метод.
Числовые/boolean-типы (`int`, `long`, `BigDecimal`, …) не помечаются tainted:
инъекционный payload через них не проходит.

SCA:

* парсеры манифестов: `requirements.txt`, `pyproject.toml`, `poetry.lock`,
  `uv.lock`, `Pipfile(.lock)`, `package.json`, `package-lock.json`, `pom.xml`,
  Gradle, `go.mod`, `composer.json/lock`, `Gemfile`, `gems.rb`, `*.gemspec`,
  `Gemfile.lock`, `Cargo.lock`, а также Debian/Ubuntu: `debian/control`, база
  dpkg (`--deb-root`/`--deb-status`) и отдельные `.deb` (`--deb`);
* `argus/sca/graph.py` восстанавливает транзитивный граф только из
  lock-файлов, где уже зафиксировано разрешение версий: рёбра
  «родитель → потомок» дают `Gemfile.lock`, `package-lock.json` (v1/v2/v3),
  `poetry.lock`, `uv.lock`, `composer.lock` и `Cargo.lock`, а BFS считает
  глубину и direct/transitive. Bare-манифесты дают только direct-зависимости:
  если рёбер нет, `resolved=false`, и argus не выдумывает дерево;
* Ruby DSL-манифесты читаются построчно: для `Gemfile` учитываются блоки
  `group ... do` (dev/test не попадают в runtime) и вложенные `platforms ... do`,
  для `*.gemspec` — вызовы `add_dependency` / `add_runtime_dependency` /
  `add_development_dependency`; условные зависимости (`unless java_p`)
  считаются выполненными. Поддерживается оператор `~>`;
* если для одного пакета есть и lock-файл, и манифест, приоритет у точного пина
  из lock-файла (диапазон из манифеста не порождает лишнюю версию);
* версии сравниваются «прощающим» компаратором (PEP 440/семвер/квалификаторы
  Maven, post/pre-релизы, trailing zeros);
* диапазоны OSV (`introduced`/`fixed`/`last_affected`/`limit`, открытые диапазоны
  `introduced: "0"`) поддерживаются;
* политика `--range-policy min` (по умолчанию) трактует `>=` как нижнюю границу и
  помечает такие находки `assumed=true`; `--range-policy skip` учитывает только
  точные пины (`==`).

Помимо taint-анализа, `argus scan`/`argus sast` запускают два лёгких сканера:
`argus/secrets.py` (ключи, токены, приватные ключи, пароли в коде) и
`argus/iac.py` (Dockerfile, Kubernetes, Terraform). Оба отключаются флагами
`--no-secrets` и `--no-iac`. Находки секретов попадают в общий поток с CWE-798
и рекомендацией ротации, IaC — с CWE-16/CWE-250 и привязкой к файлу.

После сканирования `argus/workflow.py` выполняет единый пост-процессинг:
severity-overrides из конфига → baseline → подавления → обогащение (CWE,
remediation, сниппеты) → запись нового baseline → quality gate. Порядок
фиксирован, поэтому `--fail-on-new`, подавления и гейты видят уже
нормализованные находки.

## Установка

Требуется Python 3.10+.

### Готовые сборки

Портативный архив: распакуйте и запустите. Внутри CPython 3.11 и Semgrep,
поэтому системный Python, pip, root и сеть не нужны. Нужны Linux x86_64 и
glibc 2.35+ (Debian 12, Ubuntu 22.04 и новее):

```bash
tar xzf argus-1.3.0-linux-x86_64.tar.gz
cd argus-1.3.0-linux-x86_64
./argus version
./argus scan /path/to/repo -f text
```

Для Debian и производных есть универсальный пакет: Architecture: all, Semgrep
ставится с PyPI при установке.

```bash
sudo apt install ./argus-scanner_1.3.0-1_all.deb
```

Ссылки на файлы — в разделе [Releases](../../releases/latest).

### Из исходников

```bash
git clone <repo> argus && cd argus
./scripts/install.sh            # создаст .venv и установит argus + semgrep
```

Варианты:

```bash
./scripts/install.sh --no-semgrep   # только Java-движок и SCA
VENV=/opt/argus ./scripts/install.sh
```

Ручная установка:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[semgrep]'
.venv/bin/argus version
```

Semgrep не вендорится: обёртка ищет бинарь в `$ARGUS_SEMGREP`, в каталоге
текущего virtualenv, затем в `PATH`. Без Semgrep работают Java-анализ и SCA,
а для остальных языков команда вернёт ошибку сканирования (код 2).

## Быстрый старт

```bash
# полный скан: SAST + SCA, JSON в stdout
argus scan ./src -f json -o report.json

# только статический анализ, SARIF для CI
argus sast ./src -f sarif --fail-on high -o argus.sarif

# только зависимости, включая dev/test
argus sca . --include-dev -f text

# офлайн-режим SCA
argus db update                 # скачать архивы OSV (~один раз)
argus sca . --offline
```

Машинный и человекочитаемый отчёты можно получить одним запуском:

```bash
# JSON для автоматики + Markdown для человека
argus scan . -f json -o report.json --summary report.md

# то же, но сразу Markdown в stdout
argus scan . -f md
```

SBOM (переиспользует тот же инвентарь зависимостей, что и SCA):

```bash
argus sbom . -f cyclonedx -o sbom.cdx.json          # OWASP CycloneDX 1.5
argus sbom . -f spdx -o sbom.spdx.json              # SPDX 2.3
argus sbom . -f md -o sbom.md                       # инвентарь для человека
argus sbom . -o bom.json --sign-key "$KEY"           # SHA-256 + HMAC-SHA256
argus sbom --verify bom.json --sign-key "$KEY"       # код 2 при неверной подписи
```

Debian/Ubuntu: `debian/control`, база dpkg и отдельные `.deb`:

```bash
argus sbom . -f cyclonedx -o src.cdx.json              # debian/control + changelog
argus sbom . --deb-root / -f cyclonedx -o host.cdx.json  # установленные пакеты
argus sbom . --deb ./argus-scanner_1.3.0-1_all.deb \
    --deb-suite bookworm -f md -o pkg.md               # один .deb
argus sca . --deb-root / -f json -o host-vulns.json     # OSV для Debian/Ubuntu
argus sca . --deb ./pkg.deb --deb-suite jammy           # Ubuntu-пакет
```

Workflow для CI: один раз зафиксировать baseline, затем падать только на новом:

```bash
# конфиг ищется вверх по дереву (argus.toml/.argus.toml/argus.json)
argus scan . --baseline-out .argus-baseline.json -f json -o report.json
argus scan . --baseline .argus-baseline.json --fail-on-new

# подавления: JSON/TOML или .argusignore
argus scan . --ignore .argusignore

# сравнить два отчёта и упасть на регрессиях high+
argus diff old.json new.json --fail-on high

# threat intelligence и VEX
argus sca . --threat-intel --epss-file epss.json --kev-file kev.json
argus vex report.json -o report.vex.json
```

Пример `argus.toml`:

```toml
[scan]
format = "json"
summary = "reports/argus.md"
fail_on = "high"
baseline = ".argus-baseline.json"

[sca]
threat_intel = true

[gates]
max_total = 200
max_by_severity = { critical = 0, high = 5 }
deny_packages = ["log4j-core@2.14.*"]
deny_cwes = ["CWE-502"]
deny_licenses = ["GPL-3.0-only"]

[severity]
"CWE-89" = "critical"

[[suppress]]
rule = "java-sqli-*"
file = "src/legacy/*"
reason = "legacy module, migration planned"
expires = "2027-01-01"
```

Коды возврата: `0` — чисто, `1` — есть находки на уровне `--fail-on` и выше
(или не пройден quality gate), `2` — ошибка сканирования (нет цели, нет Semgrep,
сетевой сбой, неверная подпись SBOM).
`--fail-on none` отключает проверку порога.

### Проверка: демо-пример

`examples/vulnerable` — маленький проект с двумя известными уязвимостями:
SQL-инъекцией в Java и command injection в Python. Один запуск проверяет, что
сканер находит обе:

```bash
./scripts/demo.sh
```

```
HIGH               java-sqli-jdbc
    at: Vulnerable.java:9
    cwe: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)

HIGH               python-command-injection
    at: app.py:6
    cwe: CWE-78 (Improper Neutralization of Special Elements used in an OS Command)

Summary: critical: 0, high: 2, medium: 0, low: 0, info: 0, total: 2
```

Скрипт проверяет код возврата `1` и наличие обеих находок в JSON. Готовые
отчёты этого прогона лежат в `examples/report.{txt,json,sarif}`. CI запускает
тот же сценарий на каждый push, вместе с тестами на Python 3.10–3.13.

## GUI

Графический интерфейс на `tkinter` (стандартная библиотека, отдельных
зависимостей нет). Запуск из корня проекта:

```bash
./argus-gui.py          # скрипт сам переключится на .venv, если он есть
argus-gui               # после pip install -e .
```

На Debian/Ubuntu для tkinter может понадобиться пакет `python3-tk`.

Что есть в окне:

* выбор каталога с исходниками и подсказка, какие файлы анализирует SAST/SCA;
* переключатели SAST/SCA, dev-зависимостей и офлайн-режима;
* порог `--fail-on`, политика диапазонов и список исключений;
* пути JSON- и Markdown-отчётов;
* журнал с живым выводом CLI и расшифровкой кода возврата;
* вкладка «Результаты»: сводка, цветные счётчики severity и таблица находок,
  где цвет строки соответствует severity; в шапке показан каталог, который
  реально сканировался, колонка «Зависимость» содержит `direct`/`transitive`
  и глубину, а панель деталей можно растянуть мышью или кнопкой
  «Развернуть детали»; по клику виден разбор находки (пакет, путь в графе,
  описание, сниппет кода, рекомендации по исправлению, ссылки) и полный JSON;
* панель фильтров: поиск по тексту, фильтр по типу (SAST/SCA), по CWE,
  переключатели «только новые» и «показать подавленные», группировка по
  severity/типу/CWE/правилу; кликабельные severity-чипы работают как быстрый
  фильтр;
* сравнение отчётов: кнопка загрузки второго JSON показывает новые, исправленные
  и изменившиеся находки относительно выбранного отчёта;
* вкладка сканирования принимает `--config`, baseline, `--fail-on-new`,
  переключатели секретов и IaC, а также число строк контекста — всё это
  попадает в итоговую команду `argus scan` и видно в журнале;
* сортировка таблиц: клик по заголовку упорядочивает строки, повторный клик
  меняет направление, а стрелка ▲/▼ показывает текущий порядок; severity
  по умолчанию сортируется по убыванию (critical сверху), остальные колонки —
  по возрастанию;
* двойной клик по SCA-находке открывает вкладку «Зависимости» и подсвечивает
  соответствующий пакет;
* вкладка «Зависимости»: иерархическое дерево из `stats.dependency_graph`
  с версией, экосистемой, direct/transitive, глубиной и severity пакета;
  сортировка упорядочивает корни и дочерние узлы внутри каждого родителя,
  не ломая иерархию; если граф не восстановлен, пакеты показаны плоским
  списком;
* вкладка «CWE»: встроенный офлайн-справочник с поиском по номеру, названию,
  категории и описанию; для каждой слабости показаны последствия, меры защиты
  и ссылка на MITRE. Записи, встречающиеся в текущем отчёте, подсвечены и
  содержат число находок. Кнопка «Справочник CWE →» открывает запись для
  выбранной находки, а в её деталях выводится расшифровка CWE;
* вкладка «Справка»: как пользоваться, описание опций, форматы отчётов,
  коды возврата и ограничения.

GUI запускает тот же `argus scan`, что и CI, и своей логики сканирования не
имеет. Команда целиком видна в журнале, её можно скопировать и повторить в
терминале.

## Команды CLI

```
argus scan  <target>   SAST + SCA за один проход
argus sast  <target>   только статический анализ
argus sca   <target>   только анализ зависимостей
argus sbom  <target>   SBOM в CycloneDX, SPDX или Markdown
argus bench owasp      оценка движка на OWASP Benchmark
argus bench sca        оценка SCA на фикстурах
argus db update        загрузка offline-архивов OSV
argus db status        состояние локальных кэшей (+ --verify)
argus rules list       список встроенных правил
argus cwe <ID...>      встроенный справочник CWE
argus diff OLD NEW     сравнение двух JSON-отчётов
argus vex REPORT       экспорт SCA-находок в OpenVEX
argus version          версии argus / Python / Semgrep
```

### Общие флаги отчёта (`scan`, `sast`, `sca`)

| Флаг | Значение |
| --- | --- |
| `-f, --format` | `json` (по умолчанию), `sarif`, `md`/`markdown`, `text` |
| `-o, --output` | файл вместо stdout (каталоги создаются) |
| `--summary PATH` | дополнительно записать человекочитаемый Markdown-отчёт |
| `--fail-on` | `none\|info\|low\|medium\|high\|critical` (по умолчанию `high`) |
| `--min-severity` | отбросить находки ниже уровня (по умолчанию `unknown`) |
| `-q, --quiet` | без прогресса в stderr |
| `--config PATH` | `argus.toml`/`argus.json`; без флага ищется вверх по дереву |
| `--baseline PATH` | пометить находки из baseline как `existing` |
| `--baseline-out PATH` | записать текущие находки как новый baseline |
| `--fail-on-new` | падать только на находках, которых нет в baseline |
| `--ignore PATH` | файл подавлений (JSON/TOML/`.argusignore`), можно повторять |
| `--include-suppressed` | показать подавленные находки в text/Markdown/SARIF/GUI |
| `--context-lines N` | строк контекста вокруг находки (по умолчанию 2) |
| `--no-context` | не прикреплять сниппеты к находкам |

`json` и `sarif` — машиночитаемые форматы для CI и парсинга; `md` и `text` —
для чтения человеком. `--summary` пишет Markdown рядом с основным отчётом,
поэтому один запуск отдаёт оба представления.

### Флаги SAST

| Флаг | Значение |
| --- | --- |
| `--engine` | `auto` (по умолчанию), `java`, `semgrep` |
| `-j, --jobs` | параллельные воркеры / jobs Semgrep |
| `--language` | ограничить языки (можно повторять) |
| `--exclude` | пропустить пути с подстрокой (можно повторять) |
| `--rules` | внешний каталог Semgrep-правил |
| `--java-properties` | каталог `*.properties` для разрешения констант |
| `--no-secrets` | отключить встроенный сканер секретов |
| `--no-iac` | отключить проверки Dockerfile/Kubernetes/Terraform |
| `--no-sast-cache` | не использовать инкрементальный кэш Java-анализа |
| `--sast-cache-dir` | каталог кэша (по умолчанию `$XDG_CACHE_HOME/argus/sast`) |

### Флаги SCA

| Флаг | Значение |
| --- | --- |
| `--include-dev` | включить dev/test/optional-зависимости |
| `--range-policy` | `min` (по умолчанию) или `skip` |
| `--offline` | только локальные архивы OSV |
| `--db-dir` | каталог архивов OSV |
| `--no-cache` | не использовать кэш запросов OSV |
| `--ecosystem` | ограничить экосистемы (можно повторять; Debian и Ubuntu — отдельные) |
| `--deb-root` | читать установленные Debian/Ubuntu-пакеты из `DIR/var/lib/dpkg/status` (`/` — текущая система) |
| `--deb-status` | dpkg status-файл (можно повторять) |
| `--deb` | бинарный `.deb` (можно повторять) |
| `--deb-suite` | релиз Debian/Ubuntu (`bookworm`, `jammy`, `12`, `22.04`) для `--deb`/`--deb-status`/`debian/control` |
| `--threat-intel` | добавить EPSS и CISA KEV к SCA-находкам |
| `--epss-file` | локальный JSON EPSS вместо api.first.org |
| `--kev-file` | локальный JSON каталога KEV |
| `--no-threat-cache` | игнорировать кэш EPSS/KEV |
| `--threat-cache-dir` | каталог кэша threat intel |
| `--threat-ttl` | сколько часов кэш считается свежим (по умолчанию 12) |

### Флаги SBOM (`sbom`)

| Флаг | Значение |
| --- | --- |
| `-f, --format` | `cyclonedx` (по умолчанию), `spdx`, `md`/`markdown` |
| `-o, --output` | файл вместо stdout |
| `--summary PATH` | дополнительно записать Markdown-инвентарь |
| `--name` | имя проекта в документе (по умолчанию — имя каталога) |
| `--component-version` | версия проекта |
| `--include-dev` | включить dev/test/optional-зависимости |
| `--range-policy` | `min` (по умолчанию) или `skip` |
| `--exclude` | пропустить манифесты по glob (можно повторять) |
| `--ecosystem` | ограничить экосистемы (можно повторять; Debian и Ubuntu — отдельные) |
| `--deb-root` | читать `DIR/var/lib/dpkg/status` и определить релиз Debian/Ubuntu из rootfs |
| `--deb-status` | dpkg status-файл (можно повторять) |
| `--deb` | бинарный `.deb` (можно повторять) |
| `--deb-suite` | релиз Debian/Ubuntu для purl/OSV (`bookworm`, `jammy`, `12`, `22.04`); иначе — из rootfs/changelog |
| `--sign-key` | HMAC-ключ для подписи (или `ARGUS_SBOM_KEY`) |
| `--sign-key-id` | идентификатор ключа рядом с подписью |
| `--verify FILE` | проверить подпись существующего SBOM и выйти |

`argus sbom` не обращается к OSV и работает без сети: это экспорт того, что
объявлено в манифестах.

### Бенчмарки

```bash
argus bench owasp --bench-dir /tmp/owasp-benchmark -j 8 \
    --cache /tmp/bench-cache.json -f md -o bench.md

argus bench owasp --sarif external.sarif     # оценка чужого SARIF
argus bench owasp --engine semgrep --engine java

argus bench sca --fixtures benchmarks/sca/fixtures -f md -o sca-bench.md
```

`--min-score N` возвращает код 1, если итоговый score ниже `N` (удобно для CI).

### Встроенные правила

| Пак | Правил | Содержание |
| --- | --- | --- |
| Java (движок) | 24 | SQL/LDAP/XPath/команды/файлы/XSS/cookies/SSRF |
| `rules/java` | 17 | резервный Semgrep-пак для Java |
| `rules/python` | 13 | команды, `eval`, `pickle`, YAML, SQL, шаблоны |
| `rules/javascript` | 11 | команды, `eval`, `innerHTML`, SQL, JWT, `child_process` |
| `rules/go` | 8 | команды, SQL, шаблоны, слабая криптография |
| `rules/php` | 9 | команды, `eval`, SQL, `unserialize`, файлы, XSS |
| `rules/c` | 8 | `strcpy/sprintf`, `system`, форматные строки, временные файлы, `rand` |
| `rules/cpp` | 6 | `std::system`, `strcpy`, форматные строки, `dlopen`, слабая криптография |
| `rules/ruby` | 14 | команды, backticks, `eval`, `Marshal.load`, YAML, SQL, ERB, файлы, redirect, хэши, секреты |

Особенности Ruby-пака (нет dataflow, поэтому правила — эвристики):

* `ruby-path-traversal` и `ruby-dynamic-code` срабатывают только если аргумент
  похож на внешние данные (`params`, `request`, `cookies`, `argv`, `env`,
  `user_input`, `upload`, `body`, `query`). Это убирает ложные срабатывания на
  тестах и метапрограммировании по константам (`class_eval %{ def #{name} }`);
* `ruby-erb-unescaped-output` — `generic`-правило для `*.erb` (`raw`,
  `html_safe`);
* `ruby-sql-injection` (конкатенация) и `ruby-sql-interpolation`
  (`#{...}` в `where/execute/find_by_sql`) разделены, чтобы сообщение было
  точнее.

C/C++: чтобы не засорять отчёт `memcpy`-шумом, `c-unsafe-memory-copy` не
срабатывает, если длина копирования — это `sizeof(...)` (или `sizeof(...) * n`),
либо если буфер назначения выделен ровно под эту длину
(`$DST = alloc($LEN)`, в том числе `$LEN + 1`). Правила, у которых есть
C++-эквивалент (`strcpy`, `system`, форматные строки), помечены `[c]` и не
дублируются на `.cc/.cpp`.

### Предлагаемые исправления

Правила Semgrep могут нести `fix` (готовая замена) или `fix-regex`
(регулярная замена внутри совпадения). argus переносит результат в
`Finding.suggested_fix` и показывает его в JSON, SARIF, Markdown и текстовом
отчёте, но **никогда не записывает в исходники**: отдельного autofix-флага нет,
сканирование остаётся read-only.

В бандле предложения есть у правил, где замена однозначна и не меняет
семантику:

| Правило | Что предлагается |
| --- | --- |
| `python-flask-debug` | `debug=True` → `debug=False` |
| `python-yaml-load` | `yaml.load(...)` → `yaml.safe_load(...)` |
| `python-paramiko-auto-add-policy` | `AutoAddPolicy` → `RejectPolicy` |
| `java-insecure-cookie` | `setSecure(false)` → `setSecure(true)` |
| `java-httponly-cookie` | `setHttpOnly(false)` → `setHttpOnly(true)` |
| `go-tls-insecure-skip-verify` | `InsecureSkipVerify: true` → `false` |

Если пишешь fix-правило:

* заменяй только то, что действительно можно заменить: никаких «примерно так»;
* не оставляй в `fix` эллипсис `...` — Semgrep подставит его буквально;
  для аргументов есть `$...ARGS`, но пустой список раскрывается не всегда;
* для переключателей флагов удобнее `fix-regex`: он меняет только литерал
  внутри совпадения и сохраняет остальные аргументы;
* severity правила не меняется: `suggested_fix` — дополнение к находке, а не
  причина понизить или повысить уровень. Структуру проверяет
  `tests/test_semgrep_rules.py::test_fix_suggestions_are_well_formed`, сквозной
  сценарий — `tests/test_fix_suggestions.py`.

### Справочник CWE

Встроенный каталог на 64 слабости: все CWE, которые выдают правила argus, плюс
наиболее частые идентификаторы слабостей из OSV. Для каждой записи есть
официальное название, русское пояснение, категория, последствия, меры защиты и
ссылка на MITRE. Справочник работает офлайн; незнакомый идентификатор всё равно
показывается заглушкой со ссылкой на официальную страницу.

```bash
argus cwe                      # список всех записей
argus cwe 79 89 502            # подробные карточки
argus cwe --search sql         # поиск по номеру, названию, категории, описанию
argus cwe 79 -f md -o cwe.md   # Markdown-справка
argus cwe 79 -f json           # машинный формат
```

В GUI это вкладка «CWE»: поиск, подсветка CWE из текущего отчёта и кнопка
«Открыть на cwe.mitre.org». В деталях любой находки CWE расшифровывается
автоматически.

## Конфиг, baseline, подавления и quality gates

Конфиг, baseline, подавления и гейты дают повторяемый прогон в CI. Порядок
применения: severity overrides → baseline → suppressions → enrichment →
baseline-out → quality gate.

### Конфиг

`argus` ищет конфиг в таком порядке:

1. `--config PATH`;
2. переменная окружения `ARGUS_CONFIG`;
3. `argus.toml`, `.argus.toml`, `argus.json`, `.argus.json` — вверх от цели до
   корня файловой системы.

CLI-флаги всегда приоритетнее значений из конфига; относительные пути внутри
конфига разрешаются от каталога самого конфига. Поддерживаются TOML и JSON;
если в системе нет `tomllib`/`tomli`, используется встроенный минимальный
парсер TOML (секции, массивы, inline-таблицы, строки, числа, boolean).

Секции: `[scan]`, `[sast]`, `[sca]`, `[sbom]`, `[gates]`, `[policies]`,
`[severity]`, `[diff]` и массив `[[suppress]]`. Имена ключей совпадают с
длинными флагами CLI (`fail_on`, `baseline`, `exclude`, `threat_intel`,
`max_total`, …).

### Baseline

Baseline — это JSON-снимок текущих находок. Сравнение идёт по стабильному
ключу, а не по fingerprint с номером строки, поэтому сдвиг кода не делает
находки новыми:

* SCA: `kind|rule|package|version`;
* SAST: `kind|rule|file|message`.

```bash
argus scan . --baseline-out .argus-baseline.json   # зафиксировать
argus scan . --baseline .argus-baseline.json --fail-on-new
```

`--fail-on-new` без `--baseline` — ошибка (код 2). Каждая находка получает
поле `baseline: "new" | "existing"`, а `summary` — счётчики `new`/`existing`.
Quality gate умеет учитывать только новые находки (`fail_on_new`).

### Подавления

Файл подавлений задаётся `--ignore` (можно несколько) или `[[suppress]]` в
конфиге. Поддерживаются `.argusignore`, JSON (`{"suppress": [...]}`) и TOML.
Критерии складываются по AND: `rule`, `file`, `cwe`, `package`, `id`,
`message`; `rule`/`file`/`package` понимают glob. Дополнительно:

* `reason` — причина, попадает в отчёт;
* `author` — кто принял риск;
* `expires` — дата (`YYYY-MM-DD` или ISO datetime); просроченное правило
  игнорируется и считается в `stats.workflow.expired_suppressions`.

Пример `.argusignore`:

```text
# комментарии разрешены
rule:java-sqli-*  # legacy module
file:src/generated/*
cwe:CWE-79
package:lodash@*
```

Подавленная находка остаётся в JSON с `suppressed: true` и блоком
`suppression`, но не влияет на exit code и скрывается в text/Markdown/SARIF/GUI.
`--include-suppressed` показывает её снова; в SARIF она получает
`suppressions[{kind: "external", justification, status: "accepted"}]`.

### Quality gates и политики

Секция `[gates]` (или `[policies]`) задаёт жёсткие правила поверх `--fail-on`:

| Ключ | Смысл |
| --- | --- |
| `max_total` | максимум активных находок |
| `max_by_severity` | лимиты по severity, например `{ critical = 0, high = 5 }` |
| `deny_packages` | запрещённые пакеты (glob, можно `name@version`) |
| `deny_cwes` | запрещённые CWE |
| `max_cvss` | максимально допустимый CVSS |
| `deny_licenses` | запрещённые лицензии (glob) |
| `fail_on` / `fail_on_new` | порог и режим «только новое» |

`deny_licenses` проверяет и SCA-находки, и все пакеты инвентаря — включая те,
у которых нет CVE. Нарушения попадают в `stats.gate.violations`, печатаются в
stderr, а exit code становится 1. Секция `[severity]` переопределяет
severity по правилу, CWE или `package:<name>`; исходное значение сохраняется в
`metadata.severity_original`.

### Инкрементальный кэш SAST

Java-анализ кэшируется в SQLite по содержимому файла, версии инструмента,
`*.properties` и относительному пути. Повторный скан неизменённых файлов
пропускает парсинг; статистика (`hits`/`misses`/`stored`) доступна в
`stats.sast_cache`. Кэш включён по умолчанию, отключается `--no-sast-cache`,
каталог задаётся `--sast-cache-dir`. Записи старше 30 дней удаляются при
открытии.

## Форматы отчётов

### JSON

```jsonc
{
  "$schema": "https://json.schemastore.org/argus-report-1.1.json",
  "schema_version": "1.1",
  "generated_at": "2026-11-18T09:00:00Z",
  "tool": {"name": "argus", "version": "1.3.0", "engines": ["argus-java", "osv"]},
  "target": "/abs/path",
  "summary": {
    "total": 2,
    "all": 3,
    "suppressed": 1,
    "new": 0,
    "existing": 2,
    "by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0, "unknown": 0},
    "by_kind": {"sast": 1, "sca": 1},
    "by_engine": {"argus-java": 1, "osv": 1},
    "by_ecosystem": {"Maven": 1},
    "packages": 12,
    "packages_direct": 4,
    "packages_transitive": 8,
    "packages_unknown": 0,
    "dependency_graph": true,
    "max_severity": "critical",
    "errors": 0,
    "status": "findings",
    "top_rules": [
      {"rule_id": "CVE-2021-44228", "kind": "sca", "severity": "critical", "count": 1},
      {"rule_id": "java-sqli-jdbc", "kind": "sast", "severity": "high", "count": 1}
    ]
  },
  "stats": {
    "files_total": 12, "files_java": 3, "files_other": 9,
    "packages_total": 15, "packages_unique": 12,
    "packages_direct": 4, "packages_transitive": 8, "packages_unknown": 0,
    "workflow": {"new": 0, "existing": 2, "suppressed": 1,
                  "expired_suppressions": 0, "severity_overrides": 0},
    "gate": {"passed": true, "violations": [], "considered": 2, "new": 0},
    "threat_intel": {"epss_matches": 1, "kev_matches": 1, "kev_ransomware": 1,
                      "epss_records": 250000, "kev_records": 1200,
                      "sources": {"epss": "cache", "kev": "cache"}, "errors": []},
    "sast_cache": {"hits": 2, "misses": 1, "stored": 1},
    "dependency_graph": {
      "resolved": true,
      "roots": ["pkg:maven/org.example/app@1.0"],
      "nodes": [{"ref": "pkg:gem/rack@2.0.6", "name": "rack", "version": "2.0.6",
                  "ecosystem": "RubyGems", "direct": false, "depth": 2}],
      "dependencies": [{"ref": "pkg:gem/actionpack@5.2.0",
                         "dependsOn": ["pkg:gem/rack@2.0.6"]}]
    }
  },
  "findings": [
    {
      "id": "sha256[:32]",
      "kind": "sast|sca",
      "engine": "argus-java|semgrep|osv",
      "rule_id": "java-sqli-jdbc",
      "title": "…",
      "severity": "high",
      "confidence": "high|medium|low",
      "cwe": "CWE-89",
      "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
      "message": "…",
      "remediation": ["Use a prepared statement."],
      "suggested_fix": "app.run(debug=False)",
      "baseline": "new|existing",
      "suppressed": false,
      "suppression": {"reason": "…", "expires": "…"},
      "snippet": {"start_line": 41, "lines": ["…", "…"]},
      "location": {"file": "src/App.java", "start_line": 42, "start_column": 9,
                    "end_line": 42, "end_column": 55},
      "package": {"name": "…", "version": "…", "fixed_version": "…", "purl": "…",
                    "direct": false, "depth": 2, "licenses": ["MIT"]},
      "aliases": ["CVE-…"], "references": ["…"],
      "metadata": {"epss": 0.97, "epss_percentile": 0.999, "kev": true}
    }
  ],
  "errors": [{"scanner": "sca", "message": "…"}]
}
```

Находки дедуплицируются по `(kind, rule_id, file, line)` (для SCA — по пакету и
версии), при повторе остаётся экземпляр с максимальным `confidence`.

Поля `summary` стабильны и рассчитаны на парсинг: `status` принимает
`findings` / `clean` / `error`, `total` — число активных находок,
`all` — включая подавленные, `suppressed` / `new` / `existing` — счётчики
workflow, `by_severity` считается только по активным, `by_engine` и
`by_ecosystem` — счётчики по движкам и экосистемам, `packages` — число
уникальных пакетов, `packages_direct` / `packages_transitive` /
`packages_unknown` — классификация, `dependency_graph` — построен ли граф по
lock-файлам, `top_rules` — до 10 самых частых правил (при равенстве выше по
severity). Полное дерево лежит в `stats.dependency_graph` (`resolved`, `roots`,
`nodes`, `dependencies`); у каждой SCA-находки в `package` есть `direct`,
`depth` и `licenses`. Эти же данные используются в Markdown-отчёте, поэтому оба
представления согласованы.

### Markdown (человекочитаемый)

`-f md` или `--summary PATH` формируют отчёт из тех же `Finding`, что и JSON:

* шапка (цель, время, движки, `status`, максимальная severity, качество gate,
  baseline и threat intel, если они включены);
* таблица по severity и по областям (SAST/SCA/пакеты/ошибки);
* таблица сработавших правил;
* отдельные таблицы SAST-находок (правило, CWE, файл:строка, движок) и
  SCA-находок (advisory, CWE, EPSS, KEV, пакет, установленная/исправленная
  версия, манифест) с пометкой `new` относительно baseline;
* секцию `Remediation` (команды обновления по экосистеме и советы),
  `Suggested fixes` с готовыми заменами из правил (только предложения),
  `SAST context` со сниппетами и маркером строки, `Suppressed` (при
  `--include-suppressed`);
* метрики инвентаря (direct/transitive/unknown), пропущенные зависимости,
  секцию `Dependency tree` с ASCII-деревом и severity пакетов и ошибки
  сканирования.

### SARIF 2.1.0

* `tool.driver.rules` — уникальные правила с `security-severity` и тегами CWE;
* `runs[0].originalUriBaseIds["%SRCROOT%"]` — абсолютный `file://` корень;
* для SCA в `properties` добавляются `package`, `version`, `fixed_version`,
  `purl`, `epss`, `epss_percentile`, `kev`, `kev_ransomware`, `kev_due_date`;
* CWE, `cwe_name`, `remediation` и `baselineState` доступны в `properties`;
* если у правила есть `fix`, результат получает `fixes[]` с
  `deletedRegion` и `insertedContent`: это предложение замены для code
  scanning, а не применённое изменение;
* подавленные находки получают `suppressions[{kind: "external", status:
  "accepted", justification}]`;
* нефатальные ошибки попадают в `invocations[0].toolExecutionNotifications`.

## Threat intelligence: EPSS и KEV

`--threat-intel` обогащает SCA-находки двумя публичными фидами:

* EPSS: вероятность эксплуатации CVE в ближайшие 30 дней и перцентиль
  (`https://api.first.org/data/v1/epss`);
* CISA KEV: каталог уязвимостей, которые уже эксплуатируются, с датой
  добавления, дедлайном устранения и признаком ransomware
  (`known_exploited_vulnerabilities.json`).

Данные кладутся в `metadata` находки:

```jsonc
{
  "epss": 0.974,
  "epss_percentile": 0.9999,
  "epss_cve": "CVE-2021-44228",
  "kev": true,
  "kev_cve": "CVE-2021-44228",
  "kev_ransomware": true,
  "kev_due_date": "2021-12-24",
  "kev_date_added": "2021-12-10",
  "kev_name": "Apache Log4j2 Remote Code Execution"
}
```

Конфигурация:

```bash
argus sca . --threat-intel                       # сеть + кэш на 12 часов
argus sca . --epss-file feeds/epss.json \
            --kev-file feeds/kev.json            # полностью офлайн
argus sca . --threat-intel --no-threat-cache     # без чтения/записи кэша
argus sca . --threat-intel --threat-ttl 1        # обновлять раз в час
```

Локальные файлы имеют приоритет над сетью и кэшем. EPSS запрашивается только
по CVE, которые есть в текущем отчёте (публичный API по умолчанию отдаёт не
больше 100 записей, поэтому полный дамп использовать нельзя), KEV — целиком.
Кэш лежит в `$XDG_CACHE_HOME/argus/threat` (или `--threat-cache-dir`) и содержит
`fetched_at`; при сетевой ошибке используется устаревший снимок, а причина
попадает в `stats.threat_intel.errors` — скан не падает. Источники и число
совпадений записываются в `stats.threat_intel` (`epss_matches`,
`kev_matches`, `kev_ransomware`, `sources`, `fetched_at`).

В Markdown у SCA-таблицы появляются колонки EPSS (`0.974 (100%)`) и KEV
(`yes` / `yes (ransomware)`), в SARIF — поля
`properties.epss`, `epss_percentile`, `kev`, `kev_ransomware`,
`kev_due_date`. Severity автоматически не меняется: фиды дают контекст, а
порог и гейты остаются явными.

## SBOM (CycloneDX / SPDX)

SBOM (Software Bill of Materials) — машиночитаемый перечень компонентов
проекта. `argus sbom` строится из того же инвентаря, что использует SCA
(`collect_inventory` в `argus/sca/scanner.py`), поэтому список пакетов в SBOM и
в отчёте об уязвимостях не расходится. OSV при этом не вызывается: команда
работает офлайн и экспортирует объявленные зависимости.

### Debian и Ubuntu: `debian/control`, dpkg и `.deb`

У Debian и Ubuntu нет lock-файла: объявленные зависимости лежат в
`debian/control`, а разрешённые — в базе dpkg. argus понимает оба источника и
отдельные `.deb`:

* `debian/control` — `Build-Depends*` попадают в scope `build`, `Depends`/
  `Pre-Depends` — в `runtime`, `Recommends`/`Suggests` — в `optional`/`dev`.
  Альтернативы `a | b` дают первый вариант; arch-ограничения `[amd64]` и
  profile-ограничения `<nocheck>` отбрасываются;
* `debian/changelog` задаёт имя и версию проекта в SBOM, если не передан
  `--name`/`--component-version`, а поле distribution — релиз для OSV;
* `--deb-root DIR` читает `DIR/var/lib/dpkg/status` (для текущей системы —
  `--deb-root /`), `--deb-status FILE` — произвольный status-файл, `--deb FILE`
  — метаданные одного бинарного пакета. В инвентарь попадают только
  `Status: install ok installed`;
* версии Debian и Ubuntu (`[epoch:]upstream[-revision]`, в том числе
  `3.0.2-0ubuntu1.16`) сравниваются алгоритмом dpkg (`~`, эпохи, `+deb12u1`),
  а не семвером;
* purl: `pkg:deb/debian/<name>@<version>?arch=amd64&distro=bookworm` или
  `pkg:deb/ubuntu/<name>@<version>?arch=amd64&distro=jammy`. Для
  неверсионированных зависимостей версия опускается, а `distro` — это
  codename релиза.

Для SCA критичен релиз: OSV публикует Debian-советники как `Debian:11`,
`Debian:12`, …, а Ubuntu — как `Ubuntu:22.04:LTS`, `Ubuntu:24.04:LTS` (у
промежуточных релизов суффикса `LTS` нет). Неверный релиз даст чужие
fixed-версии. argus определяет его так:

* `--deb-root`: из `<root>/etc/os-release` (сначала — чтобы отличить Ubuntu от
  её Debian-базы), затем из `<root>/etc/debian_version` (Debian и производные,
  например Astra Linux);
* `debian/control`: из поля distribution в `debian/changelog` (`bookworm`,
  `jammy`) или из явного `--deb-suite`;
* `--deb` и произвольный status-файл вне `<root>/var/lib/dpkg/status`: только
  явный `--deb-suite bookworm` / `jammy` / `12` / `22.04`. Без релиза пакеты
  пропускаются с предупреждением в `errors`, а не проверяются наугад.

Офлайн-архивы Debian (~85 МБ) и Ubuntu (~800 МБ, все релизы) не входят в
`argus db update` по умолчанию:

```bash
argus db update --ecosystem Debian
argus sca . --deb-root / --offline -f json -o host-vulns.json

argus db update --ecosystem Ubuntu
argus sca . --deb ./pkg_2.0-1ubuntu1_amd64.deb --deb-suite jammy --offline
```

### CycloneDX 1.5

```jsonc
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:…",
  "version": 1,
  "metadata": {
    "timestamp": "…",
    "tools": [{"vendor": "argus", "name": "argus", "version": "1.3.0"}],
    "component": {"type": "application", "name": "my-project"}
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:gem/rack@2.0.6",
      "name": "rack",
      "version": "2.0.6",
      "purl": "pkg:gem/rack@2.0.6",
      "scope": "required",
      "licenses": [{"license": {"id": "MIT"}}],
      "hashes": [{"alg": "SHA-256", "content": "…"}],
      "properties": [
        {"name": "argus:ecosystem", "value": "RubyGems"},
        {"name": "argus:manifest", "value": "Gemfile"},
        {"name": "argus:version-assumed", "value": "false"},
        {"name": "argus:direct", "value": "true"},
        {"name": "argus:depth", "value": "0"}
      ]
    }
  ],
  "dependencies": [
    {"ref": "pkg:gem/actionpack@5.2.0", "dependsOn": ["pkg:gem/rack@2.0.6"]}
  ],
  "signature": {
    "algorithm": "HS256",
    "created": "…",
    "sha256": "…",
    "value": "…",
    "keyId": "ci"
  }
}
```

### SPDX 2.3

```jsonc
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-project-sbom",
  "documentDescribes": ["SPDXRef-Package-rack"],
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-rack",
      "name": "rack",
      "versionInfo": "2.0.6",
      "downloadLocation": "NOASSERTION",
      "licenseConcluded": "MIT",
      "licenseDeclared": "MIT",
      "checksums": [{"algorithm": "SHA256", "checksumValue": "…"}],
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
         "referenceLocator": "pkg:gem/rack@2.0.6"}
      ]
    }
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
     "relatedSpdxElement": "SPDXRef-Package-rack"},
    {"spdxElementId": "SPDXRef-Package-actionpack", "relationshipType": "DEPENDS_ON",
     "relatedSpdxElement": "SPDXRef-Package-rack"}
  ]
}
```

### Что внутри и чего нет

* Компоненты сортируются по `(ecosystem, name, version)` — отчёт стабилен и
  удобен для diff между сборками.
* `purl` строится из экосистемы, имени и версии; SPDX-идентификаторы
  дедуплицируются при совпадении имён.
* `scope` в CycloneDX: `required` для runtime/build, `optional` для остальных;
  исходный scope и манифест сохраняются в `argus:*` properties / `comment`.
* Версия из диапазона (`~> 13.0` → `13.0`) помечается
  `argus:version-assumed=true`; lock-файл даёт точный пин.
* Граф экспортируется только когда его можно восстановить: CycloneDX получает
  top-level `dependencies` (`ref` → `dependsOn`) и свойства `argus:direct` /
  `argus:depth`, SPDX — отношения `DEPENDS_ON`. Если lock-файла с рёбрами нет,
  `dependsOn` пуст, а прямой статус берётся из манифеста.
* Хэши и лицензии берутся только из lock-файлов: npm `integrity`
  (SRI → hex), Composer `license` + `dist.shasum`, Poetry/uv `hash`,
  Cargo `checksum`, `license` в `package-lock.json`. Если источник их не
  содержит, поле остаётся пустым / `NOASSERTION`, а не заполняется догадками.
* Каждый документ получает блок `signature`: всегда SHA-256 от
  канонизированного JSON, а при `--sign-key` (или `ARGUS_SBOM_KEY`) — ещё и
  HMAC-SHA256 (`HS256`) с необязательным `keyId`. Проверка:
  `argus sbom --verify FILE [--sign-key KEY]`; неверная подпись даёт код 2.
* `-f md` (или `--summary`) печатает тот же инвентарь таблицей с колонками
  License/Hashes, Direct/Depth, секцией `Dependency tree` и пометкой источника
  версии (`pinned` / `range lower bound`). Такой отчёт можно приложить к релизу.

## VEX

`argus vex REPORT.json` превращает SCA-часть отчёта в OpenVEX 0.2.0:

* активная SCA-находка → `affected` (+ `action_statement` с версией исправления);
* подавленная → `not_affected`, причина подавления уходит в
  `impact_statement`, `justification` — `vulnerable_code_not_in_execute_path`;
* установленная версия уже не ниже исправленной → `fixed`.

```bash
argus vex report.json                       # JSON в stdout
argus vex report.json -o report.vex.json    # в файл
argus vex report.json --author "SecOps"
```

Документ содержит `@context`, `@id`, `timestamp`, `version`,
`tooling` и `statements[]` с `vulnerability.name/aliases`, `products[].identifiers.purl`
и статусом. SAST-находки в VEX не попадают.

## Сравнение отчётов

`argus diff OLD.json NEW.json` сравнивает два JSON-отчёта по тем же стабильным
ключам, что и baseline, и показывает:

* `new` — появившиеся находки;
* `fixed` — исчезнувшие;
* `changed` — оставшиеся, но с изменившейся severity;
* `unchanged`.

```bash
argus diff old.json new.json -f text
argus diff old.json new.json -f json -o diff.json
argus diff old.json new.json --fail-on high   # код 1 при регрессиях high+
argus diff old.json new.json --fail-on none   # только отчёт
```

По умолчанию подавленные находки в diff не учитываются;
`--include-suppressed` возвращает их. Формат `json` содержит `counts`,
`new_findings`, `fixed_findings`, `changed_findings`.

## Методика бенчмарков

### OWASP Benchmark (SAST)

Используется официальная методология проекта: тест-кейс считается
«обнаруженным», если инструмент дал хотя бы одну находку в файле этого кейса.
Далее по матрице ошибок:

```
TPR = TP / (TP + FN)        FPR = FP / (FP + TN)
Score = TPR − FPR           (Youden index, как в OWASP-скоркартах)
```

Дополнительно считаются precision, F1, разбивка по категориям (CWE) и по
сработавшим правилам (сколько находок пришлось на уязвимые и на чистые кейсы).
Harness умеет оценивать как встроенные движки (`--engine java|semgrep`), так и
произвольный внешний SARIF (`--sarif`), поэтому один и тот же отчёт можно
сравнивать с другими инструментами.

Кэш находок (`--cache`) инвалидируется по fingerprint исходников движка и
каталога правил, поэтому правка анализатора не даёт «залипших» результатов.

### SCA-бенчмарк

11 фикстур в `benchmarks/sca/fixtures/`, каждая — манифест(ы) + `expected.json`:

```json
{
  "description": "log4shell",
  "findings": [{"package": "org.apache.logging.log4j:log4j-core",
                "version": "2.14.1", "vulns": ["CVE-2021-44228"]}],
  "clean": ["…"]
}
```

Скоринг dependency-level: TP — ожидаемый пакет найден хотя бы с одним из
перечисленных CVE/GHSA (учитываются aliases); FN — не найден; FP — найден
пакет, который фикстура считает чистым (или не упоминает). Формула та же:
`score = recall − FPR`.

Фикстуры покрывают Maven (log4shell), npm (lodash), PyPI (flask, PyYAML),
Go (jwt-go), Packagist (PHPMailer), RubyGems (`rack` с `Gemfile.lock` и
`rack` с `Gemfile`, включая диапазоны и dev-группу), Cargo (time) и два
«чистых» проекта (Python и npm), чтобы ловить ложные срабатывания.

## Результаты

| Бенчмарк | Движок | TP | FP | FN | TPR | FPR | Score |
| --- | --- | --- | --- | --- | --- | --- | --- |
| OWASP Benchmark (2740 кейсов) | `argus-java` | 1415 | 0 | 0 | 100.0% | 0.0% | 100.0 |
| OWASP Benchmark (2740 кейсов) | Semgrep (встроенный Java-пак) | 893 | 712 | 522 | 63.1% | 53.7% | 9.4 |
| SCA-фикстуры (11 фикстур, 10 пакетов) | `osv` | 10 | 0 | 0 | 100.0% | 0.0% | 100.0 |

Полные отчёты (JSON + Markdown, включая разбивку по CWE и по правилам):
`benchmark_results/`.

Дополнительная проверка на реальном коде: проект
[java-sec-code](https://github.com/joychou93/java-sec-code) (80 файлов) — 4
находки, все 4 подтверждены вручную (command injection ×2, open redirect ×2);
precision 4/4 при ожидаемо низком recall вне категорий OWASP Benchmark.

## Ограничения

* 100.0 на OWASP Benchmark не значит «100% в бою». Java-движок разрабатывался
  и калибровался на идиомах бенчмарка (сервлетные `getParameter`, ESAPI,
  фабрики `Test`-классов). На незнакомом коде recall заметно ниже — см. проверку
  на `java-sec-code` выше.
* Анализ внутрифайловый и внутриметодный: нет межфайлового dataflow, нет
  разбора фреймворковых конфигураций. Spring MVC покрыт только на уровне
  аннотированных параметров контроллера (`@RequestParam`, `@RequestBody`, …);
  данные, пришедшие из БД/очередей/других сервисов, источниками не считаются.
  Межпроцедурные цепочки через поля класса поддерживаются лишь частично.
* Санитайзеры описаны вручную в каталоге (`argus/sast/java/catalog.py`);
  кастомные wrapper'ы очистки не распознаются и могут давать ложные
  срабатывания (или, наоборот, пропуски).
* Часть Semgrep-правил — паттерновые эвристики (`weakrand`, `hardcoded secret`,
  `weak hash`), они не анализируют поток данных и склонны к ложным срабатываниям
  на «безопасных» вызовах; для Python добавлены исключения списков аргументов и
  `shell=False`.
* Каталог Java-стоков узкий: SQL/LDAP/XPath/команды/файлы/XSS-writer/cookies/
  trust-boundary. Десериализация, SSRF, шаблоны и т.п. не покрыты.
* Ruby-пак работает без dataflow: часть правил (`ruby-dynamic-code`,
  `ruby-path-traversal`) требует, чтобы аргумент выглядел как внешние данные.
  Это сознательный компромисс в пользу precision: реальные цепочки через
  промежуточные переменные (`path = params[:f]; File.read(path)`) пропускаются,
  а вызовы вроде `class_eval %{...}` и `File.read(CONST)` — нет.
* C-правило `memcpy` подавляет копии с длиной `sizeof(...)` и копии в буфер,
  выделенный тем же размером. Это убирает шум на векторах/gumbo, но может
  скрыть реальную ошибку, если длина одновременно контролируется атакующим и
  совпадает с размером аллокации (редкий, но возможный случай).
* Условные зависимости Ruby (`spec.add_dependency(...) unless java_p`) и
  платформенные блоки `platforms :mri do` статически не вычисляются: такие
  зависимости считаются установленными, что может дать лишний пакет в отчёте.
* SCA не разрешает версии через registry: транзитивное дерево строится только
  из lock-файлов, где разрешение уже зафиксировано. `yarn.lock`,
  `pnpm-lock.yaml` и `Pipfile.lock` пока дают пакеты без рёбер
  (`resolved=false`), `go.mod` — только direct/indirect без связей. Для
  bare-манифестов известны лишь direct-зависимости. Политика `min` для
  диапазонов — приближение, такие находки помечаются `assumed=true`.
* Offline-режим требует предварительного `argus db update`; без него SCA
  обращается к OSV API и деградирует при отсутствии сети (ошибки попадают в
  `errors`, код возврата 2).
* Скоринг OWASP — файловый: срабатывание любого правила в файле засчитывается
  категории этого файла, поэтому «чужие» правила могут слегка искажать
  per-category метрики (общий score при этом корректен).
* SBOM строится по манифестам и lock-файлам: хэши и лицензии извлекаются
  только там, где lock-файл их содержит (npm `integrity`, Composer `shasum`, Poetry/uv `hash`, Cargo
  `checksum`, `license`). Для остальных компонентов поля пустые /
  `NOASSERTION`. Транзитивные пакеты появляются только там, где lock-файл их
  перечисляет; для точных версий нужен lock-файл, иначе диапазон разрешается в
  нижнюю границу и помечается `assumed`.
* Debian/Ubuntu: `debian/control` не содержит установленных версий, поэтому
  такие зависимости попадают в SBOM без версии (unversioned) и не проверяются
  в OSV; точные версии даёт только dpkg-база или `.deb`. Без `--deb-suite`
  (и без rootfs/changelog, из которых релиз определяется) пакеты пропускаются:
  советники OSV привязаны к конкретному релизу (`Debian:<N>`,
  `Ubuntu:<YY.MM>[:LTS]`). Советники Ubuntu Pro/ESM
  (`Ubuntu:Pro:FIPS-*`, `…:esm-*`) пока не запрашиваются: определяется только
  базовый релиз, поэтому версии с ESM-суффиксами могут не найти свою запись.
* EPSS/KEV — внешние фиды: их доступность и актуальность не гарантированы.
  При отсутствии сети используется кэш (возможно, устаревший), а причина
  попадает в `stats.threat_intel.errors`. Локальные `--epss-file`/`--kev-file`
  полностью воспроизводимы, но их нужно обновлять самостоятельно.

## Тесты

```bash
cd argus
PYTHONPATH=. .venv/bin/python -m pytest tests/ -q
```

Те же тесты идут в CI на Python 3.10–3.13, плюс end-to-end demo-скан:
[workflow tests](../../actions/workflows/ci.yml).

445 тестов: taint-движок (источники/стоки/санитайзеры/ветвления/контейнеры,
Spring MVC-параметры), секреты и IaC, версии и диапазоны OSV, парсеры
манифестов (включая `Gemfile`/`*.gemspec` и извлечение лицензий/хэшей),
Debian/Ubuntu (`debian/control`, dpkg status, `.deb`, dpkg-версии, релизы и
OSV `Debian:<N>`/`Ubuntu:<release>`), дедупликация пакетов SCA, рёбра lock-файлов и BFS-глубины графа, фильтрация
висячих рёбер, скоринг OWASP и SCA-бенчмарков, JSON/SARIF/Markdown/text-
рендеринг и поля `summary`, генерация CycloneDX/SPDX SBOM (структура, purl,
scope, `dependencies`/`DEPENDS_ON`, лицензии/хэши, подпись и `--verify`,
direct/depth, фильтр dev-зависимостей, сортировка, уникальность SPDX ID,
пустой проект), CLI-коды возврата, конфиг (TOML/JSON, поиск вверх,
относительные пути, argparse-defaults), baseline и `diff`, подавления и
срок действия, обогащение (CWE/remediation/сниппеты/severity overrides),
quality gates и `deny_licenses`, порядок workflow, VEX, инкрементальный
SAST-кэш, целостность offline-базы OSV (`--verify`), EPSS/KEV (парсинг,
матчинг, кэш, офлайн-файлы, отчёты), вспомогательные функции GUI (сборка
команды, сводка, строка таблицы, дерево зависимостей, сортировка, фильтры,
сравнение, разбор находки и путь в графе), справочник CWE (нормализация
идентификаторов, поиск, покрытие правил, CLI-форматы), структура и валидность
Semgrep-паков (включая прогон правил по уязвимым сэмплам и проверку
подавления C-шума).

## Структура репозитория

```
argus/
├── argus/
│   ├── cli.py                 # команды, флаги, коды возврата
│   ├── config.py              # argus.toml/json, поиск вверх, argparse-defaults
│   ├── baseline.py            # stable key, baseline, diff отчётов
│   ├── suppress.py            # .argusignore / JSON / TOML, expiry
│   ├── enrich.py              # сниппеты, remediation, CWE, severity overrides
│   ├── gates.py               # quality gates и политики
│   ├── workflow.py            # порядок пост-обработки и gate
│   ├── threat.py              # EPSS + CISA KEV, кэш, offline-файлы
│   ├── vex.py                 # OpenVEX 0.2.0
│   ├── secrets.py             # сканер секретов
│   ├── iac.py                 # Dockerfile / Kubernetes / Terraform
│   ├── cwe.py                 # встроенный справочник CWE
│   ├── models.py              # Finding/ScanResult, severity, dedupe, summary
│   ├── output/__init__.py     # JSON / SARIF / Markdown / text
│   ├── sbom.py                # CycloneDX 1.5 / SPDX 2.3 / Markdown, подпись
│   ├── gui.py                 # tkinter-интерфейс
│   ├── sast/
│   │   ├── scanner.py         # диспетчер движков, секреты, IaC
│   │   ├── cache.py           # инкрементальный SQLite-кэш Java-анализа
│   │   ├── semgrep_engine.py  # обёртка Semgrep CLI
│   │   ├── rules/<lang>/…     # встроенные паки правил
│   │   └── java/              # tree-sitter taint-движок + каталог
│   ├── sca/
│   │   ├── parsers.py         # манифесты/lock -> Package + лицензии/хэши
│   │   ├── debian.py          # debian/control, dpkg status, .deb, suite
│   │   ├── graph.py           # транзитивный граф, direct/depth, дерево
│   │   ├── versions.py        # сравнение версий, диапазоны OSV
│   │   ├── osv.py             # OSV API / offline-архивы, кэш, --verify
│   │   └── scanner.py         # оркестрация SCA
│   └── bench/
│       ├── owasp.py           # OWASP Benchmark harness
│       └── sca_bench.py       # SCA-фикстуры
├── benchmarks/sca/fixtures/   # 11 SCA-фикстур с expected.json
├── benchmark_results/         # сгенерированные отчёты
├── argus-gui.py               # запуск GUI из исходников
├── scripts/install.sh
└── tests/
```

## Лицензия

MIT, см. [LICENSE](LICENSE).
