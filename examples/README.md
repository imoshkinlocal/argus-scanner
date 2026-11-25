# Пример: две известные уязвимости

Маленький проект, на котором видно, что сканер действительно находит проблемы.

```
examples/vulnerable/
├── Vulnerable.java   SQL-инъекция: request.getParameter -> Statement.executeQuery
└── app.py            command injection: subprocess.call(..., shell=True)
```

## Как воспроизвести

Из корня репозитория:

```bash
./scripts/demo.sh
```

или вручную:

```bash
argus scan examples/vulnerable --no-sca -f text
```

Ожидаемый результат (код возврата 1 — находки есть):

```
HIGH               java-sqli-jdbc
    at: Vulnerable.java:9
    cwe: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)

HIGH               python-command-injection
    at: app.py:6
    cwe: CWE-78 (Improper Neutralization of Special Elements used in an OS Command)

Summary: critical: 0, high: 2, medium: 0, low: 0, info: 0, total: 2
```

## Готовые отчёты

Рядом лежат отчёты, полученные этим же прогоном:

| файл | формат |
|---|---|
| `report.txt` | text |
| `report.json` | JSON (машиночитаемый) |
| `report.sarif` | SARIF 2.1.0 (GitLab/GitHub code scanning, IDE) |

В `report.sarif` база `%SRCROOT%` равна `examples/vulnerable/`, пути внутри
файлов — относительные, чтобы отчёт не зависел от машины.

## Другие цели

```bash
argus scan examples/vulnerable --no-sca -f sarif -o report.sarif
argus scan . --no-sca --exclude .venv --exclude tests
argus scan . --no-sca --config argus.toml
```
