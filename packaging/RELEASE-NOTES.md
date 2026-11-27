argus 1.4.0
===========

Сканер кода и зависимостей: SAST (Java dataflow, Semgrep-правила для
Python, JavaScript/TypeScript, Go, PHP, C/C++, Ruby), SCA через OSV,
поиск секретов, IaC-эвристики. Отчёты: text, JSON, SARIF, Markdown,
CycloneDX/SPDX SBOM, OpenVEX.

Что нового
----------

* Каждая находка с CWE сопоставляется с OWASP Top 10. Встроены редакции
  **2017**, **2021** (по умолчанию) и **2025**; один CWE может относиться к
  нескольким категориям (CWE-259 → A02:2021 и A07:2021).
* Флаги `--owasp-version`, `--owasp-file` и `--no-owasp` для `scan`, `sast` и
  `sca`; настройки `owasp`, `owasp_version`, `owasp_file` в конфиге.
* Новая команда `argus owasp [CWE...]`: список категорий редакции или маппинг
  конкретных CWE, форматы text/Markdown/JSON.
* Справочник живёт в `argus/owasp_top10.json` и обновляется скриптом
  `scripts/update_owasp.py` из официального `OWASP/Top10` — без пересборки
  кода. Свой файл (JSON/TOML) подключается через `--owasp-file`.
* OWASP есть во всех представлениях: JSON (`finding.owasp`,
  `summary.by_owasp`, `summary.owasp_version`), text, Markdown (колонка и
  распределение), SARIF (теги `owasp/aNN-YYYY` и properties) и GUI (опции
  сканирования, детали находки, сводка).
* GUI: переключатель OWASP, выбор редакции и своего файла в окне сканирования.

Что скачать
-----------

1. Рекомендуется: argus-1.4.0-linux-x86_64.tar.gz
   Портативный архив. Внутри свой Python 3.11 и Semgrep 1.187.0.
   Распаковал — запустил. Без root, без pip, без сети, без установки.

     tar xzf argus-1.4.0-linux-x86_64.tar.gz
     cd argus-1.4.0-linux-x86_64
     ./argus version
     ./argus scan /path/to/repo -f text
     ./argus owasp 89 79

   Требования: Linux x86_64, glibc >= 2.35 (Debian 12+, Ubuntu 22.04+,
   ALT 10+, ROSA 2021+).

2. Для Debian: argus-scanner_1.4.0-1_all.deb
   Универсальный пакет, Architecture: all, около 245 КБ. При установке
   создаёт приватный runtime в /var/lib/argus-scanner и скачивает актуальный
   Semgrep с PyPI. Нужны сеть (или wheelhouse) и python3 >= 3.10.

     sudo apt install ./argus-scanner_1.4.0-1_all.deb
     argus scan /path/to/repo -f sarif -o argus.sarif

3. Исходники: argus-scanner_1.4.0-1.dsc, orig.tar.gz, debian.tar.xz
   Сборка: dpkg-source -x ...dsc && cd argus-scanner-1.4.0 &&
           dpkg-buildpackage -us -uc -b

Артефакты
---------
  argus-1.4.0-linux-x86_64.tar.gz          ~121 МБ  портативный архив
  argus-scanner_1.4.0-1_all.deb            ~245 КБ  универсальный .deb
  argus-scanner_1.4.0-1.dsc                        source package
  argus-scanner_1.4.0.orig.tar.gz          ~270 КБ  исходники
  argus-scanner_1.4.0-1.debian.tar.xz       ~10 КБ  debian/
  SHA256SUMS                                       контрольные суммы

Проверка
--------
  sha256sum -c SHA256SUMS

Основное в 1.4.0
----------------
  * OWASP Top 10 (2017/2021/2025) для находок с CWE, свои файлы и
    обновление справочника из OWASP/Top10;
  * GUI-поля для --owasp-version/--owasp-file/--no-owasp;
  * экосистемы Debian и Ubuntu: control, dpkg, .deb, OSV по релизам;
  * предложения замен из Semgrep-правил во всех форматах отчётов;
  * Java dataflow engine и наборы правил для 7 языков;
  * SCA через OSV (онлайн и офлайн, --offline с локальной базой);
  * поиск секретов, IaC-проверки, baseline и подавления;
  * форматы text/json/sarif/md/sbom/vex, quality gates, EPSS/KEV;
  * портативный архив с собственным CPython — не зависит от системы;
  * универсальный .deb ставит актуальный Semgrep при установке.

Лицензия
--------
  MIT (argus). В архиве: Semgrep — LGPL-2.1, CPython — PSF-2.0;
  полные тексты в licenses/ и THIRD-PARTY-NOTICES.md.
