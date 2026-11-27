argus 1.2.0
===========

Сканер кода и зависимостей: SAST (Java dataflow, Semgrep-правила для
Python, JavaScript/TypeScript, Go, PHP, C/C++, Ruby), SCA через OSV,
поиск секретов, IaC-эвристики. Отчёты: text, JSON, SARIF, Markdown,
CycloneDX/SPDX SBOM, OpenVEX.

Что нового
----------

* Semgrep-правила могут предлагать готовую замену (`fix` / `fix-regex`).
  argus показывает её как `suggested_fix` в JSON, SARIF (`fixes[]`),
  Markdown, текстовом отчёте и GUI. Замена никогда не применяется
  автоматически: сканирование остаётся read-only.
* Предложения есть для правил `python-flask-debug`, `python-yaml-load`,
  `python-paramiko-auto-add-policy`, `java-insecure-cookie`,
  `java-httponly-cookie` и `go-tls-insecure-skip-verify`.
* Severity находки не меняется: `WARNING` остаётся `medium`, `ERROR` —
  `high`; это закреплено тестами.

Что скачать
-----------

1. Рекомендуется: argus-1.2.0-linux-x86_64.tar.gz
   Портативный архив. Внутри свой Python 3.11 и Semgrep 1.187.0.
   Распаковал — запустил. Без root, без pip, без сети, без установки.

     tar xzf argus-1.2.0-linux-x86_64.tar.gz
     cd argus-1.2.0-linux-x86_64
     ./argus version
     ./argus scan /path/to/repo -f text

   Требования: Linux x86_64, glibc >= 2.35 (Debian 12+, Ubuntu 22.04+,
   ALT 10+, ROSA 2021+).

2. Для Debian: argus-scanner_1.2.0-1_all.deb
   Универсальный пакет, Architecture: all, около 245 КБ. При установке
   создаёт приватный runtime в /var/lib/argus-scanner и скачивает актуальный
   Semgrep с PyPI. Нужны сеть (или wheelhouse) и python3 >= 3.10.

     sudo apt install ./argus-scanner_1.2.0-1_all.deb
     argus scan /path/to/repo -f sarif -o argus.sarif

3. Исходники: argus-scanner_1.2.0-1.dsc, orig.tar.gz, debian.tar.xz
   Сборка: dpkg-source -x ...dsc && cd argus-scanner-1.2.0 &&
           dpkg-buildpackage -us -uc -b

Артефакты
---------
  argus-1.2.0-linux-x86_64.tar.gz          ~121 МБ  портативный архив
  argus-scanner_1.2.0-1_all.deb            ~245 КБ  универсальный .deb
  argus-scanner_1.2.0-1.dsc                        source package
  argus-scanner_1.2.0.orig.tar.gz          ~261 КБ  исходники
  argus-scanner_1.2.0-1.debian.tar.xz       ~10 КБ  debian/
  SHA256SUMS                                       контрольные суммы

Проверка
--------
  sha256sum -c SHA256SUMS

Основное в 1.2.0
----------------
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
