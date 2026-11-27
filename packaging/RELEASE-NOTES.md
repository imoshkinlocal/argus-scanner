argus 1.3.0
===========

Сканер кода и зависимостей: SAST (Java dataflow, Semgrep-правила для
Python, JavaScript/TypeScript, Go, PHP, C/C++, Ruby), SCA через OSV,
поиск секретов, IaC-эвристики. Отчёты: text, JSON, SARIF, Markdown,
CycloneDX/SPDX SBOM, OpenVEX.

Что нового
----------

* SCA и SBOM понимают Debian и Ubuntu: `debian/control`, база dpkg
  (`--deb-root` / `--deb-status`) и отдельные `.deb` (`--deb`). Версии
  сравниваются алгоритмом dpkg, purl получает `arch` и `distro`
  (`pkg:deb/debian/…`, `pkg:deb/ubuntu/…`).
* OSV-советники выбираются по релизу: `Debian:11/12/13/14` и
  `Ubuntu:22.04:LTS`, `Ubuntu:24.04:LTS`, `Ubuntu:24.10`. Релиз берётся из
  `/etc/os-release`/`/etc/debian_version`, из `debian/changelog` или задаётся
  явно через `--deb-suite bookworm|jammy|12|22.04`.
* GUI получил блок «Пакеты Debian/Ubuntu»: корень системы, status-файл dpkg,
  список `.deb` и релиз.
* Offline-архивы Debian (~85 МБ) и Ubuntu (~800 МБ) остаются опциональными:
  `argus db update --ecosystem Debian` / `--ecosystem Ubuntu`.
* Без известного релиза Debian/Ubuntu-пакеты пропускаются с предупреждением,
  а не проверяются по чужой ветке.

Что скачать
-----------

1. Рекомендуется: argus-1.3.0-linux-x86_64.tar.gz
   Портативный архив. Внутри свой Python 3.11 и Semgrep 1.187.0.
   Распаковал — запустил. Без root, без pip, без сети, без установки.

     tar xzf argus-1.3.0-linux-x86_64.tar.gz
     cd argus-1.3.0-linux-x86_64
     ./argus version
     ./argus scan /path/to/repo -f text

   Требования: Linux x86_64, glibc >= 2.35 (Debian 12+, Ubuntu 22.04+,
   ALT 10+, ROSA 2021+).

2. Для Debian: argus-scanner_1.3.0-1_all.deb
   Универсальный пакет, Architecture: all, около 245 КБ. При установке
   создаёт приватный runtime в /var/lib/argus-scanner и скачивает актуальный
   Semgrep с PyPI. Нужны сеть (или wheelhouse) и python3 >= 3.10.

     sudo apt install ./argus-scanner_1.3.0-1_all.deb
     argus scan /path/to/repo -f sarif -o argus.sarif

3. Исходники: argus-scanner_1.3.0-1.dsc, orig.tar.gz, debian.tar.xz
   Сборка: dpkg-source -x ...dsc && cd argus-scanner-1.3.0 &&
           dpkg-buildpackage -us -uc -b

Артефакты
---------
  argus-1.3.0-linux-x86_64.tar.gz          ~121 МБ  портативный архив
  argus-scanner_1.3.0-1_all.deb            ~245 КБ  универсальный .deb
  argus-scanner_1.3.0-1.dsc                        source package
  argus-scanner_1.3.0.orig.tar.gz          ~261 КБ  исходники
  argus-scanner_1.3.0-1.debian.tar.xz       ~10 КБ  debian/
  SHA256SUMS                                       контрольные суммы

Проверка
--------
  sha256sum -c SHA256SUMS

Основное в 1.3.0
----------------
  * экосистемы Debian и Ubuntu: control, dpkg, .deb, OSV по релизам;
  * GUI-поля для --deb-root/--deb-status/--deb/--deb-suite;
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
