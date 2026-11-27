argus 1.5.0
===========

Сканер кода и зависимостей: SAST (Java dataflow, Semgrep-правила для
Python, JavaScript/TypeScript, Go, PHP, C/C++, Ruby), SCA через OSV,
поиск секретов, IaC-эвристики. Отчёты: text, JSON, SARIF, Markdown,
CycloneDX/SPDX SBOM, OpenVEX.

Что нового
----------

* Новый GUI на Qt (PySide6): боковая навигация, таблица находок с фильтрами
  и группировкой, цветные счётчики severity, карточка выбранной находки,
  сводка с распределением OWASP Top 10, вкладки зависимостей, справочника
  CWE и справки.
* `argus-gui` по умолчанию открывает Qt-окно. Флаг `--tk` включает прежний
  Tk-интерфейс; он же используется автоматически, если PySide6 недоступен.
* `.deb` ставит `PySide6-Essentials` в приватный runtime, поэтому Qt
  открывается без системного `python3-pyside6`. При обновлении с 1.4.0
  `postinst` добавляет Qt в существующий runtime, не пересобирая его.
* `argus-setup-runtime --upgrade-gui` добавляет или обновляет Qt, `--no-gui`
  пропускает его, `--list` показывает версию GUI.
* Логика интерфейса вынесена в `argus/gui_core.py` без зависимости от
  тулкита: Qt- и Tk-окна показывают одни и те же данные.
* Для установки из исходников: `pip install 'argus-scanner[gui]'`.

Что скачать
-----------

1. Рекомендуется: argus-1.5.0-linux-x86_64.tar.gz
   Портативный архив. Внутри свой Python 3.11 и Semgrep 1.187.0.
   Распаковал — запустил. Без root, без pip, без сети, без установки.

     tar xzf argus-1.5.0-linux-x86_64.tar.gz
     cd argus-1.5.0-linux-x86_64
     ./argus version
     ./argus scan /path/to/repo -f text
     ./argus owasp 89 79

   Требования: Linux x86_64, glibc >= 2.35 (Debian 12+, Ubuntu 22.04+,
   ALT 10+, ROSA 2021+). GUI в архиве — Tk (`python3-tk`); PySide6 в
   портативный runtime не входит.

2. Для Debian: argus-scanner_1.5.0-1_all.deb
   Универсальный пакет, Architecture: all. При установке создаёт приватный
   runtime в /var/lib/argus-scanner, скачивает актуальный Semgrep и
   PySide6-Essentials с PyPI. Нужны сеть (или wheelhouse) и python3 >= 3.10.

     sudo apt install ./argus-scanner_1.5.0-1_all.deb
     argus-gui                       # Qt-интерфейс
     argus scan /path/to/repo -f sarif -o argus.sarif

3. Исходники: argus-scanner_1.5.0-1.dsc, orig.tar.gz, debian.tar.xz
   Сборка: dpkg-source -x ...dsc && cd argus-scanner-1.5.0 &&
           dpkg-buildpackage -us -uc -b

Артефакты
---------
  argus-1.5.0-linux-x86_64.tar.gz          ~121 МБ  портативный архив
  argus-scanner_1.5.0-1_all.deb            ~300 КБ  универсальный .deb
  argus-scanner_1.5.0-1.dsc                        source package
  argus-scanner_1.5.0.orig.tar.gz          ~440 КБ  исходники
  argus-scanner_1.5.0-1.debian.tar.xz       ~13 КБ  debian/
  SHA256SUMS                                       контрольные суммы

Проверка
--------
  sha256sum -c SHA256SUMS

Основное в 1.5.0
----------------
  * Qt-интерфейс (PySide6) с навигацией, фильтрами и карточкой находки;
  * Qt из .deb без системного python3-pyside6, обновление runtime на месте;
  * --tk, --upgrade-gui и --no-gui; резервный Tk-интерфейс;
  * OWASP Top 10 (2017/2021/2025) для находок с CWE;
  * экосистемы Debian и Ubuntu: control, dpkg, .deb, OSV по релизам;
  * Java dataflow engine и наборы правил для 7 языков;
  * SCA через OSV (онлайн и офлайн, --offline с локальной базой);
  * поиск секретов, IaC-проверки, baseline и подавления;
  * форматы text/json/sarif/md/sbom/vex, quality gates, EPSS/KEV.

Лицензия
--------
  MIT (argus). В архиве: Semgrep — LGPL-2.1, CPython — PSF-2.0;
  полные тексты в licenses/ и THIRD-PARTY-NOTICES.md.
