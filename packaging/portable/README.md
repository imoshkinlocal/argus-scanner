argus 1.3.0 — портативный архив для Linux
=========================================

Скачал, распаковал, запустил — ничего устанавливать не нужно.
Внутри уже есть Python 3.11, сам argus, его зависимости и Semgrep 1.187.0.
Ни root, ни pip, ни системный Python не требуются.

Требования
----------
  * Linux x86_64 (amd64);
  * glibc 2.35 или новее: Debian 12+, Ubuntu 22.04+, ALT 10+,
    ROSA 2021+;
  * всё остальное — в архиве. Сеть нужна только для SCA-запросов к OSV
    (можно выключить) и для обновления Semgrep.

Быстрый старт
-------------
  tar xzf argus-1.3.0-linux-x86_64.tar.gz
  cd argus-1.3.0-linux-x86_64

  ./argus version
  # argus 1.3.0
  # python 3.11.18
  # semgrep .../runtime/bin/semgrep

  cd /path/to/repo
  /path/to/argus-1.3.0-linux-x86_64/argus scan . -f text

Чтобы звать просто `argus`, положите ссылку в ~/.local/bin:

  mkdir -p ~/.local/bin
  ln -sf /path/to/argus-1.3.0-linux-x86_64/argus ~/.local/bin/argus

Отчёты и код возврата
---------------------
  ./argus scan . -f text
  ./argus scan . -f sarif -o argus.sarif     # GitLab / GitHub
  ./argus scan . -f json  -o argus.json
  ./argus scan . -f md    -o argus.md
  ./argus scan . --no-sca                    # только SAST

  0 — находок нет, 1 — есть находки, 2 — ошибка.

SCA (зависимости)
-----------------
По умолчанию запросы идут к api.osv.dev. Для офлайна:

  ./argus db update                          # один раз, с сетью
  ./argus sca /path/to/repo --offline

База лежит в ~/.cache/argus/osv-db, её можно перенести на другую машину.

GUI
---
  ./argus-gui

Нужна графическая сессия и системные X-библиотеки (libX11, libXft,
libXrender). CLI работает без них.

Обновление Semgrep
------------------
  ./update-semgrep.sh                  # последняя версия с PyPI
  ./update-semgrep.sh 1.90.0           # зафиксировать версию
  ./update-semgrep.sh --list           # что используется
  ./update-semgrep.sh --remove         # вернуться к версии из архива
  ./update-semgrep.sh --wheelhouse DIR # офлайн-обновление

Обновление ставится в ./semgrep-overlay и не трогает bundled-версию,
поэтому неудачный апдейт откатывается одной командой.

Удаление
--------
  rm -rf argus-1.3.0-linux-x86_64        # больше ничего не создаётся

Что внутри
----------
  argus                  CLI
  argus-gui              Tk-интерфейс
  update-semgrep.sh      обновление Semgrep
  python/                CPython 3.11.18 (python-build-standalone)
  runtime/               argus + зависимости + Semgrep 1.187.0
  README.md              этот файл
  README-argus.md        полная документация argus
  BUNDLE.txt             версии и состав
  LICENSE                MIT

Проверка целостности
--------------------
Рядом с архивом лежит SHA256SUMS:

  sha256sum -c SHA256SUMS

Другие способы установки
------------------------
  * Debian: argus-scanner_1.3.0-1_all.deb (системная установка,
    semgrep скачивается при установке);
  * офлайн .deb 58 МБ: только amd64 + Python 3.11 (legacy 1.1.0-2).
