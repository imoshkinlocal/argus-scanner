Сторонние компоненты в этом архиве
===================================

argus 1.4.0 распространяется по лицензии MIT (см. LICENSE).

В архив входят следующие сторонние компоненты:

  CPython 3.11.18
    лицензия: PSF-2.0
    текст: python/lib/python3.11/LICENSE.txt
    https://docs.python.org/3/license.html

  Semgrep 1.187.0 (Python-пакет и native semgrep-core)
    лицензия: LGPL-2.1
    текст: licenses/Semgrep-LGPL-2.1.txt
    https://github.com/semgrep/semgrep/blob/develop/LICENSE
    Semgrep используется как отдельный исполняемый файл (runtime/bin/semgrep,
    runtime/semgrep/bin/semgrep-core) и не модифицирован.  Исходный код
    доступен по ссылке выше; при необходимости semgrep-core можно заменить
    на свою сборку, положив её по тому же пути.

  Остальные Python-пакеты (tree-sitter, pydantic, cryptography, requests,
  opentelemetry, mcp и др.)
    лицензии MIT/BSD/Apache-2.0/PSF
    тексты: runtime/<package>-<version>.dist-info/LICENSE* или licenses/
    Полный список: runtime/*.dist-info/METADATA (поле License / classifiers).

  pip 26.3 (в составе CPython)
    лицензия: MIT
    текст: python/lib/python3.11/site-packages/pip-26.3.dist-info/licenses/

Вопросы по лицензиям: см. контакты в README.md.
