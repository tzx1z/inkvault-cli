"""Лицензии зависимостей Rust и их совместимость с лицензией проекта (AGPL-3.0-only).

Источник - cargo metadata со всеми возможностями пакетов. Код возврата 1 - есть несовместимая
или неизвестная лицензия.

Запуск из корня репозитория: python3 -I tools/licenses.py [--details]
"""


import argparse
import collections
import json
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Лицензии, совместимые с AGPL-3.0: код под ними можно распространять в составе программы под AGPL.
# MPL-2.0 совместима благодаря разделу 3.3, пока автор не пометил код "Incompatible With Secondary
# Licenses"; LGPL-2.1 разрешает перейти на GPL версии 2 или более поздней.
COMPATIBLE = {
    "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSL-1.0", "CC0-1.0", "ISC", "MIT",
    "MIT-0", "MPL-2.0", "Unicode-3.0", "Unicode-DFS-2016", "Unlicense", "WTFPL", "Zlib",
    "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "GPL-3.0-only", "GPL-3.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later",
}
EXCEPTIONS = {"LLVM-exception"}


def tokens(expression: str) -> list[str]:
    # старая запись "MIT/Apache-2.0" означает выбор одной из лицензий
    return re.findall(r"\(|\)|[^\s()]+", expression.replace("/", " OR "))


def compatible(expression: str) -> bool:
    """Выражение SPDX с OR, AND, WITH и скобками."""
    items = tokens(expression)
    pos = 0

    def parse_or() -> bool:
        nonlocal pos
        result = parse_and()
        while pos < len(items) and items[pos] == "OR":
            pos += 1
            result = parse_and() or result
        return result

    def parse_and() -> bool:
        nonlocal pos
        result = parse_atom()
        while pos < len(items) and items[pos] == "AND":
            pos += 1
            result = parse_atom() and result
        return result

    def parse_atom() -> bool:
        nonlocal pos
        item = items[pos]
        pos += 1
        if item == "(":
            result = parse_or()
            pos += 1
        else:
            result = item in COMPATIBLE
        if pos < len(items) and items[pos] == "WITH":
            result = result and items[pos + 1] in EXCEPTIONS
            pos += 2
        return result

    try:
        return parse_or() and pos == len(items)
    except IndexError:
        return False


def rust() -> list[tuple[str, str]]:
    # все возможности всех пакетов: в отчет попадает и генератор биндингов UniFFI
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--all-features", "--offline"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout
    meta = json.loads(out)
    members = set(meta["workspace_members"])
    return [
        (f"{p['name']} {p['version']}", p.get("license") or f"файл {p.get('license_file')}")
        for p in meta["packages"] if p["id"] not in members
    ]


def report(title: str, packages: list[tuple[str, str]], details: bool) -> list[tuple[str, str]]:
    counts = collections.Counter(license for _, license in packages)
    print(f"\n{title}: {len(packages)}")
    for license, count in counts.most_common():
        print(f"  {count:4} {license}")
    if details:
        for name, license in sorted(packages):
            print(f"       {name}: {license}")
    return [(name, license) for name, license in packages if not compatible(license)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--details", action="store_true", help="перечислить все пакеты")
    args = parser.parse_args()

    problems = report("Rust: ядро и CLI", rust(), args.details)

    print()
    for name, license in problems:
        print(f"[FAIL] {name}: {license}")
    print(f"Итог: {'есть несовместимые или неизвестные лицензии' if problems else 'все лицензии совместимы с AGPL-3.0-only'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
