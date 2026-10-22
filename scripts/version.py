#!/usr/bin/env python3
"""NowTP's version: library.json's, which CI's release numbering reads, copied
into each manifest that states it. PlatformIO, Arduino and ESP-IDF each read
their own without running anything, so the copies stay: this writes them.

  python3 scripts/version.py           checks that the copies agree
  python3 scripts/version.py 0.6.0     sets the version everywhere

Releases stamp it (see .github/workflows/ci.yml); nobody edits it by hand.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Each file, and where it states the version (its first match): what comes
# before it, and the version.
FILES = [
    ('library.json', re.compile(r'("version": ")([^"]*)')),
    ('library.properties', re.compile(r'^(version=)(.*)$', re.M)),
    ('idf_component.yml', re.compile(r'^(version: ")([^"]*)', re.M)),
]


def read(file):
    return (ROOT / file).read_text(encoding='utf-8')


def main(args):
    if len(args) > 1 or (args and not re.fullmatch(r'\d+\.\d+\.\d+', args[0])):
        print('usage: python3 scripts/version.py [X.Y.Z]', file=sys.stderr)
        return 2
    if args:
        for file, pattern in FILES:
            text = read(file)
            (ROOT / file).write_text(pattern.sub(lambda m: m[1] + args[0], text, count=1), encoding='utf-8')
    found = []
    for file, pattern in FILES:
        m = pattern.search(read(file))
        found.append((file, m[2] if m else None))
        print(f'{found[-1][1] or "(none)"}\t{file}')
    return 0 if all(v is not None and v == found[0][1] for _, v in found) else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
