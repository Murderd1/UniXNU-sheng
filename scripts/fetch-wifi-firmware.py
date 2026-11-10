#!/usr/bin/env python3
"""Fetch missing WCN7850 inputs from their pinned source and verify all bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def fetch(source, manifest, check_only=False):
    repository, revision, directory = (manifest[key] for key in ('repository', 'commit', 'directory'))
    if not re.fullmatch(r'https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) \
            or not re.fullmatch(r'[0-9a-f]{40}', revision) \
            or directory != 'ath12k/WCN7850/hw2.0':
        raise ValueError('Invalid pinned Wi-Fi firmware source')
    for name, expected in manifest['files'].items():
        if name not in ('amss.bin', 'amss2.bin', 'm3.bin', 'board-2.bin') \
                or not 0 < expected['bytes'] <= 16 << 20 \
                or not re.fullmatch(r'[0-9a-f]{64}', expected['sha256']):
            raise ValueError('Invalid Wi-Fi firmware manifest entry')
        destination = source / name
        missing = not destination.is_file()
        if missing:
            if check_only:
                raise ValueError('Missing Wi-Fi firmware: ' + name)
            url = repository.replace('github.com', 'raw.githubusercontent.com') + '/' + revision + '/' + directory + '/' + name
            for attempt in range(4):
                try:
                    with urllib.request.urlopen(url, timeout=60) as response:
                        data = response.read(expected['bytes'] + 1)
                    break
                except OSError:
                    if attempt == 3:
                        raise RuntimeError('Could not fetch pinned Wi-Fi firmware: ' + name) from None
                    time.sleep(2 ** attempt)
        else:
            if destination.stat().st_size != expected['bytes']:
                raise ValueError('Wi-Fi firmware size mismatch: ' + name)
            data = destination.read_bytes()
        if len(data) != expected['bytes'] or hashlib.sha256(data).hexdigest() != expected['sha256']:
            raise ValueError('Wi-Fi firmware identity mismatch: ' + name)
        if missing:
            source.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=source, prefix=name + '.', delete=False) as temporary:
                path = Path(temporary.name)
                temporary.write(data)
            try:
                path.replace(destination)
            finally:
                path.unlink(missing_ok=True)
        print(name + ': pinned size and SHA-256 verified', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='verify local inputs without downloading')
    args = parser.parse_args()
    source = ROOT / 'firmware/wcn7850'
    fetch(source, json.loads((source / 'manifest.json').read_text()), args.check)
