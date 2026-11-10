#!/usr/bin/env python3
"""Install the pinned official macOS ipsw executable without Homebrew tap parsing."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request

VERSION = '3.1.743'
ARCHIVES = {
    'arm64': ('arm64', 'c7da3f9fba1901a608e81d06269f4050f60a5b55ebf7418535336bb9c8810eba'),
    'x86_64': ('x86_64', '6cdc9417e2cacd60232f7b7ce6d4b6866668ca844735543239e5e68729e6a58d'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() not in ARCHIVES:
        parser.error('Require a macOS ARM64 or Intel build host')
    arch, expected = ARCHIVES[platform.machine()]
    url = f'https://github.com/blacktop/ipsw/releases/download/v{VERSION}/ipsw_{VERSION}_macOS_{arch}_extras.tar.gz'
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='unixnu-ipsw-') as scratch:
        archive = Path(scratch) / 'ipsw.tar.gz'
        for attempt in range(4):
            try:
                with urllib.request.urlopen(url, timeout=60) as source, archive.open('wb') as target:
                    shutil.copyfileobj(source, target)
                break
            except OSError:
                if attempt == 3:
                    raise RuntimeError('Official ipsw release download failed') from None
                time.sleep(2 ** attempt)
        with archive.open('rb') as source:
            if hashlib.file_digest(source, 'sha256').hexdigest() != expected:
                raise SystemExit('Official ipsw archive SHA-256 mismatch')
        with tarfile.open(archive) as package:
            matches = [item for item in package.getmembers() if item.name in ('ipsw', './ipsw')]
            if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= 256 << 20:
                raise SystemExit('Official ipsw archive executable is missing or invalid')
            temporary = Path(scratch) / 'ipsw'
            with package.extractfile(matches[0]) as source, temporary.open('wb') as target:
                shutil.copyfileobj(source, target)
            temporary.chmod(0o755)
            destination = args.output / 'ipsw'
            shutil.copyfile(temporary, destination)
            destination.chmod(0o755)
    subprocess.run([str(destination.resolve()), 'version'], check=True)
    if os.environ.get('GITHUB_PATH'):
        with open(os.environ['GITHUB_PATH'], 'a') as output:
            output.write(str(args.output.resolve()) + '\n')
    print(f'Installed official ipsw {VERSION} ({arch}); archive SHA-256 verified')


if __name__ == '__main__':
    main()
