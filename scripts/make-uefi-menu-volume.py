#!/usr/bin/env python3
"""Create and read back a 4 MiB FAT16 UEFI menu fixture without mounting it.

The image contains only unixnu.toml and the supplied AArch64 HelloPayload EFI
application. It is suitable for embedding as a read-only firmware-volume file.
No kernel, OS payload, boot ramdisk or device operation is involved.

Import build_volume(hello_efi, build_id, output) to use it from another builder.
The output image and its adjacent JSON report must both be fresh paths.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'package/UefiMenu/unixnu.toml.in'
EPOCH = 315532800  # 1980-01-01 00:00:00 UTC, representable by FAT.
VOLUME_BYTES = 4 * 1024 * 1024
CONFIG_PATH = 'EFI/UniXNU/unixnu.toml'
HELLO_PATH = 'EFI/UniXNU/Payloads/HelloPayload.efi'
MISSING_PATH = 'EFI/UniXNU/Payloads/DoesNotExist.efi'


class VolumeError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def render_config(build_id):
    """Render and check the exact three-entry configuration without mtools."""
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,96}', build_id):
        raise VolumeError('build ID must be 1-96 ASCII letters, digits, dots, underscores or hyphens')
    template = TEMPLATE.read_text(encoding='utf-8')
    if template.count('@BUILD_ID@') != 1:
        raise VolumeError('configuration template must contain exactly one build-ID placeholder')
    text = template.replace('@BUILD_ID@', build_id)
    config = tomllib.loads(text)
    if config.get('version') != 1 or config.get('boot') != {'timeout': -1, 'rotate': 0, 'default': 'missing'}:
        raise VolumeError('menu fixture boot settings changed')
    if config.get('kits') != {'autoload': False} or build_id not in config['ui']['title']:
        raise VolumeError('menu fixture title or kit settings changed')
    entries = config.get('entry', [])
    if [entry.get('id') for entry in entries] != ['missing', 'hello', 'shutdown']:
        raise VolumeError('menu fixture must have missing, hello and shutdown entries in that order')
    for entry in entries:
        if not isinstance(entry.get('confirm'), str) or not entry['confirm'].strip():
            raise VolumeError('every entry must require confirmation, including no-input fallback')
    if entries[0].get('type') != 'efi' or entries[0].get('path') != 'Payloads/DoesNotExist.efi':
        raise VolumeError('missing-file entry changed')
    if entries[1].get('type') != 'efi' or entries[1].get('path') != 'Payloads/HelloPayload.efi' or entries[1].get('args') != 'plain pause':
        raise VolumeError('HelloPayload entry must pause and return without starting an OS')
    if entries[2].get('type') != 'action' or entries[2].get('action') != 'shutdown':
        raise VolumeError('shutdown entry changed')
    return text.encode('ascii')


def _normalize_directory_times(image):
    """Fix all short directory entry times, including mtools creation dates."""
    data = bytearray(image.read_bytes())
    bps, spc, reserved, fats, root_count, total16, _media, fat_sectors = struct.unpack_from('<HBHBHHBH', data, 11)
    total = total16 or struct.unpack_from('<I', data, 32)[0]
    root_sectors = (root_count * 32 + bps - 1) // bps
    data_sector = reserved + fats * fat_sectors + root_sectors
    clusters = (total - data_sector) // spc if spc else 0
    if bps != 512 or not 4085 <= clusters < 65525 or len(data) != VOLUME_BYTES or total * bps != len(data) or data[510:512] != b'\x55\xaa':
        raise VolumeError('mformat did not create the expected 4 MiB FAT16 geometry')
    fat_start = reserved * bps
    cluster_bytes = spc * bps
    visited = set()

    def visit(start, length):
        for offset in range(start, start + length, 32):
            first, attr = data[offset], data[offset + 11]
            if first == 0:
                break
            if first == 0xE5 or attr == 0x0F:
                continue
            data[offset + 13] = 0
            struct.pack_into('<HHH', data, offset + 14, 0, 0x21, 0x21)
            struct.pack_into('<HH', data, offset + 22, 0, 0x21)
            if attr & 0x10 and first != ord('.'):
                cluster = struct.unpack_from('<H', data, offset + 26)[0]
                while cluster < 0xFFF8:
                    if not 2 <= cluster < clusters + 2 or cluster in visited:
                        raise VolumeError('invalid or cyclic FAT16 directory chain')
                    visited.add(cluster)
                    visit((data_sector + (cluster - 2) * spc) * bps, cluster_bytes)
                    cluster = struct.unpack_from('<H', data, fat_start + cluster * 2)[0]

    visit((reserved + fats * fat_sectors) * bps, root_count * 32)
    image.write_bytes(data)
    return {'type': 'FAT16', 'bytes_per_sector': bps, 'sectors_per_cluster': spc,
            'total_sectors': total, 'data_clusters': clusters}


def build_volume(hello_efi, build_id, output):
    """Write a fresh FAT image and JSON report; return the verified report."""
    hello_efi, output = Path(hello_efi).resolve(), Path(output).resolve()
    report_path = output.with_suffix('.json')
    if output == report_path or output.exists() or report_path.exists():
        raise VolumeError('image and adjacent .json report must both be fresh paths')
    config = render_config(build_id)
    hello = hello_efi.read_bytes()
    if len(hello) < 64 or hello[:2] != b'MZ':
        raise VolumeError('HelloPayload must be a PE/COFF EFI application')
    pe = struct.unpack_from('<I', hello, 60)[0]
    if pe + 94 > len(hello) or hello[pe:pe + 4] != b'PE\0\0' or struct.unpack_from('<H', hello, pe + 4)[0] != 0xAA64 or struct.unpack_from('<H', hello, pe + 92)[0] != 10:
        raise VolumeError('HelloPayload must be an AArch64 PE EFI application')
    if len(hello) + len(config) > VOLUME_BYTES * 0.9:
        raise VolumeError('EFI fixture exceeds the 4 MiB FAT volume capacity')
    programs = {}
    for name in ('mformat', 'mcopy', 'mdir'):
        programs[name] = shutil.which(name)
        if not programs[name]:
            raise VolumeError(f'{name} missing; install mtools on the build host')
    env = dict(os.environ, MTOOLS_SKIP_CHECK='1', TZ='UTC', SOURCE_DATE_EPOCH=str(EPOCH))
    commands = []

    def run(name, *args, check=True):
        command = [programs[name], *map(str, args)]
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        commands.append({'tool': name, 'args': list(map(str, args)), 'returncode': result.returncode})
        if check and result.returncode:
            raise VolumeError(f'{name} failed: {result.stderr.strip() or result.stdout.strip()}')
        return result

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sheng-uefi-menu-') as scratch_name:
        scratch = Path(scratch_name)
        stage = scratch / 'stage'
        for relative, content in ((CONFIG_PATH, config), (HELLO_PATH, hello)):
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        for path in [*stage.rglob('*'), stage]:
            os.utime(path, (EPOCH, EPOCH))
        candidate = scratch / 'menu.img'
        run('mformat', '-C', '-T', VOLUME_BYTES // 512, '-h', 2, '-s', 32, '-c', 1,
            '-v', 'SHENGMENU', '-N', '53484e47', '-i', candidate, '::')
        run('mcopy', '-i', candidate, '-s', '-Q', '-m', stage / 'EFI', '::/')
        geometry = _normalize_directory_times(candidate)
        listing = run('mdir', '-i', candidate, '-/', '::/').stdout
        files = {}
        for index, (relative, expected) in enumerate(((CONFIG_PATH, config), (HELLO_PATH, hello))):
            extracted = scratch / f'readback-{index}'
            run('mcopy', '-i', candidate, f'::/{relative}', extracted)
            actual = extracted.read_bytes()
            if actual != expected:
                raise VolumeError(f'FAT file did not read back byte for byte: {relative}')
            files[relative] = {'bytes': len(actual), 'sha256': sha256(actual)}
        if run('mdir', '-i', candidate, f'::/{MISSING_PATH}', check=False).returncode == 0:
            raise VolumeError('the expected missing-file fixture is present')
        payload = candidate.read_bytes()
        report = {'schema_version': 1, 'kind': 'sheng-uefi-menu-volume', 'build_id': build_id,
                  'bytes': len(payload), 'sha256': sha256(payload), 'geometry': geometry,
                  'files': files, 'config_sha256': sha256(config), 'hello_efi_sha256': sha256(hello),
                  'template_sha256': sha256(TEMPLATE.read_bytes()), 'fixed_mtime_epoch': EPOCH,
                  'expected_missing_file': MISSING_PATH, 'all_entries_require_confirmation': True,
                  'readback_verified': True, 'directory_listing': listing, 'commands': commands,
                  'hardware_tested': False, 'mount_commands_executed': False}
        # Exclusive creation never overwrites an existing artifact.
        with output.open('xb') as stream:
            stream.write(payload)
        with report_path.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(report, stream, indent=2)
            stream.write('\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hello-efi', type=Path, required=True)
    parser.add_argument('--build-id', required=True)
    parser.add_argument('--output', type=Path, required=True, help='fresh .img path; creates an adjacent .json report')
    args = parser.parse_args()
    try:
        report = build_volume(args.hello_efi, args.build_id, args.output)
    except (VolumeError, OSError, ValueError) as error:
        print(f'UEFI menu volume: {error}', file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
