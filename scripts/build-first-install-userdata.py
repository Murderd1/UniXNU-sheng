#!/usr/bin/env python3
"""Build sheng's first-install userdata with the existing signed root policies.

Uses the pinned UniXNU userdata builder. Reconstructs ordered hash tables from
the unchanged OS windows, verifies their existing signatures and signed hashes,
and includes them as OS.vroot and SystemOS.vroot. No signing key is needed.
The final Android sparse image explicitly zeros the remainder of userdata.
This script writes host files only; it never accesses or flashes a tablet.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import uuid

DEVICE = Path(__file__).resolve().parents[1]
HEADER = struct.Struct('<8s4I2Q16s32s32s32sQ')
CHUNK = 8 << 20


def require(condition, message):
    if not condition:
        raise ValueError(message)


def der(tag, data):
    length = len(data)
    encoded = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + (bytes([length]) if length < 128 else bytes([128 + len(encoded)]) + encoded) + data


def verify_policy(envelope, anchor):
    require(len(envelope) == 544 and len(anchor) == 395, 'Invalid signed policy size')
    require(anchor[:8] == b'VROOTKEY' and anchor[-3:] == b'\x01\x00\x01', 'Invalid root key format')
    fields = HEADER.unpack(envelope[:160])
    magic, version, header_size, block_size, flags, size, count, _, _, _, key_hash, generation = fields
    require((magic, version, header_size, block_size, flags) == (b'VROOT01\0', 1, 160, 4096, 0), 'Invalid root header')
    require(size > 0 and count == (size + 4095) // 4096 and generation > 0, 'Invalid root dimensions')
    require(hashlib.sha256(anchor).digest() == key_hash, 'Trusted key hash mismatch')
    modulus = anchor[8:392]
    require(modulus[0] & 128 and modulus[-1] & 1, 'Invalid RSA3072 modulus')
    key = der(0x30, der(2, b'\0' + modulus) + der(2, anchor[-3:]))
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        (temp / 'key.der').write_bytes(key)
        (temp / 'header').write_bytes(envelope[:160])
        (temp / 'signature').write_bytes(envelope[160:])
        result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(temp / 'key.der'),
                                 '-keyform', 'DER', '-signature', str(temp / 'signature'), str(temp / 'header')],
                                capture_output=True, text=True)
        require(result.returncode == 0, 'Root policy signature verification failed')
    return fields


def restore_manifest(source, window, envelope, anchor, destination, expected_hash, expected_uuid):
    fields = verify_policy(envelope, anchor)
    size, count, volume, image_hash, table_hash = fields[5:10]
    require(size == window['size'], 'Signed image size differs from userdata window')
    require(image_hash.hex() == expected_hash == window['sha256'], 'OS profile/window hash differs from signed policy')
    require(volume == uuid.UUID(expected_uuid).bytes, 'OS profile UUID differs from signed policy')
    temporary = destination.with_suffix('.partial')
    temporary.unlink(missing_ok=True)
    image_digest, table_digest = hashlib.sha256(), hashlib.sha256()
    try:
        source.seek(window['offset'])
        remaining, blocks = size, 0
        with temporary.open('wb') as output:
            output.write(envelope)
            while remaining:
                data = source.read(min(CHUNK, remaining))
                require(len(data) == min(CHUNK, remaining), 'Short userdata window')
                image_digest.update(data)
                hashes = b''.join(hashlib.sha256(data[at:at + 4096]).digest() for at in range(0, len(data), 4096))
                output.write(hashes)
                table_digest.update(hashes)
                blocks += (len(data) + 4095) // 4096
                remaining -= len(data)
        require(blocks == count and image_digest.digest() == image_hash, 'Raw OS image hash mismatch')
        require(table_digest.digest() == table_hash, 'Reconstructed block table hash mismatch')
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def sparse_image(raw, destination, partition_bytes):
    spec = importlib.util.spec_from_file_location('sheng_sparse', DEVICE / 'scripts/make-userdata-full.py')
    sparse = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sparse)
    size = raw.stat().st_size
    require(size <= partition_bytes and size % 4096 == partition_bytes % 4096 == 0, 'Invalid sparse image dimensions')
    temporary = destination.with_suffix('.partial')
    writer = sparse.Writer(temporary, partition_bytes // 4096)
    try:
        with raw.open('rb') as source:
            while data := source.read(CHUNK):
                writer.data(data)
        writer.zeros((partition_bytes - size) // 4096)
        writer.close()
        temporary.replace(destination)
    finally:
        writer.out.close()
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unixnu', required=True, type=Path)
    args = parser.parse_args()
    main_repo = args.unixnu.resolve()
    sys.path.insert(0, str(main_repo / 'scripts'))
    from unixnu.cli import parser as build_parser
    from unixnu.config import Context
    from unixnu import userdata
    from unixnu.util import sha256_file

    options = build_parser().parse_args(['build', 'userdata', '-D', str(DEVICE), '--os', '27'])
    ctx = Context(options)
    profile = ctx.board['board']['os_profile']
    require(profile == 'ipados-27.0.1-24A446', 'Only the reviewed iPadOS 27 profile is supported')
    raw = userdata.build(ctx)
    out, _, report = userdata.paths(ctx)
    initial = json.loads(report.read_text())
    require([w['name'] for w in initial['windows']] == ['OS', 'SystemOS'], 'Unexpected root windows')
    policy_dir = DEVICE / 'scripts/policies' / profile
    with raw.open('rb') as source:
        for window in initial['windows']:
            name = window['name']
            policy = policy_dir / name
            manifest = out / (name + '.vroot')
            prefix = name.lower()
            restore_manifest(source, window, (policy / 'manifest.header.bin').read_bytes(),
                             (policy / 'trusted-key.bin').read_bytes(), manifest,
                             ctx.board['root'][prefix + '_image_sha256'], ctx.board['root'][prefix + '_volume_uuid'])
            options.object.append(name + '.vroot=' + str(manifest))
            print(f'{name}: existing signature, original image and restored block table verified', flush=True)
    raw = userdata.build(ctx)
    final = json.loads(report.read_text())
    destination = out / 'userdata-first-install.img'
    sparse_image(raw, destination, final['userdata_bytes'])
    record = {'profile': profile, 'format': 'android-sparse-v1', 'file': destination.name,
              'device_revision': subprocess.check_output(['git', '-C', str(DEVICE), 'rev-parse', 'HEAD'], text=True).strip(),
              'unixnu_revision': subprocess.check_output(['git', '-C', str(main_repo), 'rev-parse', 'HEAD'], text=True).strip(),
              'bytes': destination.stat().st_size, 'sha256': sha256_file(destination),
              'expanded_bytes': final['userdata_bytes'], 'geometry': ctx.board['userdata'],
              'root_manifest_sha256': final['manifest_sha256'],
              'signed_root_tables_restored': True, 'remaining_userdata_explicitly_zeroed': True,
              'hardware_tested': False, 'destructive_on_flash': True,
              'required_before_flash': 'Read the target GPT and boot partition sizes; back up Android data and boot images.'}
    (out / 'first-install.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
