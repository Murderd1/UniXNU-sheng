#!/usr/bin/env python3
"""Repack a qualified full package as a manually selected v4 RAM boot trial.

The existing complete kernel, ADT, firmware and runtime sidecars stay intact.
Only the FAT configuration and Android header change. Persistent Data and
native UFS log/export writes are disabled; the install entry is removed.
No device commands or image mounts are performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import tomllib
import zlib


AUDITED_REVISIONS = {
    'package:device': '52d7600a6b5de83e4869e5496d4f23d4915d8e11',
    'package:main': 'd830d23b0d19c9322d906c21afeca1d6c54aeffe',
    'driver:ShengUfs': 'b11de87c234cf4b8f80a8160fb15e6f37a8e5d0c',
    'driver:RamBlock': '60a54ce8f86161db958fd8e6edf577081b3c9ae7',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Fat32:
    def __init__(self, data):
        self.data = bytearray(data)
        self.bps, self.spc, self.reserved, self.fats, roots, sectors16, _, sectors_fat16 = struct.unpack_from('<HBHBHHBH', data, 11)
        self.total, self.fat_sectors = struct.unpack_from('<II', data, 32)
        self.root = struct.unpack_from('<I', data, 44)[0]
        if (self.bps != 512 or not self.spc or self.spc & (self.spc - 1)
                or not self.fats or roots or sectors16 or sectors_fat16
                or data[510:512] != b'\x55\xaa' or self.total * self.bps != len(data)):
            raise ValueError('Expected a whole-volume FAT32 image')
        self.data_sector = self.reserved + self.fats * self.fat_sectors
        self.clusters = (self.total - self.data_sector) // self.spc
        self.cluster_bytes = self.bps * self.spc
        self.fat = memoryview(self.data)[self.reserved * self.bps:(self.reserved + self.fat_sectors) * self.bps]
        for index in range(1, self.fats):
            start = (self.reserved + index * self.fat_sectors) * self.bps
            if self.data[start:start + len(self.fat)] != self.fat:
                raise ValueError('FAT copies differ')

    def chain(self, cluster):
        visited = set()
        while cluster < 0x0ffffff8:
            if not 2 <= cluster < self.clusters + 2 or cluster in visited:
                raise ValueError('Invalid or cyclic FAT chain')
            visited.add(cluster)
            yield (self.data_sector + (cluster - 2) * self.spc) * self.bps
            cluster = struct.unpack_from('<I', self.fat, cluster * 4)[0] & 0x0fffffff

    def entries(self, cluster):
        long_name = []
        for start in self.chain(cluster):
            for offset in range(start, start + self.cluster_bytes, 32):
                entry = self.data[offset:offset + 32]
                if not entry[0]:
                    return
                if entry[0] == 0xe5:
                    long_name = []
                    continue
                if entry[11] == 0x0f:
                    text = entry[1:11] + entry[14:26] + entry[28:32]
                    long_name.insert(0, text)
                    continue
                short = entry[:8].decode('ascii').rstrip()
                ext = entry[8:11].decode('ascii').rstrip()
                name = (short + ('.' + ext if ext else ''))
                if long_name:
                    name = b''.join(long_name).decode('utf-16le').split('\0')[0].rstrip('\uffff')
                long_name = []
                if entry[11] & 8 or name in ('.', '..'):
                    continue
                child = (struct.unpack_from('<H', entry, 20)[0] << 16) | struct.unpack_from('<H', entry, 26)[0]
                yield name, offset, child, struct.unpack_from('<I', entry, 28)[0], bool(entry[11] & 16)

    def files(self):
        result = {}
        seen = set()

        def walk(cluster, prefix):
            if cluster in seen:
                raise ValueError('Repeated directory chain')
            seen.add(cluster)
            for name, offset, child, size, directory in self.entries(cluster):
                path = prefix + name
                if directory:
                    walk(child, path + '/')
                else:
                    result[path] = (offset, child, size)
        walk(self.root, '')
        return result

    def read(self, entry):
        _, child, size = entry
        content = b''.join(self.data[start:start + self.cluster_bytes] for start in self.chain(child))
        if len(content) < size:
            raise ValueError('File ends before its size')
        return content[:size]

    def replace_smaller(self, entry, content):
        offset, child, size = entry
        if len(content) > size:
            raise ValueError('New config exceeds its existing allocation')
        padded = content + bytes(size - len(content))
        for index, start in enumerate(self.chain(child)):
            chunk = padded[index * self.cluster_bytes:(index + 1) * self.cluster_bytes]
            self.data[start:start + len(chunk)] = chunk
        struct.pack_into('<I', self.data, offset + 28, len(content))


def repack(source, output):
    if output.exists():
        raise ValueError('Choose a fresh output directory')
    manifest = json.loads((source / 'package.manifest.json').read_text())
    if manifest.get('os_profile') != 'ipados-27.0.1-24A446':
        raise ValueError('This trial is qualified only for the audited iPadOS 27 package')
    for name, expected in AUDITED_REVISIONS.items():
        if manifest.get('revisions', {}).get(name) != expected:
            raise ValueError('Persistent-write gates were not audited for ' + name)
    inputs = {'boot.img': source / 'boot/boot.img', 'kernel.macho': source / 'kernel/kernel.macho',
              'payload.img': source / 'payload/payload.img'}
    blobs = {name: path.read_bytes() for name, path in inputs.items()}
    for name, blob in blobs.items():
        expected = manifest['outputs'][name]
        if len(blob) != expected['bytes'] or sha(blob) != expected['sha256']:
            raise ValueError('Package input mismatch: ' + name)
    boot = blobs['boot.img']
    fields = struct.unpack_from('<10I', boot, 8)
    kernel_size, _, ramdisk_size, _, second_size, _, _, page, version, os_version = fields
    if boot[:8] != b'ANDROID!' or version != 0 or page != 4096 or second_size:
        raise ValueError('Expected the original v0/4096 package')
    ramdisk_start = page + (kernel_size + page - 1) // page * page
    if boot[ramdisk_start:ramdisk_start + ramdisk_size] != blobs['payload.img']:
        raise ValueError('Boot ramdisk and package payload differ')
    compressed = boot[page:page + kernel_size]
    decoder = zlib.decompressobj(31)
    firmware = decoder.decompress(compressed)
    if not decoder.eof or firmware[56:60] != b'ARM\x64' or decoder.unused_data[:4] != b'\xd0\x0d\xfe\xed':
        raise ValueError('Expected ARM64 BootShim/FD gzip followed by FDT')
    fat = Fat32(blobs['payload.img'])
    files = fat.files()
    config_path = next(name for name in files if name.lower() == 'efi/unixnu/unixnu.toml')
    old_config = fat.read(files[config_path])
    config = tomllib.loads(old_config.decode())
    entry = next(value for value in config['entry'] if value['id'] == 'xnu')
    if entry['type'] != 'xnu' or entry['path'] != 'Payloads/kernel.macho':
        raise ValueError('Unexpected full-kernel entry')
    args = entry['args'].split()
    changes = {'data-persist': '0', 'log': '0'}
    for key in changes:
        if sum(token.split('=')[0] == key for token in args) != 1:
            raise ValueError('Expected exactly one explicit ' + key + ' argument')
    args = [token.split('=')[0] + '=' + changes[token.split('=')[0]]
            if token.split('=')[0] in changes else token for token in args
            if token.split('=')[0] not in ('data-reset', 'autoreset')]
    build_id = 'sheng-full-v4-' + manifest['revisions']['package:device'][:12]
    text = ('version = 1\n[boot]\ntimeout = -1\nrotate = 0\ndefault = "xnu"\n'
            '[ui]\ntitle = ' + json.dumps('Sheng Full Trial - ' + build_id) + '\n'
            '[kits]\nautoload = false\n')
    for driver in config.get('driver', []):
        text += '[[driver]]\npath = ' + json.dumps(driver['path']) + '\n'
    text += ('[[entry]]\nid = "xnu"\ntitle = "Boot full XNU (Data/log writes off)"\n'
             'confirm = "Start the full kernel trial?"\ntype = "xnu"\npath = "Payloads/kernel.macho"\n')
    if entry.get('initrd'):
        text += 'initrd = ' + json.dumps(entry['initrd']) + '\n'
    text += 'args = ' + json.dumps(' '.join(args)) + '\n'
    text += ('[[entry]]\nid = "shutdown"\ntitle = "Power off"\n'
             'confirm = "Power off?"\ntype = "action"\naction = "shutdown"\n')
    new_config = text.encode('ascii')
    parsed = tomllib.loads(text)
    if len(parsed['entry']) != 2 or any(not item.get('confirm') for item in parsed['entry']):
        raise ValueError('Every trial entry must require confirmation')
    before = {name: sha(fat.read(value)) for name, value in files.items()}
    fat.replace_smaller(files[config_path], new_config)
    modified = bytes(fat.data)
    check = Fat32(modified)
    checked_files = check.files()
    after = {name: sha(check.read(value)) for name, value in checked_files.items()}
    if set(before) != set(after) or [name for name in before if before[name] != after[name]] != [config_path]:
        raise ValueError('A payload file other than config changed')
    if check.read(checked_files[config_path]) != new_config:
        raise ValueError('Config readback differs')
    header = bytearray(4096)
    header[:8] = b'ANDROID!'
    struct.pack_into('<4I', header, 8, kernel_size, ramdisk_size, os_version, 1584)
    struct.pack_into('<I', header, 40, 4)
    cmdline = boot[64:576].split(b'\0')[0] + boot[608:1632].split(b'\0')[0]
    if len(cmdline) >= 1536:
        raise ValueError('Android command line too long')
    header[44:44 + len(cmdline)] = cmdline
    image = bytearray(boot)
    image[:4096] = header  # v4 unsigned image: signature_size is zero.
    image[ramdisk_start:ramdisk_start + ramdisk_size] = modified
    if image[page:page + kernel_size] != compressed:
        raise ValueError('Firmware/DTB kernel field changed')
    output.mkdir(parents=True)
    (output / 'boot.img').write_bytes(image)
    (output / 'unixnu.toml').write_bytes(new_config)
    (output / 'original-unixnu.toml').write_bytes(old_config)
    report = {'kind': 'sheng-full-v4-trial', 'build_id': build_id, 'hardware_tested': False,
              'source_package': str(source.resolve()), 'source_revisions': manifest['revisions'],
              'inputs': {name: {'bytes': len(blob), 'sha256': sha(blob)} for name, blob in blobs.items()},
              'header_version': 4, 'signature_bytes': 0, 'kernel_field_unchanged': True,
              'complete_kernel_and_all_sidecars_unchanged': True, 'payload_files': after,
              'only_changed_payload_file': config_path, 'kernel_args': ' '.join(args),
              'data_persistence': 0, 'native_ufs_log_and_export': 0,
              'install_entry_present': False, 'all_entries_require_confirmation': True,
              'ramdisk_bytes': ramdisk_size, 'ramdisk_sha256': sha(modified),
              'image_bytes': len(image), 'image_sha256': sha(image),
              'firmware_field_sha256': sha(compressed), 'decompressed_firmware_bytes': len(firmware)}
    (output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    (output / 'SHA256SUMS').write_text(''.join(sha((output / name).read_bytes()) + '  ' + name + '\n'
                                             for name in ('boot.img', 'unixnu.toml', 'original-unixnu.toml', 'manifest.json')))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-package', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    repack(args.source_package, args.output)
