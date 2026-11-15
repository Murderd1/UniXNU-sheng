"""Isolated integration for an existing complete XNU package and RAM transport."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import tomllib


ROOT = Path(__file__).resolve().parents[1]
DARWIN_COMMIT = '8544957e04bdc43e2aac9243764ac16979f15c42'
APP_INF = 'UefiKernelProbe/ShengKernelProbe.inf'
DISK_INF = 'UefiKernelDisk/ShengKernelDiskDxe.inf'
SHARED_DISK_INF = 'UniXNUPkg/Driver/UniXNURamDiskDxe/UniXNURamDiskDxe.inf'


def root_readonly_args():
    header = (ROOT / 'package/UefiKernelProbe/ShengRootReadonlyArgs.h').read_text(encoding='utf-8')
    match = re.search(r'^#define SHENG_ROOT_READONLY_ARGS L("[^\n]+")$', header, re.MULTILINE)
    if match is None:
        raise ValueError('Missing canonical root-readonly argument whitelist')
    return json.loads(match[1])


def full_root_args():
    """The exact successful full handoff, without the diagnostic probe suffix."""
    suffix = ' native-ufs-probe=10'
    diagnostic = root_readonly_args()
    if not diagnostic.endswith(suffix):
        raise ValueError('Canonical root diagnostic must end with probe 10')
    arguments = diagnostic[:-len(suffix)]
    if (len(arguments) != 775 or hashlib.sha256(arguments.encode('ascii')).hexdigest() !=
            '452563097518e626be38881b9da8e47b68fb5161608cddfe91088b1691811a03'):
        raise ValueError('Full-root trial requires the exact successful 775-byte Stage 3 baseline')
    return arguments


def root_media_args():
    """The complete Stage 3 handoff with only the media-report probe appended."""
    arguments = full_root_args() + ' native-ufs-probe=12'
    header = (ROOT / 'package/UefiKernelProbe/ShengRootMediaArgs.h').read_text(encoding='utf-8')
    match = re.search(r'^#define SHENG_ROOT_MEDIA_ARGS L("[^\n]+")$', header, re.MULTILINE)
    if (match is None or json.loads(match[1]) != arguments or len(arguments) != 795 or
            hashlib.sha256(arguments.encode('ascii')).hexdigest() !=
            '0e29632941bb5a79b4af422526f0689a874584b38d4c5fed506af74c9a31abfa'):
        raise ValueError('Root-media probe requires the exact Stage 3 baseline plus probe 12')
    return arguments


def root_state_args():
    arguments = full_root_args() + ' native-ufs-probe=13 native-ufs-stats-delay=30'
    header = (ROOT / 'package/UefiKernelProbe/ShengRootStateArgs.h').read_text(encoding='utf-8')
    match = re.search(r'^#define SHENG_ROOT_STATE_ARGS L("[^\n]+")$', header, re.MULTILINE)
    if (match is None or json.loads(match[1]) != arguments or len(arguments) != 821 or
            hashlib.sha256(arguments.encode('ascii')).hexdigest() !=
            '6ed5ed7278c0bb48b31555341c66c7465e40f8313be59fd1e5b331ce7ea85b10'):
        raise ValueError('Root-state probe requires the exact baseline plus probe 13 and delay 30')
    return arguments


def trial_mode(root_readonly_probe=False, full_root_trial=False, root_media_probe=False, root_state_probe=False):
    if sum(map(bool, (root_readonly_probe, full_root_trial, root_media_probe, root_state_probe))) > 1:
        raise ValueError('Root diagnostic and full-root trial modes are mutually exclusive')
    return ('root-state-probe' if root_state_probe else 'root-media-probe' if root_media_probe else 'full-root-trial' if full_root_trial else
            'root-readonly-probe' if root_readonly_probe else 'full-kernel')


def handoff_inputs(report, root_readonly_probe=False, full_root_trial=False, root_media_probe=False, root_state_probe=False):
    mode = trial_mode(root_readonly_probe, full_root_trial, root_media_probe, root_state_probe)
    result = dict(report)
    result['kernel_args_origin'] = 'Source FAT configuration after the audited repack; not necessarily the effective loader handoff.'
    arguments = report['kernel_args']
    if root_state_probe:
        arguments += ' native-ufs-probe=13 native-ufs-stats-delay=30'
        if arguments != root_state_args():
            raise ValueError('Root-state source arguments differ from the exact baseline and diagnostic suffix')
    elif root_media_probe:
        arguments += ' native-ufs-probe=12'
        if arguments != root_media_args():
            raise ValueError('Root-media source arguments differ from the exact Stage 3 baseline plus probe 12')
    elif root_readonly_probe:
        arguments += ' native-ufs-probe=10'
        if arguments != root_readonly_args():
            raise ValueError('Root-readonly source arguments differ from the exact Stage 3 baseline plus probe 10')
    elif full_root_trial and arguments != full_root_args():
        raise ValueError('Full-root source arguments differ from the exact Stage 3 baseline')
    result['effective_handoff_args'] = arguments
    result['trial_mode'] = mode
    return result


def render_app_config(inputs):
    return ('#define SHENG_FULL_TRIAL_ARGS L' + json.dumps(inputs['effective_handoff_args']) + '\n'
            '#define SHENG_FULL_TRIAL_ROOT_READONLY ' + str(int(inputs['trial_mode'] == 'root-readonly-probe')) + '\n'
            '#define SHENG_FULL_TRIAL_ROOT_MEDIA ' + str(int(inputs['trial_mode'] == 'root-media-probe')) + '\n'
            '#define SHENG_FULL_TRIAL_ROOT_STATE ' + str(int(inputs['trial_mode'] == 'root-state-probe')) + '\n'
            '#define SHENG_FULL_TRIAL_RAMDISK_BYTES ' + str(inputs['seed_bytes']) + 'ULL\n')


def patch_root_state_volume(payload, fat_module, workdir):
    """Replace only the same-size actual FAT kernel; fail closed on any other byte change."""
    if fat_module.sha(payload) != 'f46ba1674303a37e89dd0e8ad24fe54ed43cd63c7dd29001216b87f36634ed68':
        raise ValueError('Root-state probe requires the frozen Stage 3 FAT')
    spec = importlib.util.spec_from_file_location('root_state_kernel_patch', ROOT / 'scripts/patch-sheng-root-state.py')
    patch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patch)
    disk = fat_module.Fat32(payload)
    entries = disk.files()
    kernel_name = 'EFI/UniXNU/Payloads/kernel.macho'
    unchanged_files = {name: bytes(disk.read(entry)) for name, entry in entries.items() if name != kernel_name}
    original = disk.read(entries[kernel_name])
    changed, report = patch.patch_kernel(bytes(original), workdir)
    if (len(changed) != len(original) or changed == original or
            report['input_sha256'] != fat_module.sha(original) or report['output_sha256'] != fat_module.sha(changed)):
        raise ValueError('Root-state diagnostic must change the kernel without changing its length')
    disk.replace_smaller(entries[kernel_name], changed)
    updated = bytes(disk.data)
    checked = fat_module.Fat32(updated)
    after_entries = checked.files()
    if entries != after_entries or len(updated) != len(payload):
        raise ValueError('Root-state patch changed FAT metadata or length')
    for name, entry in entries.items():
        expected = changed if name == kernel_name else unchanged_files[name]
        if checked.read(after_entries[name]) != expected:
            raise ValueError('Root-state FAT readback differs: ' + name)
    clusters = list(disk.chain(entries[kernel_name][1]))
    ranges = []
    for offset, length in ((report['cave']['file_offset'], report['cave']['bytes']),
                           (report['entry_patch']['file_offset'], 4)):
        while length:
            index, relative = divmod(offset, disk.cluster_bytes)
            count = min(length, disk.cluster_bytes - relative)
            ranges.append((clusters[index] + relative, count))
            offset += count
            length -= count
    previous = 0
    for offset, count in sorted(ranges):
        if offset < previous or payload[previous:offset] != updated[previous:offset]:
            raise ValueError('Root-state patch changed bytes outside its two permitted kernel ranges')
        previous = offset + count
    if payload[previous:] != updated[previous:]:
        raise ValueError('Root-state patch changed the FAT suffix')
    report['all_other_fat_files_byte_identical'] = True
    report['all_fat_directory_entries_identical'] = True
    report['all_volume_bytes_outside_kernel_patch_identical'] = True
    report['allowed_changed_volume_ranges'] = [dict(offset=offset, bytes=count) for offset, count in sorted(ranges)]
    return updated, report


def prepare(source, output, root_readonly_probe=False, full_root_trial=False, root_media_probe=False, root_state_probe=False):
    # Validate arguments and mode before repacking or compiling a diagnostic.
    trial_mode(root_readonly_probe, full_root_trial, root_media_probe, root_state_probe)
    spec = importlib.util.spec_from_file_location('full_repack', ROOT / 'scripts/repack-sheng-full-trial.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    repacked = output / 'work/full-input'
    module.repack(source, repacked)
    report = json.loads((repacked / 'manifest.json').read_text())
    image = (repacked / 'boot.img').read_bytes()
    kernel_bytes, size = struct.unpack_from('<II', image, 8)
    start = 4096 + ((kernel_bytes + 4095) // 4096) * 4096
    payload = image[start:start + size]
    if root_state_probe:
        original_payload_sha = module.sha(payload)
        payload, kernel_patch = patch_root_state_volume(payload, module, output / 'logs/root-state-patch')
        report['diagnostic_kernel_changed'] = True
        report['original_kernel_sha256'] = kernel_patch['input_sha256']
        report['diagnostic_kernel_sha256'] = kernel_patch['output_sha256']
        report['root_state_kernel_patch'] = kernel_patch
        report['root_state_patch_artifacts'] = 'logs/root-state-patch'
        report['original_volume_sha256'] = original_payload_sha
        report['complete_kernel_and_all_sidecars_unchanged'] = False
        report['all_sidecars_unchanged'] = True
        report['only_changed_payload_files'] = [report.pop('only_changed_payload_file'), 'EFI/UniXNU/Payloads/kernel.macho']
        report['image_sha256_scope'] = 'Original intermediate repack before the root-state diagnostic; final FAT hash is volume_sha256.'
        report['ramdisk_sha256'] = module.sha(payload)
        report['payload_files']['EFI/UniXNU/Payloads/kernel.macho'] = kernel_patch['output_sha256']
    path = output / 'full-volume.img'
    path.write_bytes(payload)
    disk = module.Fat32(payload)
    files = disk.files()
    seed_entry = files['EFI/UniXNU/Payloads/scratch-data.img']
    report['seed_bytes'] = seed_entry[2]
    report['volume_bytes'] = size
    report['volume_sha256'] = module.sha(payload)
    report['boot_sector_sha256'] = module.sha(payload[:512])
    report['boot_prefix_hex'] = payload[:16].hex()
    # Existing modes change only the handoff; root-state also changes its guarded kernel ranges.
    report = handoff_inputs(report, root_readonly_probe, full_root_trial, root_media_probe, root_state_probe)
    (output / 'full-trial-inputs.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def byte_list(hex_string):
    return ', '.join('0x' + hex_string[index:index + 2] for index in range(0, len(hex_string), 2))


def integrate(builder, uefi, tree, build_id, inputs):
    changed = builder.integrate_probe(uefi, tree, ROOT / 'package/UefiProbe', build_id)
    for name in ('UefiKernelDisk', 'UefiKernelProbe'):
        shutil.copytree(ROOT / 'package' / name, tree / 'package' / name)
    app = tree / 'package/UefiKernelProbe'
    builder.replace_once(app / 'ShengKernelProbe.inf',
                         '9AE357D9-4CF7-4866-8351-9779B750DC14', builder.APP_GUID)
    builder.replace_once(app / 'ShengKernelProbe.c',
                         '#define SHENG_KERNEL_PROBE_BUILD_ID "unversioned"',
                         '#define SHENG_KERNEL_PROBE_BUILD_ID ' + json.dumps(build_id))
    (app / 'ShengFullTrialConfig.h').write_text(render_app_config(inputs))
    expected = tree / 'package/UefiKernelDisk/KernelDiskExpected.h'
    expected.write_text(
        '#define SHENG_KERNEL_DISK_EXPECTED_BYTES ' + str(inputs['volume_bytes']) + 'ULL\n'
        '#define SHENG_KERNEL_DISK_EXPECTED_SHA256 { ' + byte_list(inputs['volume_sha256']) + ' }\n'
        '#define SHENG_KERNEL_DISK_BOOT_SECTOR_SHA256 { ' + byte_list(inputs['boot_sector_sha256']) + ' }\n'
        '#define SHENG_KERNEL_DISK_BOOT_PREFIX { ' + byte_list(inputs['boot_prefix_hex']) + ' }\n')
    for relative in (builder.PLATFORM / 'sheng.dsc', builder.PLATFORM / 'sheng.fdf'):
        builder.replace_once(uefi / relative, builder.PROBE_APP, APP_INF)
    dsc = uefi / builder.PLATFORM / 'sheng.dsc'
    with dsc.open('a') as stream:
        stream.write('\n[Components]\n  ' + builder.DARWIN_INF + '\n')
    include = uefi / builder.PLATFORM / 'Include/DXE.inc'
    with include.open('a') as stream:
        stream.write('\n  INF ' + builder.DARWIN_INF + '\n')
    for path in (dsc, include):
        builder.replace_once(path, SHARED_DISK_INF, DISK_INF)
    secure = Path('Silicon/Silicium/SiliciumPkg/Library/BootManagerLib/BootManager.c')
    builder.replace_once(uefi / secure,
                         'PlatformBootManagerBdsEntry ()\n{\n  EFI_STATUS Status;',
                         'PlatformBootManagerBdsEntry ()\n{')
    builder.replace_once(uefi / secure,
                         '  // Setup Secure Boot\n  Status = SetupSecureBoot ();\n  ASSERT_EFI_ERROR (Status);',
                         '  // Isolated RAM trial: skip key enrollment and filesystem callbacks.\n'
                         '  DEBUG ((DEBUG_WARN, "SHENGFULL: isolated RAM trial policy\\n"));')
    sec = uefi / builder.SEC_SOURCE
    reserve = sec.with_name('ShengKernelReserve.h')
    shutil.copy2(ROOT / 'package/UefiKernelDisk/ShengKernelReserve.h', reserve)
    builder.replace_once(sec, '#include "Sec.h"',
                         '#include "Sec.h"\n#include "ShengKernelReserve.h"')
    builder.replace_once(sec, '  CheckHobList ();\n\n  // Run Library Cconstructors',
                         '  ShengKernelReserveEntry (gSecEntryArg0);\n\n  CheckHobList ();\n\n  // Run Library Cconstructors')
    changed += [str(secure), str(builder.PLATFORM / 'Include/DXE.inc'),
                str(builder.SEC_SOURCE.with_name('ShengKernelReserve.h'))]
    changed += ['tree/' + str(path.relative_to(tree)) for name in ('UefiKernelDisk', 'UefiKernelProbe')
                for path in sorted((tree / 'package' / name).glob('*')) if path.is_file()]
    return list(dict.fromkeys(changed))
