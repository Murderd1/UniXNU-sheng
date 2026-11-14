"""Isolated integration for an existing complete XNU package and RAM transport."""
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


def handoff_inputs(report, root_readonly_probe=False):
    result = dict(report)
    result['kernel_args_origin'] = 'Source FAT configuration after the audited repack; not necessarily the effective loader handoff.'
    arguments = report['kernel_args']
    if root_readonly_probe:
        arguments += ' native-ufs-probe=10'
        if arguments != root_readonly_args():
            raise ValueError('Root-readonly source arguments differ from the exact Stage 3 baseline plus probe 10')
    result['effective_handoff_args'] = arguments
    result['trial_mode'] = 'root-readonly-probe' if root_readonly_probe else 'full-kernel'
    return result


def render_app_config(inputs):
    return ('#define SHENG_FULL_TRIAL_ARGS L' + json.dumps(inputs['effective_handoff_args']) + '\n'
            '#define SHENG_FULL_TRIAL_ROOT_READONLY ' + str(int(inputs['trial_mode'] == 'root-readonly-probe')) + '\n'
            '#define SHENG_FULL_TRIAL_RAMDISK_BYTES ' + str(inputs['seed_bytes']) + 'ULL\n')


def prepare(source, output, root_readonly_probe=False):
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
    # The mode changes only the generated app handoff, never the FAT bytes.
    report = handoff_inputs(report, root_readonly_probe)
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
