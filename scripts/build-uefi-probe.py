#!/usr/bin/env python3
"""Build a standalone sheng DEBUG firmware probe in a fresh, isolated tree.

This entry point never invokes the OS resolver, kernel, payload or Data-seed
builders. It does not connect to a device. Stock inputs use board.toml pins.
macOS is required for the existing pinned vendor-module importer.
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
TOOLS_COMMIT = 'd830d23b0d19c9322d906c21afeca1d6c54aeffe'
UEFI_COMMIT = '66421cb7bb5694843aec8de1ca3d1de4c20cca38'
EDK2_COMMIT = 'cfb93724a06ff86ff5ba971413368a7809ee42a5'
APP_GUID = '9B665204-A133-47A2-9396-9E2B370A4E25'
PROBE_BOOT_IMAGE = {'header_version': 4, 'pagesize': 4096}
MENU_PAYLOAD_GUID = '79D77DA6-3053-4705-9B3C-18750AE7C3F1'
MENU_DISK_INF = 'UefiMenuDisk/ShengMenuDiskDxe.inf'
HELLO_INF = 'UniXNUPkg/Test/HelloPayload/HelloPayload.inf'
NORMAL_APP = 'UniXNUPkg/Application/UniXNU/UniXNU.inf'
PROBE_APP = 'UniXNUPkg/Application/ShengUefiProbe/ShengUefiProbe.inf'
DARWIN_INF = 'DarwinBootPkg/Driver/DarwinBoot.inf'
PREFLIGHT_SCRIPTS = ('fetch-sheng-dts.py', 'download-sheng-firmware.py',
                     'extract-sheng-firmware.py', 'import-sheng-uefi.py',
                     'check-sheng.py', 'check-sheng-fv.py', 'check-uefi-probe.py')
PLATFORM = Path('Platforms/Xiaomi/shengPkg')
SEC_SOURCE = Path('Silicon/Silicium/SiliciumPkg/Sec/Sec.c')
BDS_SOURCE = Path('Silicon/Qualcomm/QcomPkg/Library/PlatformBootManagerLib/PlatformBootManager.c')
GOP_SOURCE = Path('Silicon/Silicium/SiliciumPkg/Drivers/SimpleFbDxe/SimpleFb.c')
REGISTRATION_SOURCE = Path('package/UniXNUPkg/Driver/UniXNUDxe/UniXNUDxe.c')
EXPECTED_CHECKPOINTS = (
    'SHENGUEFI: SEC_DEBUG_READY', 'SEC: memory HOBs done',
    'SEC: platform HOBs done', 'SEC: FV decompressed', 'SEC: loading DXE core',
    'SHENGUEFI: DXE_REGISTRATION', 'SHENGUEFI: GOP_REGISTER', 'SHENGUEFI: BDS_ENTRY',
    'SHENGUEFI: BDS_BEFORE_CONSOLE', 'SHENGUEFI: BDS_AFTER_CONSOLE',
    'SHENGUEFI: APP_ENTRY', 'SHENGUEFI: GOP_READY', 'SHENGUEFI: MENU_READY',
    'SHENGUEFI: HEARTBEAT', 'SHENGUEFI: INPUT_KEY',
    'SHENGUEFI: HOLD_300_TICKS', 'SHENGUEFI: RUN_CHECKS_MET',
)


class ProbeError(Exception):
    pass


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while blob := stream.read(1024 * 1024):
            value.update(blob)
    return value.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def command(parts, *, cwd=None, log=None, env=None):
    parts = [str(part) for part in parts]
    if log:
        with Path(log).open('a', encoding='utf-8') as stream:
            stream.write('+ ' + ' '.join(parts) + '\n')
            stream.flush()
            result = subprocess.run(parts, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
        if result.returncode:
            raise ProbeError(f'{parts[0]} failed ({result.returncode}); see {log}')
        return ''
    result = subprocess.run(parts, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode:
        raise ProbeError(f'{parts[0]} failed: {result.stderr.strip() or result.stdout.strip()}')
    return result.stdout.strip()


def git(path, *args):
    # Per-command safe.directory supports a shared local workspace without
    # changing the user's global Git configuration.
    return command(['git', '-c', f'safe.directory={Path(path).resolve().as_posix()}', '-C', path, *args])


def require_pin(path, expected):
    if git(path, 'rev-parse', 'HEAD') != expected:
        raise ProbeError(f'{path}: expected pinned commit {expected}')
    if git(path, 'status', '--porcelain', '--untracked-files=no', '--ignore-submodules=all'):
        raise ProbeError(f'{path}: tracked source changes would be discarded; use a clean pinned checkout')


def clone_local(source, destination, expected, log):
    require_pin(source, expected)
    command(['git', 'clone', '--no-hardlinks', '--shared', '--no-checkout', source, destination], log=log)
    command(['git', '-C', destination, 'checkout', '--detach', expected], log=log)


def clone_remote(url, destination, commit, log):
    command(['git', 'init', destination], log=log)
    command(['git', '-C', destination, 'remote', 'add', 'origin', url], log=log)
    command(['git', '-C', destination, 'fetch', '--depth', '1', 'origin', commit], log=log)
    command(['git', '-C', destination, 'checkout', '--detach', 'FETCH_HEAD'], log=log)
    require_pin(destination, commit)


def replace_once(path, old, new):
    text = path.read_text(encoding='utf-8')
    if text.count(old) != 1:
        raise ProbeError(f'{path}: expected one exact integration anchor: {old[:75]}')
    path.write_text(text.replace(old, new), encoding='utf-8')


def integrate_probe(uefi, tree, app_dir, build_id):
    """Change only isolated source copies, retaining UniXNUDxe's file GUID."""
    source_inf = app_dir / 'ShengUefiProbe.inf'
    inf = source_inf.read_text(encoding='utf-8')
    match = re.search(r'^\s*FILE_GUID\s*=\s*([\w-]+)', inf, re.MULTILINE)
    if not match or match[1].upper() != APP_GUID:
        raise ProbeError('Probe FILE_GUID must match the UniXNUDxe application PCD')
    staged_app = tree / 'package/UniXNUPkg/Application/ShengUefiProbe'
    shutil.copytree(app_dir, staged_app, ignore=shutil.ignore_patterns('__pycache__'))
    replace_once(staged_app / 'ShengUefiProbe.c',
                 '#define SHENG_UEFI_PROBE_BUILD_ID "unversioned"',
                 '#define SHENG_UEFI_PROBE_BUILD_ID ' + json.dumps(build_id))
    changed = []
    for relative in (PLATFORM / 'sheng.dsc', PLATFORM / 'sheng.fdf'):
        path = uefi / relative
        replace_once(path, NORMAL_APP, PROBE_APP)
        changed.append(str(relative))
    for relative in (PLATFORM / 'sheng.dsc', PLATFORM / 'Include/DXE.inc'):
        path = uefi / relative
        text = path.read_text(encoding='utf-8')
        lines = text.splitlines(keepends=True)
        active = [line for line in lines if DARWIN_INF in line and not line.lstrip().startswith('#')]
        if len(active) != 1:
            raise ProbeError(f'{path}: expected one DarwinBoot module to remove')
        path.write_text(''.join(line for line in lines if line not in active), encoding='utf-8')
        if str(relative) not in changed:
            changed.append(str(relative))
    # The pinned APRIORI list points at a vendor DevicePathDxe while DXE.inc
    # embeds the source implementation. Make the two references agree.
    apriori = uefi / PLATFORM / 'Include/APRIORI.inc'
    replace_once(apriori, 'Binaries/sheng/MdeModulePkg/Universal/DevicePathDxe/DevicePathDxe.inf',
                 'MdeModulePkg/Universal/DevicePathDxe/DevicePathDxe.inf')
    changed.append(str(PLATFORM / 'Include/APRIORI.inc'))
    dsc = (uefi / PLATFORM / 'sheng.dsc').read_text(encoding='utf-8')
    for name in ('SHENG_VENDOR_HW', 'USE_CUSTOM_DISPLAY_DRIVER'):
        if not re.search(rf'^\s*{name}\s*=\s*0\s*$', dsc, re.MULTILINE):
            raise ProbeError(f'Probe requires the pinned minimal {name}=0 path')
    replace_once(uefi / SEC_SOURCE, '  PrintFirmwareVersion ();',
                 '  PrintFirmwareVersion ();\n  DEBUG ((EFI_D_WARN, "SHENGUEFI: SEC_DEBUG_READY\\n"));')
    replace_once(tree / REGISTRATION_SOURCE, '  Path = FindApplication (ImageHandle);',
                 '  DEBUG ((DEBUG_WARN, "SHENGUEFI: DXE_REGISTRATION\\n"));\n  Path = FindApplication (ImageHandle);')
    bds = uefi / BDS_SOURCE
    replace_once(bds, '  // Protect Shared RFS Area',
                 '  DEBUG ((EFI_D_WARN, "SHENGUEFI: BDS_ENTRY\\n"));\n  // Protect Shared RFS Area')
    replace_once(bds, '  // Create SD Card Init Event',
                 '  DEBUG ((EFI_D_WARN, "SHENGUEFI: BDS_AFTER_CONSOLE\\n"));\n  // Create SD Card Init Event')
    text = bds.read_text(encoding='utf-8')
    expression = r'(DeviceBootManagerBeforeConsole\s*\([^{};]*\)\s*\{\s*\n)'
    text, count = re.subn(expression, lambda match: match[1] +
                         '  DEBUG ((EFI_D_WARN, "SHENGUEFI: BDS_BEFORE_CONSOLE\\n"));\n', text)
    if count != 1:
        raise ProbeError('Pinned BDS before-console integration anchor changed')
    bds.write_text(text, encoding='utf-8')
    replace_once(uefi / GOP_SOURCE,
                 '  Status = gBS->InstallMultipleProtocolInterfaces (&ImageHandle, &gEfiDevicePathProtocolGuid, &DisplayDevicePath, &gEfiGraphicsOutputProtocolGuid, &mFrameBuffer, NULL);',
                 '  Status = gBS->InstallMultipleProtocolInterfaces (&ImageHandle, &gEfiDevicePathProtocolGuid, &DisplayDevicePath, &gEfiGraphicsOutputProtocolGuid, &mFrameBuffer, NULL);\n'
                 '  DEBUG ((EFI_D_WARN, "SHENGUEFI: GOP_REGISTER status=%r\\n", Status));')
    changed += [str(SEC_SOURCE), str(BDS_SOURCE), str(GOP_SOURCE), 'tree/' + str(REGISTRATION_SOURCE)]
    # Pinning catches upstream changes; these checks catch accidental duplicate
    # app inclusion or an XNU loader being left in the isolated selection.
    for relative in (PLATFORM / 'sheng.dsc', PLATFORM / 'sheng.fdf', PLATFORM / 'Include/DXE.inc'):
        text = (uefi / relative).read_text(encoding='utf-8')
        active = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
        if NORMAL_APP in active or DARWIN_INF in active:
            raise ProbeError(f'{relative}: ordinary OS boot entry remains selected')
    return changed


def integrate_menu(uefi, tree, build_id):
    """Reuse the proven minimal firmware with UniXNU and a read-only file disk."""
    changed = integrate_probe(uefi, tree, ROOT / 'package/UefiProbe', build_id)
    for relative in (PLATFORM / 'sheng.dsc', PLATFORM / 'sheng.fdf'):
        replace_once(uefi / relative, PROBE_APP, NORMAL_APP)
    shutil.copytree(ROOT / 'package/UefiMenuDisk', tree / 'package/UefiMenuDisk')
    dsc = uefi / PLATFORM / 'sheng.dsc'
    with dsc.open('a', encoding='utf-8') as stream:
        stream.write('\n[Components]\n  ' + MENU_DISK_INF + '\n  ' + HELLO_INF + '\n')
        stream.write('\n[PcdsFixedAtBuild]\n  gUniXNUPkgTokenSpaceGuid.PcdUniXNUDebugLevel|0x00000002\n')
    raw = uefi / 'Stage2Menu/menu-fat.img'
    raw.parent.mkdir()
    raw.write_bytes(b'\0' * 512)  # First pass builds HelloPayload; final pass embeds the verified FAT.
    replace_once(uefi / PLATFORM / 'sheng.fdf', '  # IORT DT',
                 '  INF ' + MENU_DISK_INF + '\n'
                 '  FILE FREEFORM = ' + MENU_PAYLOAD_GUID + ' {\n'
                 '    SECTION RAW = Stage2Menu/menu-fat.img\n'
                 '    SECTION UI = "ShengMenuFiles"\n'
                 '  }\n\n  # IORT DT')
    secure = Path('Silicon/Silicium/SiliciumPkg/Library/BootManagerLib/BootManager.c')
    replace_once(uefi / secure,
                 'PlatformBootManagerBdsEntry ()\n{\n  EFI_STATUS Status;',
                 'PlatformBootManagerBdsEntry ()\n{')
    replace_once(uefi / secure,
                 '  // Setup Secure Boot\n  Status = SetupSecureBoot ();\n  ASSERT_EFI_ERROR (Status);',
                 '  // Standalone menu research firmware: no key enrollment or filesystem callback.\n'
                 '  DEBUG ((DEBUG_WARN, "SHENGMENU: isolated file-loader policy; no key enrollment\\n"));')
    changed.append(str(secure))
    menu = Path('package/UniXNUPkg/Library/UniXNULib/Menu.c')
    replace_once(tree / menu, '  RotateMs = Config->RotateSeconds * 1000;',
                 '  // Stage 2 waits for physical selection; missing input never starts a file.\n'
                 '  RemainingMs = -1;\n  RotateMs = Config->RotateSeconds * 1000;')
    replace_once(tree / menu, '  UniXNUUiDrawFrame (Ui, Config);',
                 '  RotateMs = 0;\n  UniXNUUiDrawFrame (Ui, Config);')
    changed.append('tree/' + str(menu))
    hello_source = Path('package/UniXNUPkg/Test/HelloPayload/HelloPayload.c')
    replace_once(tree / hello_source,
                 '  Print (L"UNIXNU-HELLO: Hello from the UniXNU test payload\\n");',
                 '  Print (L"UNIXNU-HELLO: Hello from the UniXNU test payload\\n");\n'
                 '  Print (L"SHENG MENU FILE: ' + build_id + '\\n");')
    changed.append('tree/' + str(hello_source))
    return changed


def source_identity(stage='probe'):
    files = [ROOT / 'board.toml', Path(__file__),
             *sorted((ROOT / 'package/UefiProbe').glob('*')),
             *(ROOT / 'scripts' / name for name in PREFLIGHT_SCRIPTS)]
    if stage == 'menu':
        files += [ROOT / 'scripts/make-uefi-menu-volume.py',
                  *sorted((ROOT / 'package/UefiMenuDisk').glob('*')),
                  *sorted((ROOT / 'package/UefiMenu').glob('*'))]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path) for path in files if path.is_file()}
    combined = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    return hashes, combined


def verify_firmware(uefi, tree, fd, build_id, logs, env, menu_report=None):
    """Inspect the decompressed FV, not strings in a compressed FD blob."""
    (tree / 'uefi-sheng').symlink_to(uefi, target_is_directory=True)
    command([sys.executable, tree / 'scripts/check-sheng-fv.py'], cwd=tree,
            env=env, log=logs / 'firmware-volume.log')
    report = json.loads((tree / 'build/sheng/fv-check.json').read_text())
    app_found = False
    menu_found = False
    for info in fd.with_name(fd.name + '.dump').rglob('info.txt'):
        fields = {}
        for line in info.read_text(errors='replace').splitlines():
            if ': ' in line:
                key, value = line.split(': ', 1)
                fields.setdefault(key, value)
        if fields.get('Type') != 'File':
            continue
        if fields.get('Text') == 'DarwinBoot':
            raise ProbeError('DarwinBoot remains in the assembled firmware volume')
        if fields.get('File GUID', '').upper() == MENU_PAYLOAD_GUID:
            if menu_report is None or menu_found:
                raise ProbeError('Unexpected or duplicate embedded menu volume')
            menu_found = any(digest(body) == menu_report['sha256'] for body in info.parent.rglob('body.bin'))
            if not menu_found:
                raise ProbeError('Embedded FAT image does not match the verified volume')
        if fields.get('File GUID', '').upper() != APP_GUID:
            continue
        expected_app = 'ShengUefiProbe' if menu_report is None else 'UniXNU'
        if app_found or fields.get('Text') != expected_app:
            raise ProbeError(f'Firmware application GUID does not identify one {expected_app}')
        app_found = True
        if menu_report is None and not any(build_id.encode('ascii') in body.read_bytes() for body in info.parent.rglob('body.bin')):
            raise ProbeError('Built application does not contain the expected build ID')
    if not app_found:
        raise ProbeError('Standalone probe application absent from decompressed FV')
    if menu_report is not None and not menu_found:
        raise ProbeError('Menu FAT image absent from decompressed FV')
    report.update(probe_application_guid=APP_GUID, probe_build_id=build_id, probe_app_verified=True,
                  hardware_tested=False)
    if menu_report is not None:
        report.update(menu_volume_verified=True, menu_volume_sha256=menu_report['sha256'],
                      menu_config_build_id=build_id)
    return report


def checkpoints_document():
    return {
        'hardware_tested': False, 'observed': [], 'expected': list(EXPECTED_CHECKPOINTS),
        'bootshim': 'No UART or display checkpoint before SEC debug initialization; BootShim execution is not asserted.',
        'early_output': 'Pinned DEBUG firmware maps SerialPortLib to FrameBufferSerialPortLib. SEC, DXE and BDS DEBUG markers draw into the inherited framebuffer, not a physical UART. Photograph or video this output; its visibility depends on the stock display handoff.',
        'gop': 'GOP_READY is emitted by the application only after a successful GOP Blt.',
        'acceptance': 'One complete device run: matching build ID, visible heartbeat for at least 300 timer ticks, input response and manual Fastboot return. Host build success does not satisfy these checks.',
    }


def self_test():
    """Check the probe contract without a compiler, network or device."""
    app = ROOT / 'package/UefiProbe'
    inf = (app / 'ShengUefiProbe.inf').read_text(encoding='utf-8')
    source = (app / 'ShengUefiProbe.c').read_text(encoding='utf-8')
    if APP_GUID not in inf or 'UniXNULib' in inf:
        raise ProbeError('Probe GUID/dependency contract failed')
    for forbidden in ('LoadImage (', 'StartImage (', 'ExitBootServices (', 'EFI_SIMPLE_FILE_SYSTEM_PROTOCOL'):
        if forbidden in source:
            raise ProbeError(f'Unexpected OS/filesystem dependency in probe: {forbidden}')
    if source.count('#define SHENG_UEFI_PROBE_BUILD_ID "unversioned"') != 1:
        raise ProbeError('Build ID integration contract changed')
    for checkpoint in ('APP_ENTRY', 'GOP_READY', 'MENU_READY', 'HOLD_300_TICKS', 'RUN_CHECKS_MET'):
        if checkpoint not in source:
            raise ProbeError(f'Probe checkpoint missing: {checkpoint}')
    if checkpoints_document()['observed'] or checkpoints_document()['hardware_tested']:
        raise ProbeError('Host checks must not claim device observations')
    module_spec = importlib.util.spec_from_file_location('menu_volume', ROOT / 'scripts/make-uefi-menu-volume.py')
    menu_volume = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(menu_volume)
    menu_volume.render_config('self-test')
    if MENU_PAYLOAD_GUID.lower() not in (ROOT / 'package/UefiMenuDisk/ShengMenuDiskDxe.inf').read_text().lower():
        raise ProbeError('Menu disk RAW GUID contract changed')
    print('PASS: GUID, standalone dependencies, build ID, checkpoints and evidence separation')


def build(args):
    output = args.output.resolve()
    if output.exists():
        raise ProbeError(f'Output already exists; choose a fresh directory: {output}')
    if not args.prepare_only and sys.platform != 'darwin':
        raise ProbeError('Full build requires macOS for the pinned UEFIExtract importer; use --self-test on this host')
    require_pin(args.unixnu, TOOLS_COMMIT)
    require_pin(args.uefi, UEFI_COMMIT)
    hashes, identity = source_identity(args.stage)
    revision = git(ROOT, 'rev-parse', 'HEAD')
    prefix = 'sheng-uefi' if args.stage == 'probe' else 'sheng-menu'
    build_id = args.build_id or f'{prefix}-{revision[:12]}-{identity[:12]}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}'
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,96}', build_id):
        raise ProbeError('--build-id must be 1-96 ASCII letters, digits, dots, underscores or hyphens')
    output.mkdir(parents=True)
    logs = output / 'logs'
    logs.mkdir()
    work = output / 'work'
    work.mkdir()
    tree, tools, uefi = work / 'tree', work / 'tools', work / 'uefi'
    tree.mkdir()
    manifest = {'schema_version': 1, 'kind': prefix, 'stage': args.stage, 'status': 'preparing',
                'build_id': build_id, 'target': 'DEBUG', 'hardware_tested': False,
                'bootloader_acceptance_proven': False, 'source_identity_sha256': identity,
                'source_files_sha256': hashes, 'revisions': {'device': revision, 'tools': TOOLS_COMMIT,
                'uefi': UEFI_COMMIT, 'edk2': EDK2_COMMIT}, 'outputs': {},
                'excluded_stages': ['kernel', 'payload', 'Data seed', 'IPSW', 'userdata flashing'],
                'device_commands_executed': False}
    write_json(output / 'manifest.json', manifest)
    checkpoints = checkpoints_document()
    if args.stage == 'menu':
        checkpoints.update(expected=['SHENGMENUDISK: published', 'UNIXNU: config:', 'UNIXNU: menu:',
                                     'Expected missing file error returned: Not Found', 'UNIXNU-HELLO: Hello',
                                     'SHENG MENU FILE: ' + build_id, 'Hello file probe returned: Success'],
                           acceptance='One device run: matching menu title/build ID, physical selection, visible Not Found error, file-loaded Hello build ID and return to menu; no OS starts.')
    write_json(output / 'checkpoints.json', checkpoints)
    try:
        clone_local(args.unixnu, tools, TOOLS_COMMIT, logs / 'sources.log')
        clone_local(args.uefi, uefi, UEFI_COMMIT, logs / 'sources.log')
        board = copy.deepcopy(tomllib.loads((ROOT / 'board.toml').read_text(encoding='utf-8')))
        # A device comparison with identical kernel bytes reached the visible
        # probe and working volume keys only with a v4 Android container.
        # Override the isolated board copy; retain the repository's OS recipe.
        board.setdefault('bootimg', {}).setdefault('image', {}).update(PROBE_BOOT_IMAGE)
        manifest['probe_boot_image_overrides'] = dict(PROBE_BOOT_IMAGE)
        # Import genuine board binaries below rather than downloading the
        # unrelated Device-Binaries submodule or a second Mu_Basecore checkout.
        command(['git', '-C', uefi, 'submodule', 'update', '--init', '--recursive', '--depth', '1',
                 '--', *board['firmware']['submodules']], log=logs / 'sources.log')
        shutil.copytree(tools / 'package', tree / 'package', ignore=shutil.ignore_patterns('.git', 'Build'))
        (tree / 'scripts').mkdir()
        for name in PREFLIGHT_SCRIPTS:
            shutil.copy2(ROOT / 'scripts' / name, tree / 'scripts' / name)
        shutil.copy2(ROOT / 'board.toml', tree / 'board.toml')
        if args.stage == 'menu':
            manifest['isolated_changes'] = integrate_menu(uefi, tree, build_id)
            board['firmware']['defines']['ENABLE_SECUREBOOT'] = '0'
            manifest['file_loader_policy'] = 'Isolated research firmware accepts test EFI files; no key enrollment or filesystem secure-boot callback. Stock bootloader and repository board remain unchanged.'
        else:
            manifest['isolated_changes'] = integrate_probe(uefi, tree, ROOT / 'package/UefiProbe', build_id)
        (logs / 'firmware-source-overlay.patch').write_text(git(uefi, 'diff', '--ignore-submodules=all'), encoding='utf-8')
        manifest['isolated_sources_sha256'] = {
            relative: digest(tree / relative[5:] if relative.startswith('tree/') else uefi / relative)
            for relative in manifest['isolated_changes']}
        manifest['isolated_sources_sha256']['probe-app.c'] = digest(tree / 'package/UniXNUPkg/Application/ShengUefiProbe/ShengUefiProbe.c')
        firmware = board['firmware']
        # The standalone application neither loads DarwinBoot nor uses its
        # package search path. No OS profile/component resolution is performed.
        firmware['packages'] = [entry for entry in firmware['packages'] if 'DarwinBoot' not in entry]
        firmware['preflight'] = []
        edk2_source = next(entry for entry in tomllib.loads((tools / 'feeds.toml').read_text(encoding='utf-8'))['source'] if entry['name'] == 'edk2')
        if edk2_source['commit'] != EDK2_COMMIT:
            raise ProbeError('Pinned tools edk2 source differs from probe contract')
        manifest['uefi_submodules'] = [line for line in git(uefi, 'submodule', 'status', '--recursive').splitlines()
                                       if not line.startswith('-')]
        manifest['firmware_defines'] = firmware.get('defines', {})
        manifest['status'] = 'prepared'
        write_json(output / 'manifest.json', manifest)
        if args.prepare_only:
            print(f'Prepared isolated sources: {output}; no firmware built or device tested')
            return
        env = dict(os.environ, UNIXNU_DEVICE=str(tree), UNIXNU_UEFI=str(uefi))
        # Scripts locate caches from their own path: these isolated copies use
        # only tree/.cache, never an existing installation or normal build cache.
        command([sys.executable, tree / 'scripts/download-sheng-firmware.py'], cwd=tree, env=env, log=logs / 'stock-inputs.log')
        command([sys.executable, tree / 'scripts/extract-sheng-firmware.py', '--delete-archive'], cwd=tree, env=env, log=logs / 'stock-inputs.log')
        command([sys.executable, tree / 'scripts/fetch-sheng-dts.py'], cwd=tree, env=env, log=logs / 'dts.log')
        command([sys.executable, tree / 'scripts/import-sheng-uefi.py'], cwd=tree, env=env, log=logs / 'vendor-import.log')
        command([sys.executable, tree / 'scripts/check-sheng.py'], cwd=tree, env=env, log=logs / 'memory-map.log')
        preflight = json.loads((tree / 'build/sheng/check.json').read_text())
        if preflight['static_errors'] or preflight['missing_vendor_inputs']:
            raise ProbeError('Static memory/vendor preflight failed')
        manifest['preflight'] = preflight
        stock_record = tree / '.cache/firmware/sheng/porting-inputs.json'
        shutil.copy2(stock_record, output / 'stock-inputs.json')
        edk2 = work / 'edk2'
        clone_remote(edk2_source['git'], edk2, EDK2_COMMIT, logs / 'sources.log')
        command(['git', '-C', edk2, 'submodule', 'update', '--init', '--depth', '1', '--', *edk2_source.get('submodules', [])], log=logs / 'sources.log')
        shutil.copytree(ROOT / 'package/UefiProbe', tree / 'package/UefiProbe')
        command([sys.executable, tree / 'scripts/check-uefi-probe.py', '--edk2', edk2,
                 '--cc', 'cc', '--aarch64-cc', 'clang'], cwd=tree, env=env, log=logs / 'host-probe.log')
        sys.path.insert(0, str(tools / 'scripts'))
        from unixnu import firmware as firmware_builder, bootimg
        ctx = SimpleNamespace(board=board, args=SimpleNamespace(skip_preflight=True), tree=tree,
                              device=tree, work=work, logs=logs, jobs=args.jobs)
        fd = firmware_builder.build(ctx, {}, uefi, edk2, target='DEBUG')
        menu_report = None
        if args.stage == 'menu':
            hello = fd.parent.parent / 'AARCH64/HelloPayload.efi'
            menu_image = output / 'menu-volume.img'
            command([sys.executable, ROOT / 'scripts/make-uefi-menu-volume.py',
                     '--hello-efi', hello, '--build-id', build_id, '--output', menu_image],
                    log=logs / 'menu-volume.log')
            menu_report = json.loads(menu_image.with_suffix('.json').read_text())
            if not menu_report['readback_verified']:
                raise ProbeError('Menu volume file readback was not verified')
            shutil.copy2(menu_image, uefi / 'Stage2Menu/menu-fat.img')
            fd = firmware_builder.build(ctx, {}, uefi, edk2, target='DEBUG')
            manifest['menu_volume'] = menu_report
        fv_report = verify_firmware(uefi, tree, fd, build_id, logs, env, menu_report)
        write_json(output / 'fv-check.json', fv_report)
        shutil.copy2(fd, output / 'SILICIUM_UEFI.fd')
        image_settings, fd_base, fd_size, requires_header, _ = bootimg.settings(ctx, uefi)
        manifest['effective_boot_image_settings'] = dict(
            image_settings, kernel_compression=str(image_settings.get('kernel_compression', 'gzip')).lower())
        manifest['boot_layout'] = {
            'fd_base': hex(fd_base), 'fd_bytes': fd_size, 'requires_kernel_header': requires_header,
            'append_dtb': True, 'dtb_node_fixups': board['bootimg'].get('dtb_node', [])}
        bootimg.build(ctx, uefi, fd, tree / 'build/sheng/sheng.dtb', ramdisk=None, output=output / 'boot.img')
        report = json.loads((output / 'boot.json').read_text())
        if report['header_version'] != PROBE_BOOT_IMAGE['header_version']:
            raise ProbeError('UEFI probe must use the v4 Android container')
        if report['ramdisk_bytes'] != 0 or report['hardware_tested']:
            raise ProbeError('UEFI probe image must have no ramdisk and no hardware claim')
        for path in fd.parent.glob('*.Fv.map'):
            shutil.copy2(path, logs / path.name)
        output_names = ['boot.img', 'SILICIUM_UEFI.fd', 'boot.json', 'stock-inputs.json', 'fv-check.json']
        if args.stage == 'menu':
            output_names += ['menu-volume.img', 'menu-volume.json']
        for name in output_names:
            path = output / name
            manifest['outputs'][name] = {'bytes': path.stat().st_size, 'sha256': digest(path)}
        manifest['status'] = 'built'
        write_json(output / 'manifest.json', manifest)
        (output / 'SHA256SUMS').write_text(''.join(f'{digest(output / name)}  {name}\n' for name in
                                               (*manifest['outputs'], 'manifest.json', 'checkpoints.json')), encoding='utf-8')
        print(f'Built UEFI-only probe: {output / "boot.img"}; hardware_tested=false')
    except Exception as error:
        manifest['status'] = 'failed'
        manifest['error'] = str(error)
        write_json(output / 'manifest.json', manifest)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unixnu', type=Path, default=ROOT.parent / 'UniXNU', help=f'clean tools checkout at {TOOLS_COMMIT}')
    parser.add_argument('--uefi', type=Path, default=ROOT.parent / 'uefi-sheng', help=f'clean firmware checkout at {UEFI_COMMIT}')
    parser.add_argument('--output', type=Path, default=ROOT / 'out/uefi-probe', help='fresh output directory (must not exist)')
    parser.add_argument('--build-id', help='optional ASCII identifier; source hashes always remain in the manifest')
    parser.add_argument('--stage', choices=('probe', 'menu'), default='probe', help='probe: standalone UI; menu: UniXNU with an embedded read-only FAT file fixture')
    parser.add_argument('-j', '--jobs', type=int, default=4)
    parser.add_argument('--prepare-only', action='store_true', help='stage isolated firmware sources and integration; do not import stock inputs or compile')
    parser.add_argument('--self-test', action='store_true', help='run offline standalone-app contract checks only')
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    try:
        if args.self_test:
            self_test()
        else:
            args.unixnu, args.uefi = args.unixnu.resolve(), args.uefi.resolve()
            build(args)
    except (ProbeError, OSError, ValueError, StopIteration) as error:
        print(f'UEFI probe: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
