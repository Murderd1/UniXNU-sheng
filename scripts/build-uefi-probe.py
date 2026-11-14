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


def source_identity():
    files = [ROOT / 'board.toml', Path(__file__),
             *sorted((ROOT / 'package/UefiProbe').glob('*')),
             *(ROOT / 'scripts' / name for name in PREFLIGHT_SCRIPTS)]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path) for path in files if path.is_file()}
    combined = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    return hashes, combined


def verify_firmware(uefi, tree, fd, build_id, logs, env):
    """Inspect the decompressed FV, not strings in a compressed FD blob."""
    (tree / 'uefi-sheng').symlink_to(uefi, target_is_directory=True)
    command([sys.executable, tree / 'scripts/check-sheng-fv.py'], cwd=tree,
            env=env, log=logs / 'firmware-volume.log')
    report = json.loads((tree / 'build/sheng/fv-check.json').read_text())
    app_found = False
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
        if fields.get('File GUID', '').upper() != APP_GUID:
            continue
        if app_found or fields.get('Text') != 'ShengUefiProbe':
            raise ProbeError('Firmware application GUID does not identify one ShengUefiProbe')
        app_found = any(build_id.encode('ascii') in body.read_bytes() for body in info.parent.rglob('body.bin'))
        if not app_found:
            raise ProbeError('Built application does not contain the expected build ID')
    if not app_found:
        raise ProbeError('Standalone probe application absent from decompressed FV')
    report.update(probe_application_guid=APP_GUID, probe_build_id=build_id, probe_app_verified=True,
                  hardware_tested=False)
    return report


def checkpoints_document():
    return {
        'hardware_tested': False, 'observed': [], 'expected': list(EXPECTED_CHECKPOINTS),
        'bootshim': 'No UART or display checkpoint before SEC debug initialization; BootShim execution is not asserted.',
        'early_output': 'Pinned DEBUG firmware maps SerialPortLib to FrameBufferSerialPortLib. SEC, DXE and BDS DEBUG markers draw into the inherited framebuffer, not a physical UART. Photograph or video this output; its visibility depends on the stock display handoff.',
        'gop': 'GOP_READY is emitted by the application only after a successful GOP Blt.',
        'acceptance': 'On the device: matching build ID, visible heartbeat for at least 300 timer ticks, input response, and three cold boots. Host build success does not satisfy these checks.',
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
    print('PASS: GUID, standalone dependencies, build ID, checkpoints and evidence separation')


def build(args):
    output = args.output.resolve()
    if output.exists():
        raise ProbeError(f'Output already exists; choose a fresh directory: {output}')
    if not args.prepare_only and sys.platform != 'darwin':
        raise ProbeError('Full build requires macOS for the pinned UEFIExtract importer; use --self-test on this host')
    require_pin(args.unixnu, TOOLS_COMMIT)
    require_pin(args.uefi, UEFI_COMMIT)
    hashes, identity = source_identity()
    revision = git(ROOT, 'rev-parse', 'HEAD')
    build_id = args.build_id or f'sheng-uefi-{revision[:12]}-{identity[:12]}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}'
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,96}', build_id):
        raise ProbeError('--build-id must be 1-96 ASCII letters, digits, dots, underscores or hyphens')
    output.mkdir(parents=True)
    logs = output / 'logs'
    logs.mkdir()
    work = output / 'work'
    work.mkdir()
    tree, tools, uefi = work / 'tree', work / 'tools', work / 'uefi'
    tree.mkdir()
    manifest = {'schema_version': 1, 'kind': 'sheng-uefi-probe', 'status': 'preparing',
                'build_id': build_id, 'target': 'DEBUG', 'hardware_tested': False,
                'bootloader_acceptance_proven': False, 'source_identity_sha256': identity,
                'source_files_sha256': hashes, 'revisions': {'device': revision, 'tools': TOOLS_COMMIT,
                'uefi': UEFI_COMMIT, 'edk2': EDK2_COMMIT}, 'outputs': {},
                'excluded_stages': ['kernel', 'payload', 'Data seed', 'IPSW', 'userdata flashing'],
                'device_commands_executed': False}
    write_json(output / 'manifest.json', manifest)
    write_json(output / 'checkpoints.json', checkpoints_document())
    try:
        clone_local(args.unixnu, tools, TOOLS_COMMIT, logs / 'sources.log')
        clone_local(args.uefi, uefi, UEFI_COMMIT, logs / 'sources.log')
        board = copy.deepcopy(tomllib.loads((ROOT / 'board.toml').read_text(encoding='utf-8')))
        # Import genuine board binaries below rather than downloading the
        # unrelated Device-Binaries submodule or a second Mu_Basecore checkout.
        command(['git', '-C', uefi, 'submodule', 'update', '--init', '--recursive', '--depth', '1',
                 '--', *board['firmware']['submodules']], log=logs / 'sources.log')
        shutil.copytree(tools / 'package', tree / 'package', ignore=shutil.ignore_patterns('.git', 'Build'))
        (tree / 'scripts').mkdir()
        for name in PREFLIGHT_SCRIPTS:
            shutil.copy2(ROOT / 'scripts' / name, tree / 'scripts' / name)
        shutil.copy2(ROOT / 'board.toml', tree / 'board.toml')
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
        fv_report = verify_firmware(uefi, tree, fd, build_id, logs, env)
        write_json(output / 'fv-check.json', fv_report)
        shutil.copy2(fd, output / 'SILICIUM_UEFI.fd')
        bootimg.build(ctx, uefi, fd, tree / 'build/sheng/sheng.dtb', ramdisk=None, output=output / 'boot.img')
        report = json.loads((output / 'boot.json').read_text())
        if report['ramdisk_bytes'] != 0 or report['hardware_tested']:
            raise ProbeError('UEFI probe image must have no ramdisk and no hardware claim')
        for path in fd.parent.glob('*.Fv.map'):
            shutil.copy2(path, logs / path.name)
        for name in ('boot.img', 'SILICIUM_UEFI.fd', 'boot.json', 'stock-inputs.json', 'fv-check.json'):
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
