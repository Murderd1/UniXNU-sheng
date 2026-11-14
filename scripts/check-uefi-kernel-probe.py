#!/usr/bin/env python3
"""Check the real full-kernel probe with mocked services and real EDK II headers.

The generated configuration is a temporary test fixture. This does not execute
firmware or XNU, or establish tablet display, input, storage or recovery behavior.
"""
import argparse
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--edk2', type=Path, required=True, help='Mu_Basecore checkout containing MdePkg')
    parser.add_argument('--unixnu', type=Path, default=ROOT.parent / 'UniXNU', help='UniXNU checkout containing package/UniXNUPkg')
    parser.add_argument('--cc', default=shutil.which('cc') or shutil.which('clang') or shutil.which('cl'), help='native C compiler')
    parser.add_argument('--aarch64-cc', help='optional clang for AARCH64 freestanding compilation')
    args = parser.parse_args()
    if not args.cc:
        parser.error('a native C compiler is required; pass --cc')
    include = args.edk2.resolve() / 'MdePkg/Include'
    unixnu_include = args.unixnu.resolve() / 'package/UniXNUPkg/Include'
    if not (include / 'Uefi.h').is_file():
        parser.error('--edk2 must contain MdePkg/Include/Uefi.h')
    if not (unixnu_include / 'Protocol/UniXNULoader.h').is_file():
        parser.error('--unixnu must contain package/UniXNUPkg/Include/Protocol/UniXNULoader.h')
    native_arch = 'AArch64' if platform.machine().lower() in ('arm64', 'aarch64') else 'X64'
    with tempfile.TemporaryDirectory(prefix='sheng-kernel-probe-check-') as name:
        work = Path(name)
        source_dir = work / 'package/UefiKernelProbe'
        diagnostic_dir = work / 'package/UefiKernelDisk'
        source_dir.mkdir(parents=True)
        diagnostic_dir.mkdir(parents=True)
        source = source_dir / 'ShengKernelProbe.c'
        shutil.copy2(ROOT / 'package/UefiKernelProbe/ShengKernelProbe.c', source)
        shutil.copy2(ROOT / 'package/UefiKernelDisk/ShengKernelDiskDiagnostic.h', diagnostic_dir)
        fixture = source_dir / 'probe-host.c'
        shutil.copy2(ROOT / 'package/UefiKernelProbe/tests/probe-host.c', fixture)
        config = source_dir / 'ShengFullTrialConfig.h'
        config.write_text('#define SHENG_FULL_TRIAL_ARGS mTestArgs\n#define SHENG_FULL_TRIAL_RAMDISK_BYTES 16ULL\n', encoding='utf-8')
        executable = work / ('probe-host.exe' if platform.system() == 'Windows' else 'probe-host')
        includes = [include, include / native_arch, unixnu_include, source_dir]
        if Path(args.cc).name.lower() in ('cl', 'cl.exe'):
            command = [args.cc, '/nologo', '/O2', '/W3', '/D_CRT_SECURE_NO_WARNINGS',
                       *[f'/I{path}' for path in includes], str(fixture), f'/Fe{executable}', f'/Fo{work / "probe-host.obj"}']
        else:
            command = [args.cc, '-std=c11', '-O2', '-fshort-wchar', '-DNO_MSABI_VA_FUNCS', '-Werror', '-Wall', '-Wextra',
                       '-Wno-unused-parameter', '-Wno-missing-field-initializers',
                       *[argument for path in includes for argument in ('-I', str(path))], str(fixture), '-o', str(executable)]
        subprocess.run(command, check=True, cwd=work)
        subprocess.run([str(executable)], check=True, timeout=45)
        if args.aarch64_cc:
            config.write_text('#define SHENG_FULL_TRIAL_ARGS L"data-persist=0 log=0 native-source-storage=1 native-ufs-root=1"\n'
                              '#define SHENG_FULL_TRIAL_RAMDISK_BYTES 16ULL\n', encoding='utf-8')
            subprocess.run([args.aarch64_cc, '--target=aarch64-unknown-windows', '-ffreestanding', '-fshort-wchar',
                            '-fno-builtin', '-Werror', '-Wall', '-Wextra', '-Wno-unused-parameter',
                            '-I', str(include), '-I', str(include / 'AArch64'), '-I', str(unixnu_include),
                            '-c', str(source), '-o', str(work / 'ShengKernelProbe.obj')], check=True)
            print('PASS: kernel probe AARCH64 freestanding compilation against real EDK II headers')
    print('Host verification only; firmware build and tablet acceptance remain separate.')


if __name__ == '__main__':
    main()
