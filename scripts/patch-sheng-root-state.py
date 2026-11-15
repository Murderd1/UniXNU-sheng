#!/usr/bin/env python3
"""Replace one fixed kernel's probe-13 stats thread with a read-only snapshot.

The actual kernel extracted from the qualified FAT is the sole accepted input.
Only statsThread's second instruction and verified unused text padding change.
Its initial PACIBSP, the normal root path and the existing panic renderer stay
intact. This compiles a small freestanding probe; it never compiles XNU.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess


ROOT = Path(__file__).resolve().parents[1]
INPUT_SHA256 = 'b8d0e71ccceffbb13023b8343a633db5f9f7b16de058b42d263c5d7c118a1c92'
THREAD_SHA256 = 'efdc00460ab2d75450cdd82f3664d9b25c9a74e6eb1488eb8880c311c33b6720'
THREAD_SYMBOL = '__ZL11statsThreadPvi'
THREAD_VA = 0xfffffff00b826cc0
THREAD_BYTES = 164
ZERO_START = 0xfffffff00aefa784
CAVE_START = 0xfffffff00aefa790
CAVE_END = 0xfffffff00aefb000

# Macro -> (real symbol, byte width, independently checked address).
FIELDS = {
    'ROOT_ACCEPTED': ('_native_owner_root_accepted', 4, 0xfffffff00b91c6a8),
    'ROOT_APPLE': ('_native_owner_root_apple_autherr', 4, 0xfffffff00b84c7e4),
    'ROOT_DECISION': ('_native_owner_root_decision', 4, 0xfffffff00b84c7e8),
    'ROOT_READONLY': ('_native_owner_root_readonly', 4, 0xfffffff00b84c7ec),
    'ROOT_MOUNT_DEVICE': ('_native_owner_root_mount_device', 4, 0xfffffff00b84c7dc),
    'ROOT_SELECTED_DEVICE': ('_native_owner_root_selected_device', 4, 0xfffffff00b84c7e0),
    'ROOT_DEVICE': ('_rootdev', 4, 0xfffffff00b91c670),
    'CACHE_STAGE': ('_native_owner_cache_stage', 4, 0xfffffff00b91d308),
    'CACHE_STATUS': ('_native_owner_cache_status', 4, 0xfffffff00b84d678),
    'CACHE_MOUNT_STATUS': ('_native_owner_cache_mount_status', 4, 0xfffffff00b84d67c),
    'CACHE_READONLY': ('_native_owner_cache_readonly', 4, 0xfffffff00b91d30c),
    'CACHE_AUTHORIZED': ('_native_owner_cache_authorized', 4, 0xfffffff00b91d310),
    'CACHE_ROOT_RECHECK': ('_native_owner_cache_root_recheck', 4, 0xfffffff00b91d314),
    'CACHE_UNION': ('_native_owner_cache_native_union', 4, 0xfffffff00b91d330),
    'CACHE_SELECTED_DEVICE': ('_native_owner_cache_selected_device', 4, 0xfffffff00b84d680),
    'CACHE_MOUNTED_DEVICE': ('_native_owner_cache_mounted_device', 4, 0xfffffff00b84d684),
    'DATA_STAGE': ('_native_owner_data_stage', 4, 0xfffffff00b91d334),
    'DATA_STATUS': ('_native_owner_data_status', 4, 0xfffffff00b84d688),
    'DATA_READONLY': ('_native_owner_data_readonly', 4, 0xfffffff00b84d68c),
    'DATA_DEVICE': ('_native_owner_data_device', 4, 0xfffffff00b84d690),
    'UFS_STEP': ('_native_ufs_root_step', 4, 0xfffffff00b963b54),
    'UFS_PUBLISHED': ('_native_ufs_blocks_published', 4, 0xfffffff00b963ce8),
    'UFS_READS': ('_native_ufs_block_reads', 8, 0xfffffff00b963cf0),
    'UFS_FAILURES': ('_native_ufs_block_failures', 8, 0xfffffff00b963cf8),
    'RAM_READY': ('_native_ram_block_ready', 4, 0xfffffff00b963d20),
    'RAM_SPARSE': ('_native_ram_block_sparse', 4, 0xfffffff00b963d50),
    'RAM_READS': ('_native_ram_block_reads', 8, 0xfffffff00b963d30),
    'RAM_WRITES': ('_native_ram_block_writes', 8, 0xfffffff00b963d38),
    'RAM_FAILURES': ('_native_ram_block_failures', 8, 0xfffffff00b963d40),
    'STORE_WRITES': ('_native_ufs_store_wr_ops', 8, 0xfffffff00b963bd8),
    'STORE_SYNCS': ('_native_ufs_store_sync_ops', 8, 0xfffffff00b963be8),
    'PROCESS_COUNT': ('_nprocs', 4, 0xfffffff00b942a78),
}
CALLS = {'kernel_IOSleep': ('_IOSleep', 0xfffffff00b422a48),
         'kernel_panic': ('_panic', 0xfffffff00b768794)}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_commands(data, header):
    if header < 0 or header + 32 > len(data) or struct.unpack_from('<I', data, header)[0] != 0xfeedfacf:
        raise ValueError('Expected a bounded 64-bit Mach-O header')
    count, command_bytes = struct.unpack_from('<II', data, header + 16)
    offset = header + 32
    end = offset + command_bytes
    if end > len(data):
        raise ValueError('Mach-O load commands exceed the file')
    for _ in range(count):
        if offset + 8 > end:
            raise ValueError('Truncated Mach-O load command')
        command, size = struct.unpack_from('<II', data, offset)
        if size < 8 or offset + size > end:
            raise ValueError('Invalid Mach-O load command size')
        yield command, offset, size
        offset += size
    if offset != end:
        raise ValueError('Mach-O command count and size disagree')


def parse_kernel(data):
    segments = []
    kernel_headers = []
    for command, offset, size in load_commands(data, 0):
        if command == 0x19:
            name, va, virtual_size, file_offset, file_size = struct.unpack_from('<16sQQQQ', data, offset + 8)
            if file_offset + file_size > len(data):
                raise ValueError('Mach-O segment exceeds the file')
            segments.append((name.rstrip(b'\0').decode('ascii'), va, virtual_size, file_offset, file_size))
        elif command == 0x80000035:
            _, file_offset, name_offset = struct.unpack_from('<QQI', data, offset + 8)
            end = data.find(b'\0', offset + name_offset, offset + size)
            if name_offset < 32 or end < 0:
                raise ValueError('Invalid fileset entry name')
            if data[offset + name_offset:end] == b'com.apple.kernel':
                kernel_headers.append(file_offset)
    if len(kernel_headers) != 1:
        raise ValueError('Expected exactly one com.apple.kernel fileset entry')
    symbols = {}
    needed = {THREAD_SYMBOL, *(item[0] for item in FIELDS.values()),
              *(item[0] for item in CALLS.values())}
    for command, offset, _ in load_commands(data, kernel_headers[0]):
        if command != 2:
            continue
        table, count, strings, strings_size = struct.unpack_from('<IIII', data, offset + 8)
        if table + count * 16 > len(data) or strings + strings_size > len(data):
            raise ValueError('Kernel symbol table exceeds the file')
        for index in range(count):
            name_index, kind, section, _, va = struct.unpack_from('<IBBHQ', data, table + index * 16)
            # STAB entries retain obsolete, relocated addresses in this kernel.
            if kind & 0xe0 or kind & 0x0e != 0x0e or not section:
                continue
            if name_index >= strings_size:
                raise ValueError('Kernel symbol name exceeds string table')
            end = data.find(b'\0', strings + name_index, strings + strings_size)
            if end < 0:
                raise ValueError('Unterminated kernel symbol name')
            name = data[strings + name_index:end].decode('utf-8')
            if name not in needed:
                continue
            if name in symbols and symbols[name] != va:
                raise ValueError('Conflicting real N_SECT symbol: ' + name)
            symbols[name] = va
    return segments, symbols


def file_offset(segments, va, size):
    for _, start, _, offset, file_size in segments:
        if start <= va and size <= file_size and va - start <= file_size - size:
            return offset + va - start
    raise ValueError('Patch address is not file-backed: ' + hex(va))


def branch(site, target):
    delta = target - site
    if delta % 4 or not -(1 << 27) <= delta < (1 << 27):
        raise ValueError('AArch64 branch target is out of range')
    return struct.pack('<I', 0x14000000 | ((delta >> 2) & 0x03ffffff))


def tool(name):
    path = shutil.which(name)
    if not path:
        raise ValueError(name + ' is required on PATH for the small standalone probe build')
    return path


def command(arguments, workdir, name):
    result = subprocess.run(list(map(str, arguments)), cwd=workdir, capture_output=True)
    output = (result.stdout + result.stderr).decode('utf-8', 'replace')
    (workdir / (name + '.log')).write_text(output, encoding='utf-8')
    if result.returncode:
        raise ValueError(name + ' failed: ' + output[-4000:])


def elf_sections(data):
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
        raise ValueError('Probe linker output is not little-endian AArch64 ELF64')
    offset = struct.unpack_from('<Q', data, 40)[0]
    entry_size, count, name_index = struct.unpack_from('<HHH', data, 58)
    if entry_size != 64 or name_index >= count or offset + count * 64 > len(data):
        raise ValueError('Invalid probe ELF section table')
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, offset + index * 64) for index in range(count)]
    names = headers[name_index]
    name_data = data[names[4]:names[4] + names[5]]
    result = {}
    for values in headers:
        end = name_data.find(b'\0', values[0])
        if end < 0:
            raise ValueError('Invalid probe ELF section name')
        name = name_data[values[0]:end].decode('ascii')
        if name in result:
            raise ValueError('Duplicate ELF section: ' + name)
        result[name] = values
    return result


def patch_kernel(data: bytes, workdir: Path):
    """Return a patched copy and its exact guards, build and scope report."""
    if digest(data) != INPUT_SHA256:
        raise ValueError('Root-state probe requires the exact actual FAT kernel SHA-256 ' + INPUT_SHA256)
    segments, symbols = parse_kernel(data)
    if symbols.get(THREAD_SYMBOL) != THREAD_VA:
        raise ValueError('Real N_SECT statsThread address differs')
    at = file_offset(segments, THREAD_VA, THREAD_BYTES)
    original = data[at:at + THREAD_BYTES]
    if digest(original) != THREAD_SHA256 or original[:8] != bytes.fromhex('7f2303d5ff4302d1'):
        raise ValueError('The complete original statsThread/PACIBSP guard differs')
    zero_at = file_offset(segments, ZERO_START, CAVE_END - ZERO_START)
    if any(data[zero_at:zero_at + CAVE_END - ZERO_START]):
        raise ValueError('Verified entry-page padding is not entirely zero')
    resolved = {}
    for macro, (name, width, expected) in FIELDS.items():
        va = symbols.get(name)
        if va != expected or va % width or not any(
                start <= va and width <= size and va - start <= size - width
                for _, start, size, _, _ in segments):
            raise ValueError('Diagnostic field N_SECT/address/width differs: ' + name)
        resolved[macro] = {'symbol': name, 'va': hex(va), 'bytes': width}
    for _, (name, expected) in CALLS.items():
        if symbols.get(name) != expected:
            raise ValueError('Existing call target differs: ' + name)
        file_offset(segments, expected, 4)
    workdir = Path(workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / 'RootStateProbeSymbols.h').write_text(''.join(
        '#define ' + macro + ' ' + hex(int(info['va'], 16)) + 'UL\n'
        for macro, info in resolved.items()), encoding='ascii')
    sources = (ROOT / 'package/RootStateProbe.c', ROOT / 'package/RootStateProbe.S')
    compiler = tool('clang')
    common = [compiler, '--target=aarch64-none-elf', '-ffreestanding', '-fno-builtin',
              '-fno-stack-protector', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
              '-mgeneral-regs-only', '-fno-pic', '-mcmodel=tiny', '-Oz', '-Wall', '-Wextra', '-Werror']
    command([*common, '-fstack-usage', '-I', workdir, '-c', sources[0], '-o', workdir / 'root-state.o'], workdir, 'compile-c')
    command([compiler, '--target=aarch64-none-elf', '-c', sources[1], '-o', workdir / 'root-state-abi.o'], workdir, 'compile-abi')
    script = workdir / 'root-state.ld'
    script.write_text(''.join(alias + ' = ' + hex(va) + ';\n' for alias, (_, va) in CALLS.items()) +
                      'SECTIONS { . = ' + hex(CAVE_START) + ';\n'
                      ' .text : { KEEP(*(.text.root_state_entry)) *(.text*) *(.rodata*) }\n'
                      ' /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.ARM.*) } }\n', encoding='ascii')
    command([tool('ld.lld'), '-T', script, '-e', 'root_state_thread', workdir / 'root-state.o',
             workdir / 'root-state-abi.o', '-o', workdir / 'root-state.elf'], workdir, 'link')
    elf = (workdir / 'root-state.elf').read_bytes()
    sections = elf_sections(elf)
    if struct.unpack_from('<Q', elf, 24)[0] != CAVE_START:
        raise ValueError('Probe ELF entry does not match the branch destination')
    for name, values in sections.items():
        if values[5] and (values[1] in (4, 9) or values[2] & 0x401 or name in ('.data', '.bss', '.tdata', '.tbss')):
            raise ValueError('Probe has relocations, writable data or TLS: ' + name)
    text = sections.get('.text')
    if text is None or text[3] != CAVE_START or not 0 < text[5] <= CAVE_END - CAVE_START:
        raise ValueError('Probe text does not fit verified entry padding')
    command([tool('llvm-objcopy'), '-O', 'binary', '--only-section=.text', workdir / 'root-state.elf',
             workdir / 'root-state.bin'], workdir, 'objcopy')
    code = (workdir / 'root-state.bin').read_bytes()
    if code != elf[text[4]:text[4] + text[5]]:
        raise ValueError('Probe binary and ELF text differ')
    stack_lines = (workdir / 'root-state.su').read_text().splitlines()
    stack = max(int(line.split('\t')[1]) for line in stack_lines if '\t' in line)
    stack_bound = sum(int(line.split('\t')[1]) for line in stack_lines if '\t' in line) + 16
    if stack_bound > 1536 or any(not line.endswith('\tstatic') for line in stack_lines):
        raise ValueError('Probe stack use is dynamic or exceeds 1536 bytes')
    result = bytearray(data)
    patch_at = at + 4
    instruction = branch(THREAD_VA + 4, CAVE_START)
    cave_at = file_offset(segments, CAVE_START, len(code))
    result[patch_at:patch_at + 4] = instruction
    result[cave_at:cave_at + len(code)] = code
    # Exact comparison establishes that no other function or payload changed.
    if (result[:cave_at] != data[:cave_at] or
            result[cave_at + len(code):patch_at] != data[cave_at + len(code):patch_at] or
            result[patch_at + 4:] != data[patch_at + 4:]):
        raise ValueError('Unexpected mutation outside the two permitted ranges')
    report = {
        'kind': 'sheng-root-state-thread-patch', 'hardware_tested': False,
        'input_sha256': INPUT_SHA256, 'output_sha256': digest(result), 'kernel_bytes': len(data),
        'symbol_filter': 'LC_SYMTAB in com.apple.kernel; exclude N_STAB; require N_SECT',
        'thread_symbol': THREAD_SYMBOL, 'thread_va': hex(THREAD_VA), 'thread_bytes': THREAD_BYTES,
        'original_thread_sha256': THREAD_SHA256, 'pacibsp_preserved': True,
        'entry_patch': {'va': hex(THREAD_VA + 4), 'file_offset': patch_at,
                        'before_hex': original[4:8].hex(), 'after_hex': instruction.hex()},
        'cave': {'zero_start': hex(ZERO_START), 'va': hex(CAVE_START), 'end': hex(CAVE_END),
                 'file_offset': cave_at, 'capacity': CAVE_END - CAVE_START, 'bytes': len(code),
                 'sha256': digest(code), 'whole_original_range_zero': True},
        'source_sha256': {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in sources},
        'fields': resolved, 'maximum_static_stack_bytes': stack,
        'conservative_probe_stack_bound_bytes': stack_bound, 'writable_data_bytes': 0,
        'tls_bytes': 0, 'remaining_relocations': 0,
        'runtime': 'Existing probe13 starts the thread after startRoot; x0 seconds is reused by IOSleep(seconds*1000).',
        'panic_abi': 'Explicit 16-byte aligned Darwin arm64 variadic stack slot; only existing panic is called.',
        'preserved': ['normal root path', 'existing panic renderer', 'log=0', 'data-persist=0',
                      'all kernel bytes outside one branch and verified zero padding'],
        'limits': ['Snapshot fields are sampled separately and are not atomic.',
                   'Early RamBlock NotReady returns precede existing counters; zero counters do not exclude these requests.',
                   'Original earlier panics retain priority; a missing delayed screen is not evidence of a completed stage.'],
    }
    (workdir / 'patch-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return bytes(result), report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True, help='Actual kernel extracted from the qualified FAT')
    parser.add_argument('--output', type=Path, required=True, help='New patched kernel path; must not exist')
    parser.add_argument('--workdir', type=Path, required=True, help='Small probe compilation and report directory')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Choose a new output file; source and existing kernels are never overwritten')
    result, report = patch_kernel(args.kernel.read_bytes(), args.workdir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(result)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
