#!/usr/bin/env python3
"""Verify the pinned self-code-clean overlay and actual AARCH64 COFF opcodes.

No network, firmware build or device commands. The caller supplies the original
pinned Entry.S and real EDK II headers. Tests use isolated temporary checkouts.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('handoff_clean', ROOT / 'scripts/uefi_handoff_clean.py')
OVERLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OVERLAY)


def expect_rejected(action):
    try:
        action()
    except ValueError:
        return
    raise AssertionError('Expected source drift or duplicate overlay to be rejected')


def coff_function(path, name):
    data = path.read_bytes()
    machine, count, _, symbols, number, optional, _ = struct.unpack_from('<HHIIIHH', data)
    assert machine == 0xaa64 and optional == 0
    strings = data[symbols + number * 18:]
    found = []
    for index in range(count):
        at = 20 + index * 40
        section = data[at:at + 8].rstrip(b'\0')
        if section.startswith(b'/'):
            section = strings[int(section[1:]):].split(b'\0')[0]
        if section.decode() == '.text.' + name:
            size, offset = struct.unpack_from('<II', data, at + 16)
            found.append(data[offset:offset + size])
    assert len(found) == 1
    return found[0]


def instructions(text, function):
    block = text.split('<' + function + '>:', 1)[1]
    block = block.split('Disassembly of section', 1)[0]
    return [(int(at, 16), int(opcode, 16), operation.strip()) for at, opcode, operation
            in re.findall(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.+)$', block, re.MULTILINE)]


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def adr_target(opcode, pc):
    assert opcode & 0x9f000000 == 0x10000000
    immediate = ((opcode >> 5) & 0x7ffff) << 2 | ((opcode >> 29) & 3)
    return pc + signed(immediate, 21)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--entry', type=Path, required=True, help='Exact original pinned DarwinBoot Entry.S')
    parser.add_argument('--already-overlaid', action='store_true', help='Check an already overlaid isolated Entry.S')
    parser.add_argument('--edk2', type=Path, required=True, help='Mu tree with real MdePkg headers')
    parser.add_argument('--aarch64-cc', required=True, help='Clang with AARCH64 Windows target')
    parser.add_argument('--objdump', required=True, help='llvm-objdump executable')
    args = parser.parse_args()
    supplied = args.entry.read_bytes()
    original = supplied
    if args.already_overlaid:
        for marker in (b'4:\n', OVERLAY.SELF_CLEAN.encode('ascii'), b'5:\n'):
            if original.count(marker) != 1:
                raise ValueError('Already-overlaid Entry.S is missing a unique diagnostic marker')
            original = original.replace(marker, b'', 1)
    assert OVERLAY.sha(original) == OVERLAY.ORIGINAL_SHA256
    patched = OVERLAY.transform(original)
    if args.already_overlaid:
        assert supplied == patched, 'Already-overlaid source differs from the exact expected overlay'
    assert OVERLAY.transform(original) == patched
    for changed in (original + b' ', original.replace(b'tlbi vmalle1', b'nop'),
                    original.replace(b'  dsb sy\n  ic iallu\n', b'  dsb ish\n  ic iallu\n'),
                    original.replace(b'\n', b'\r\n'), patched):
        expect_rejected(lambda changed=changed: OVERLAY.transform(changed))
    tail = original[original.index(b'  ic iallu\n'):]
    assert patched[patched.index(b'  ic iallu\n'):].replace(b'5:\n', b'', 1) == tail
    assert patched.replace(b'4:\n', b'', 1).replace(OVERLAY.SELF_CLEAN.encode(), b'', 1).replace(b'5:\n', b'', 1) == original
    include = args.edk2.resolve() / 'MdePkg/Include'
    assert (include / 'AArch64/AsmMacroLib.h').is_file()
    with tempfile.TemporaryDirectory(prefix='sheng-handoff-clean-') as directory:
        work = Path(directory)
        source = work / OVERLAY.ENTRY_SOURCE
        source.parent.mkdir(parents=True)
        source.write_bytes(original)
        provenance = OVERLAY.apply(work)
        assert source.read_bytes() == patched
        assert provenance['original_sha256'] == OVERLAY.ORIGINAL_SHA256
        assert provenance['overlay_sha256'] == OVERLAY.sha(patched)
        expect_rejected(lambda: OVERLAY.apply(work))
        assert source.read_bytes() == patched
        source.write_bytes(original + b' ')
        expect_rejected(lambda: OVERLAY.apply(work))
        assert source.read_bytes() == original + b' '
        objects, disassemblies, functions = {}, {}, {}
        for label, blob in (('original', original), ('overlay', patched)):
            entry = work / (label + '.S')
            obj = work / (label + '.obj')
            entry.write_bytes(blob)
            subprocess.run([args.aarch64_cc, '--target=aarch64-unknown-windows', '-x', 'assembler-with-cpp',
                            '-ffreestanding', '-Werror', '-Wall', '-Wextra', '-D__ASSEMBLER__',
                            # EDK's generated AutoGen.h supplies these COFF ABI
                            # macros; Base.h contains C types, not assembly.
                            '-DASM_PFX(Name)=Name', '-D_ASM_TYPE(Name)=', '-DAARCH64_BTI(Type)=',
                            '-I', str(include), '-I', str(include / 'AArch64'),
                            '-c', str(entry), '-o', str(obj)], check=True)
            objects[label] = obj
            disassemblies[label] = subprocess.check_output([args.objdump, '-d', str(obj)], text=True)
            functions[label] = coff_function(obj, 'DarwinEnter')
        before, after = functions['original'], functions['overlay']
        assert len(before) == 0x94 and len(after) == len(before) + 32
        assert coff_function(objects['original'], 'DarwinCurrentEl') == coff_function(objects['overlay'], 'DarwinCurrentEl')
        assert before[:0x60] == after[:0x60], 'Original paint and owned kernel clean bytes changed'
        assert before[0x60:] == after[0x80:], 'Original IC/SCTLR/TLBI/branch suffix bytes changed'
        decoded = instructions(disassemblies['overlay'], 'DarwinEnter')
        new = [entry for entry in decoded if 0x60 <= entry[0] < 0x80]
        assert len(new) == 8
        words = [struct.unpack_from('<I', after, 0x60 + i * 4)[0] for i in range(8)]
        assert adr_target(words[0], 0x60) == 0 and words[0] & 31 == 12
        assert adr_target(words[1], 0x64) == len(after) and words[1] & 31 == 13
        assert words[2:] == [0x8a27018c, 0xd50b7a2c, 0x8b06018c, 0xeb0d019f, 0x54ffffa3, 0xd5033f9f]
        assert [' '.join(operation.split()) for _, _, operation in new][3] == 'dc cvac, x12'
        # Inspect the actual new instruction operands as well as exact opcodes.
        written = []
        for _, _, operation in new:
            mnemonic, *operands = operation.split(None, 1)
            if mnemonic in ('adr', 'bic', 'add'):
                written.append(operands[0].split(',')[0])
        assert written == ['x12', 'x13', 'x12', 'x12']
        assert not any(register in written for register in ('x0', 'x1', 'x2', 'x3'))
        assert before[-32:] == after[-32:]
        assert int.from_bytes(after[-16:-12], 'little') == 0xd508871f, 'TLBI VMALLE1 changed'
        # Model addresses from both ADR instructions, line alignment and the
        # do/while DC CVAC loop. Compare against every byte's required line.
        cases = 0
        for line in (16, 32, 64, 128, 256, 512, 1024, 2048):
            for start in range(0x100000, 0x100000 + line):
                end = start + len(after)
                cursor = start & ~(line - 1)
                visited = []
                while True:
                    visited.append(cursor)
                    cursor += line
                    if cursor >= end:
                        break
                required = sorted({address & ~(line - 1) for address in range(start, end)})
                assert visited == required
                assert all(address < end and address + line > start for address in visited)
                cases += 1
        # Cover end-on-boundary and straddling cases explicitly at 64B.
        for start, size in ((0x1000, 64), (0x1001, 63), (0x103f, 2), (0x1040, 128)):
            visited = list(range(start & ~63, start + size, 64))
            assert visited == sorted({address & ~63 for address in range(start, start + size)})
            cases += 1
        print(json.dumps(dict(status='passed', original_sha256=OVERLAY.sha(original),
                              overlay_sha256=OVERLAY.sha(patched), source_drift_and_duplicate_rejected=True,
                              target='aarch64-unknown-windows', original_enter_bytes=len(before),
                              overlay_enter_bytes=len(after), original_prefix_identical=True,
                              original_terminal_suffix_identical=True, new_loop_bytes=32,
                              new_register_writes=written, cache_range_cases=cases,
                              no_device_or_firmware_build=True), indent=2))


if __name__ == '__main__':
    main()
