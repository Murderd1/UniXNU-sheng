#!/usr/bin/env python3
"""Host-only synthetic regression checks for lazy bounded-write sparse shards."""
import importlib.util
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('sparse_flash_chunks', ROOT / 'scripts/sparse_flash_chunks.py')
SPARSE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SPARSE
SPEC.loader.exec_module(SPARSE)
BLOCK = 4096


def fixture(parts, block=BLOCK):
    chunks, expanded = [], bytearray()
    for kind, value, blocks in parts:
        length = block * blocks
        if kind == SPARSE.RAW:
            assert len(value) == length
            payload = value
            expanded.extend(value)
        elif kind == SPARSE.FILL:
            assert len(value) == 4
            payload = value
            expanded.extend(value * (length // 4))
        else:
            payload = b''
            expanded.extend(bytes(length))
        chunks.append(SPARSE.CHUNK.pack(kind, 0, blocks, 12 + len(payload)) + payload)
    header = SPARSE.HEADER.pack(SPARSE.MAGIC, 1, 0, 28, 12, block,
                                len(expanded) // block, len(parts), 0)
    return header + b''.join(chunks), bytes(expanded)


def apply_small(shard, disk):
    """Separate tiny reference decoder: DONT_CARE preserves prior disk bytes."""
    data = shard.read_bytes()
    _, _, _, offset, chunk_size, block, total, count, _ = struct.unpack_from('<IHHHHIIII', data)
    assert total * block == len(disk)
    cursor = 0
    for _ in range(count):
        kind, _, blocks, encoded = struct.unpack_from('<HHII', data, offset)
        length = blocks * block
        payload = data[offset + chunk_size:offset + encoded]
        if kind == 0xCAC1:
            disk[cursor:cursor + length] = payload
        elif kind == 0xCAC2:
            disk[cursor:cursor + length] = payload * (length // 4)
        elif kind != 0xCAC3:
            raise AssertionError('unexpected chunk')
        cursor += length
        offset += encoded
    assert cursor == len(disk) and offset == len(data)


class Shards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='check-sparse-shards-', dir=ROOT / 'out')
        self.root = Path(self.temporary.name)
        self.path = self.root / 'source.img'
        parts = [(SPARSE.RAW, bytes(range(256)) * (3 * BLOCK // 256), 3),
                 (SPARSE.FILL, bytes(4), 5),
                 (SPARSE.RAW, b'raw!' * (2 * BLOCK // 4), 2),
                 (SPARSE.FILL, b'\x12\x34\x56\x78', 7)]
        self.encoded, self.expanded = fixture(parts)
        self.path.write_bytes(self.encoded)
        self.source = SPARSE.SparseSource(self.path)

    def tearDown(self):
        self.temporary.cleanup()

    def test_all_shards_compose_exactly_including_nonzero_tail(self):
        disk = bytearray(b'\xa5' * len(self.expanded))
        ranges = list(self.source.ranges(4 * BLOCK))
        self.assertEqual(ranges, [(i * BLOCK, min(i + 4, 17) * BLOCK) for i in range(0, 17, 4)])
        for index, (start, end) in enumerate(ranges):
            path = self.root / f'shard-{index}.img'
            made = self.source.write_shard(start, end, path)
            verified = SPARSE.verify_shard(self.source, start, end, path)
            self.assertEqual(made['sha256'], verified['sha256'])
            self.assertEqual(made['file_bytes'], path.stat().st_size)
            self.assertEqual(verified['expanded_bytes'], len(self.expanded))
            previous = bytes(disk)
            apply_small(path, disk)
            self.assertEqual(disk[:start], previous[:start])
            self.assertEqual(disk[end:], previous[end:])
            self.assertEqual(disk[start:end], self.expanded[start:end])
        self.assertEqual(disk, self.expanded)

    def test_cross_chunk_partial_ranges_and_boundary_ranges(self):
        for index, (left, right) in enumerate([(0, 1), (2, 9), (3, 8), (7, 11), (10, 17), (0, 17)]):
            start, end = left * BLOCK, right * BLOCK
            path = self.root / f'partial-{index}.img'
            self.source.write_shard(start, end, path)
            SPARSE.verify_shard(self.source, start, end, path)

    def test_huge_fill_stays_tiny_and_bounded(self):
        path = self.root / 'huge-source.img'
        blocks = 60912571
        path.write_bytes(SPARSE.HEADER.pack(SPARSE.MAGIC, 1, 0, 28, 12, BLOCK, blocks, 1, 0) +
                         SPARSE.CHUNK.pack(SPARSE.FILL, 0, blocks, 16) + b'abcd')
        source = SPARSE.SparseSource(path)
        ranges = list(source.ranges())
        self.assertEqual(ranges[0], (0, SPARSE.MAX_WRITE_BYTES))
        self.assertEqual(ranges[-1][1], blocks * BLOCK)
        for index in (0, 1, len(ranges) - 1):
            start, end = ranges[index]
            shard = self.root / f'huge-{index}.img'
            source.write_shard(start, end, shard)
            verified = SPARSE.verify_shard(source, start, end, shard)
            self.assertLess(shard.stat().st_size, 100)
            self.assertLessEqual(verified['write_bytes'], SPARSE.MAX_WRITE_BYTES)

    def test_reject_bad_source_headers_chunks_and_dontcare(self):
        bad = [self.encoded[:20], self.encoded + b'extra', self.encoded[:-1]]
        for offset, format_, value in [(0, '<I', 0), (4, '<H', 2), (8, '<H', 32),
                                       (10, '<H', 16), (12, '<I', 3), (16, '<I', 18),
                                       (20, '<I', 999999), (24, '<I', 1),
                                       (28, '<H', 0xCAC3), (28, '<H', 0xCAC4),
                                       (30, '<H', 1), (32, '<I', 0), (36, '<I', 13)]:
            blob = bytearray(self.encoded)
            struct.pack_into(format_, blob, offset, value)
            bad.append(bytes(blob))
        for index, blob in enumerate(bad):
            path = self.root / f'bad-{index}.img'
            path.write_bytes(blob)
            with self.assertRaises(ValueError):
                SPARSE.SparseSource(path)

    def test_refuse_overwrite_and_bad_bounds(self):
        target = self.root / 'existing.img'
        target.write_bytes(b'keep me')
        with self.assertRaises(FileExistsError):
            self.source.write_shard(0, BLOCK, target)
        self.assertEqual(target.read_bytes(), b'keep me')
        for start, end in [(-BLOCK, BLOCK), (0, 1), (1, BLOCK), (0, 0), (BLOCK, 0),
                           (0, len(self.expanded) + BLOCK), (0, SPARSE.MAX_WRITE_BYTES + BLOCK)]:
            with self.assertRaises(ValueError):
                self.source.write_shard(start, end, self.root / 'rejected.img')
            self.assertFalse((self.root / 'rejected.img').exists())
        for limit in (0, -BLOCK, 1, SPARSE.MAX_WRITE_BYTES + BLOCK):
            with self.assertRaises(ValueError):
                list(self.source.ranges(limit))

    def test_reject_drift(self):
        stat = self.path.stat()
        os.utime(self.path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1000000000))
        with self.assertRaises(ValueError):
            self.source.write_shard(0, BLOCK, self.root / 'drift.img')
        self.assertFalse((self.root / 'drift.img').exists())

    def test_verifier_rejects_corruption_and_wrong_window(self):
        path = self.root / 'verified.img'
        self.source.write_shard(2 * BLOCK, 11 * BLOCK, path)
        original = path.read_bytes()
        for offset in (16, 28, 40 + 12 + 123, len(original) - 1):
            blob = bytearray(original)
            blob[offset] ^= 1
            path.write_bytes(blob)
            with self.assertRaises(ValueError):
                SPARSE.verify_shard(self.source, 2 * BLOCK, 11 * BLOCK, path)
        path.write_bytes(original)
        with self.assertRaises(ValueError):
            SPARSE.verify_shard(self.source, 3 * BLOCK, 11 * BLOCK, path)
        path.write_bytes(original + b'trailing')
        with self.assertRaises(ValueError):
            SPARSE.verify_shard(self.source, 2 * BLOCK, 11 * BLOCK, path)

    def test_verifier_rejects_fill_change_and_interior_skip(self):
        path = self.root / 'fill.img'
        self.source.write_shard(10 * BLOCK, 17 * BLOCK, path)
        encoded = bytearray(path.read_bytes())
        # Header, prefix DONT_CARE, FILL header, four-byte pattern.
        encoded[28 + 12 + 12] ^= 1
        path.write_bytes(encoded)
        with self.assertRaises(ValueError):
            SPARSE.verify_shard(self.source, 10 * BLOCK, 17 * BLOCK, path)
        interior, _ = fixture([(SPARSE.RAW, self.expanded[:BLOCK], 1),
                               (SPARSE.DONT_CARE, b'', 1),
                               (SPARSE.FILL, bytes(4), 15)])
        path.write_bytes(interior)
        with self.assertRaisesRegex(ValueError, 'DONT_CARE intersects'):
            SPARSE.verify_shard(self.source, 0, 17 * BLOCK, path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
