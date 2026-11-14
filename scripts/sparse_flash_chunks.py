"""Lazily make bounded-write Android sparse shards. Never invokes a device tool.

Each shard retains the complete logical image length. DONT_CARE chunks locate
one contiguous RAW/FILL window; they are not a request to erase its complement.
The target sparse implementation must preserve skipped blocks across flashes.
Source identity checks detect ordinary replacement/modification, not an attacker
able to change bytes while restoring all filesystem identity/timestamp fields.
"""
from bisect import bisect_right
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import struct


MAGIC = 0xED26FF3A
RAW, FILL, DONT_CARE = 0xCAC1, 0xCAC2, 0xCAC3
HEADER = struct.Struct('<IHHHHIIII')
CHUNK = struct.Struct('<HHII')
IO_BYTES = 1024 * 1024
MAX_WRITE_BYTES = 512 * 1024 * 1024


def _identity(stat):
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)


def _read_exact(handle, count):
    data = handle.read(count)
    if len(data) != count:
        raise ValueError('Truncated sparse data')
    return data


def _header(data):
    magic, major, minor, size, chunk_size, block, blocks, chunks, checksum = HEADER.unpack(data)
    if (magic, major, minor, size, chunk_size) != (MAGIC, 1, 0, HEADER.size, CHUNK.size):
        raise ValueError('Unsupported sparse header/version/header sizes')
    if block < 4 or block % 4 or not blocks or not chunks or checksum:
        raise ValueError('Invalid geometry, empty image, or unsupported image checksum')
    return block, blocks, chunks


@dataclass(frozen=True)
class Extent:
    kind: int
    start_bytes: int
    end_bytes: int
    data_offset: int
    fill: bytes | None = None


class SparseSource:
    """Validate a RAW/FILL-only v1 sparse file without reading its RAW payloads."""

    def __init__(self, path):
        self.path = Path(path).resolve(strict=True)
        self._identity = _identity(self.path.stat())
        self.file_bytes = self._identity[2]
        extents = []
        with self.path.open('rb') as handle:
            self._check(handle)
            self.block_bytes, self.total_blocks, chunks = _header(_read_exact(handle, HEADER.size))
            self.expanded_bytes = self.block_bytes * self.total_blocks
            logical = 0
            # Every chunk has a header; reject impossible counts before looping.
            if chunks > (self.file_bytes - HEADER.size) // CHUNK.size:
                raise ValueError('Chunk count exceeds file size')
            for _ in range(chunks):
                kind, reserved, blocks, size = CHUNK.unpack(_read_exact(handle, CHUNK.size))
                if reserved or not blocks or kind not in (RAW, FILL):
                    raise ValueError('Source requires nonempty RAW/FILL chunks only')
                length = blocks * self.block_bytes
                expected = CHUNK.size + (length if kind == RAW else 4)
                if size != expected or logical + length > self.expanded_bytes:
                    raise ValueError('Invalid source chunk size or logical bounds')
                offset = handle.tell()
                if offset + size - CHUNK.size > self.file_bytes:
                    raise ValueError('Source payload exceeds file size')
                fill = _read_exact(handle, 4) if kind == FILL else None
                if kind == RAW:
                    handle.seek(length, os.SEEK_CUR)
                extents.append(Extent(kind, logical, logical + length, offset, fill))
                logical += length
            if logical != self.expanded_bytes or handle.tell() != self.file_bytes:
                raise ValueError('Source total blocks or physical length mismatch')
            self._check(handle)
        self.extents = tuple(extents)
        self._starts = tuple(extent.start_bytes for extent in extents)

    def _check(self, handle=None):
        if _identity(self.path.stat()) != self._identity:
            raise ValueError('Sparse source identity/size/timestamps changed')
        if handle is not None and _identity(os.fstat(handle.fileno())) != self._identity:
            raise ValueError('Opened sparse source differs from validated source')

    def assert_unchanged(self):
        self._check()

    def _bounds(self, start, end):
        if (not isinstance(start, int) or not isinstance(end, int) or
                not 0 <= start < end <= self.expanded_bytes or
                start % self.block_bytes or end % self.block_bytes or
                end - start > MAX_WRITE_BYTES):
            raise ValueError('Window must be aligned, in bounds, and at most 512 MiB')

    def _spans(self, start, end):
        index = max(0, bisect_right(self._starts, start) - 1)
        while index < len(self.extents):
            extent = self.extents[index]
            if extent.start_bytes >= end:
                return
            left, right = max(start, extent.start_bytes), min(end, extent.end_bytes)
            if left < right:
                yield extent, left, right
            index += 1

    def ranges(self, max_write_bytes=MAX_WRITE_BYTES):
        if (not isinstance(max_write_bytes, int) or not 0 < max_write_bytes <= MAX_WRITE_BYTES or
                max_write_bytes % self.block_bytes):
            raise ValueError('Write limit must be block aligned and at most 512 MiB')
        self._check()
        for start in range(0, self.expanded_bytes, max_write_bytes):
            yield start, min(start + max_write_bytes, self.expanded_bytes)

    def write_shard(self, start, end, path):
        self._bounds(start, end)
        self._check()
        destination = Path(path)
        spans = list(self._spans(start, end))
        chunk_count = len(spans) + int(start > 0) + int(end < self.expanded_bytes)
        digest = hashlib.sha256()
        file_bytes = 0
        created = False

        def emit(handle, data):
            nonlocal file_bytes
            handle.write(data)
            digest.update(data)
            file_bytes += len(data)

        try:
            with self.path.open('rb') as source, destination.open('xb') as target:
                created = True
                self._check(source)
                emit(target, HEADER.pack(MAGIC, 1, 0, HEADER.size, CHUNK.size,
                                         self.block_bytes, self.total_blocks, chunk_count, 0))
                if start:
                    emit(target, CHUNK.pack(DONT_CARE, 0, start // self.block_bytes, CHUNK.size))
                for extent, left, right in spans:
                    length = right - left
                    encoded = CHUNK.size + (length if extent.kind == RAW else 4)
                    emit(target, CHUNK.pack(extent.kind, 0, length // self.block_bytes, encoded))
                    if extent.kind == FILL:
                        emit(target, extent.fill)
                    else:
                        source.seek(extent.data_offset + left - extent.start_bytes)
                        remaining = length
                        while remaining:
                            data = _read_exact(source, min(remaining, IO_BYTES))
                            emit(target, data)
                            remaining -= len(data)
                if end < self.expanded_bytes:
                    emit(target, CHUNK.pack(DONT_CARE, 0,
                                           (self.expanded_bytes - end) // self.block_bytes, CHUNK.size))
                self._check(source)
            self._check()
        except BaseException:
            # Remove only a partial file created by this invocation, never an existing path.
            if created:
                destination.unlink(missing_ok=True)
            raise
        return dict(kind='bounded-write-sparse-shard', source=str(self.path), path=str(destination.resolve()),
                    block_bytes=self.block_bytes, total_blocks=self.total_blocks,
                    expanded_bytes=self.expanded_bytes, start_bytes=start, end_bytes=end,
                    write_bytes=end - start, file_bytes=file_bytes, sha256=digest.hexdigest(),
                    prefix_skip_bytes=start, suffix_skip_bytes=self.expanded_bytes - end)


def _compare_raw(source, original, shard, digest, start, end):
    """Compare one RAW output stream with source spans, using at most 1 MiB per read."""
    for extent, left, right in source._spans(start, end):
        if extent.kind == RAW:
            original.seek(extent.data_offset + left - extent.start_bytes)
        remaining = right - left
        while remaining:
            count = min(remaining, IO_BYTES)
            actual = _read_exact(shard, count)
            digest.update(actual)
            expected = (_read_exact(original, count) if extent.kind == RAW
                        else extent.fill * (count // 4))
            if actual != expected:
                raise ValueError('Shard RAW bytes differ from source')
            remaining -= count


def _compare_fill(source, original, pattern, start, end):
    """Compare FILL intervals symbolically; never expand a large source FILL."""
    for extent, left, right in source._spans(start, end):
        if extent.kind == FILL:
            if extent.fill != pattern:
                raise ValueError('Shard FILL pattern differs from source')
            continue
        original.seek(extent.data_offset + left - extent.start_bytes)
        remaining = right - left
        while remaining:
            count = min(remaining, IO_BYTES)
            if _read_exact(original, count) != pattern * (count // 4):
                raise ValueError('Shard FILL differs from source RAW bytes')
            remaining -= count


def verify_shard(source, start, end, path):
    """Independently parse a shard and prove its sole explicit window equals source.

    SHA256 covers encoded shard bytes. FILL equivalence is checked by interval
    and four-byte pattern, rather than hashing hundreds of GiB of expanded zeros.
    This does not assert that a particular bootloader preserves DONT_CARE blocks.
    """
    if not isinstance(source, SparseSource):
        raise TypeError('source must be a validated SparseSource')
    source._bounds(start, end)
    source._check()
    path = Path(path)
    target_identity = _identity(path.stat())
    digest = hashlib.sha256()
    explicit_start = explicit_end = None
    explicit_bytes = 0
    with source.path.open('rb') as original, path.open('rb') as shard:
        source._check(original)
        if _identity(os.fstat(shard.fileno())) != target_identity:
            raise ValueError('Shard changed while opening')
        header = _read_exact(shard, HEADER.size)
        digest.update(header)
        block, total, chunks = _header(header)
        if (block, total) != (source.block_bytes, source.total_blocks):
            raise ValueError('Shard does not retain complete source geometry')
        if chunks > (target_identity[2] - HEADER.size) // CHUNK.size:
            raise ValueError('Shard chunk count exceeds file size')
        cursor = 0
        for _ in range(chunks):
            raw_header = _read_exact(shard, CHUNK.size)
            digest.update(raw_header)
            kind, reserved, blocks, size = CHUNK.unpack(raw_header)
            if reserved or not blocks or kind not in (RAW, FILL, DONT_CARE):
                raise ValueError('Invalid shard chunk type, reserved bits, or empty chunk')
            right = cursor + blocks * block
            if right > source.expanded_bytes:
                raise ValueError('Shard chunk exceeds logical image')
            expected_size = CHUNK.size + (right - cursor if kind == RAW else 4 if kind == FILL else 0)
            if size != expected_size or shard.tell() + size - CHUNK.size > target_identity[2]:
                raise ValueError('Invalid shard chunk length')
            if kind == DONT_CARE:
                if cursor < end and right > start:
                    raise ValueError('DONT_CARE intersects required explicit window')
            else:
                if cursor < start or right > end:
                    raise ValueError('Shard explicitly writes outside requested window')
                if explicit_end is not None and cursor != explicit_end:
                    raise ValueError('Shard explicit window is not contiguous')
                if explicit_start is None:
                    explicit_start = cursor
                explicit_end = right
                explicit_bytes += right - cursor
                if kind == RAW:
                    _compare_raw(source, original, shard, digest, cursor, right)
                else:
                    pattern = _read_exact(shard, 4)
                    digest.update(pattern)
                    _compare_fill(source, original, pattern, cursor, right)
            cursor = right
        if (cursor != source.expanded_bytes or shard.tell() != target_identity[2] or
                (explicit_start, explicit_end, explicit_bytes) != (start, end, end - start)):
            raise ValueError('Shard total length or unique explicit window mismatch')
        source._check(original)
        if (_identity(os.fstat(shard.fileno())) != target_identity or
                _identity(path.stat()) != target_identity):
            raise ValueError('Shard changed during verification')
    source._check()
    return dict(status='passed', kind='sparse-shard-equivalence', path=str(path.resolve()),
                block_bytes=block, total_blocks=total, expanded_bytes=source.expanded_bytes,
                start_bytes=start, end_bytes=end, write_bytes=explicit_bytes,
                file_bytes=target_identity[2], sha256=digest.hexdigest(),
                unique_contiguous_explicit_window=True, source_equivalent=True,
                fill_compared_without_expansion=True, device_behavior_verified=False)
