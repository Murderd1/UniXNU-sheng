"""Apply the isolated DarwinEnter self-code clean-to-PoC diagnostic overlay.

Only the pinned assembly source is accepted. The normal build is unaffected
unless its caller explicitly invokes apply() on an isolated DarwinBoot tree.
"""
import hashlib
from pathlib import Path


ENTRY_SOURCE = Path('DarwinBootPkg/Driver/Entry.S')
PINNED_REVISION = '8544957e04bdc43e2aac9243764ac16979f15c42'
ORIGINAL_SHA256 = '44c05d16af1fbe51cfdcf074ff590ec214dbe3e8efdc4b83a9d06f7e49be44bd'
START_ANCHOR = 'ASM_FUNC(DarwinEnter)\n'
CLEAN_ANCHOR = '  b.lo 1b\n  dsb sy\n  ic iallu\n'
END_ANCHOR = '  br x1\n'
SELF_CLEAN = ('  adr x12, 4b\n'
              '  adr x13, 5f\n'
              '  bic x12, x12, x7\n'
              '6:\n'
              '  dc cvac, x12\n'
              '  add x12, x12, x6\n'
              '  cmp x12, x13\n'
              '  b.lo 6b\n'
              '  dsb sy\n')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def transform(original):
    """Return exact overlay bytes, refusing source drift or repeated application."""
    if sha(original) != ORIGINAL_SHA256:
        raise ValueError('DarwinEnter overlay requires the exact pinned Entry.S SHA256')
    text = original.decode('ascii')
    for anchor in (START_ANCHOR, CLEAN_ANCHOR, END_ANCHOR):
        if text.count(anchor) != 1:
            raise ValueError('DarwinEnter overlay anchor is not unique: ' + repr(anchor))
    text = text.replace(START_ANCHOR, START_ANCHOR + '4:\n', 1)
    text = text.replace(CLEAN_ANCHOR, '  b.lo 1b\n  dsb sy\n' + SELF_CLEAN + '  ic iallu\n', 1)
    text = text.replace(END_ANCHOR, END_ANCHOR + '5:\n', 1)
    return text.encode('ascii')


def apply(darwin: Path) -> dict:
    """Mutate only the isolated checkout's pinned Entry.S and return provenance."""
    source = Path(darwin).resolve() / ENTRY_SOURCE
    original = source.read_bytes()
    overlay = transform(original)
    source.write_bytes(overlay)
    return dict(kind='darwin-enter-self-code-clean-to-poc', source_path=str(source),
                source_relative=ENTRY_SOURCE.as_posix(), source_revision=PINNED_REVISION,
                original_sha256=sha(original), overlay_sha256=sha(overlay),
                old_text_sha256=sha(original.decode('ascii').encode('utf-8')),
                new_text_sha256=sha(overlay.decode('ascii').encode('utf-8')),
                description='Clean the complete executing DarwinEnter code range to PoC with DC CVAC '
                            'after the existing owned-memory clean and before IC IALLU. Preserve the '
                            'original kernel clean, SCTLR M/C/I disable, TLBI and terminal branch sequence.')
