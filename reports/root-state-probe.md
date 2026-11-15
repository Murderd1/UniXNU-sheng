# Delayed root startup state

The repaired-root media report identifies the expected OS, SystemOS and Data
seed volumes. It does not report filesystem mounts or launchd. Use the separate
`--stage full --root-state-probe --handoff-code-clean` diagnostic to sample the
existing kernel checkpoint globals after a bounded delay.

This mode retains the exact accepted 775-byte handoff and appends only
` native-ufs-probe=13 native-ufs-stats-delay=30`. The result is 821 ASCII bytes,
SHA-256 `6ed5ed7278c0bb48b31555341c66c7465e40f8313be59fd1e5b331ce7ea85b10`.
It preserves `log=0 data-persist=0`; it adds no Data reset or initialization.
It is mutually exclusive with the metadata, media and ordinary full-root
trials and requires manual confirmation of `RUN ROOT STATE ONCE`.

The diagnostic modifies a copy of the actual accepted kernel, whose SHA-256
is `b8d0e71ccceffbb13023b8343a633db5f9f7b16de058b42d263c5d7c118a1c92`.
It reuses the existing probe-13 thread and its delay argument. Only that
thread's second instruction and an explicitly checked unused code range may
change. Its original PAC entry and all storage, matching, authentication,
mount and process-startup paths remain intact. All FAT files other than this
same-size kernel remain byte-for-byte equal to the media baseline.

After waiting, the thread reads existing diagnostic globals, builds a bounded
text report and deliberately stops through the existing panic display. The
report is a sequence of passive reads, not an atomic snapshot. An earlier
kernel panic can stop the system before this delayed report appears.

Interpret the checkpoint groups separately:

- Root: selected and mounted devices, read-only state, Apple authentication
  error and the owner authorization/acceptance decision.
- SystemOS: preparation stage, mount result, authorized/read-only state and
  selected/mounted devices. A zero final status and stage 6 establish more
  than media discovery alone.
- Data: preparation stage, final status and actual mount device/read-only
  state. Stage 2 can mean the writable mount is still in progress; stage 4
  with status zero records the completed Data checks.
- I/O and processes: root stage and counters, RAM block counters, persistent
  store writes/syncs and process count. A process count alone does not prove
  launchd completed startup.

The large seed's persistence-disabled write path returns NotReady before
incrementing its ordinary write/failure counters. Zero counters therefore
do not establish that no Data write request was attempted. Keep this known
blind spot with any photographed report.

This is a diagnostic build contract. Host checks, a successful cloud build
and Fastboot acceptance remain separate from actual device evidence.

If the original complete-package artifact has expired, the state diagnostic
can take `--full-media-baseline` instead of `--full-package`. This entry is
restricted to the accepted probe-12 artifact: it verifies its fixed boot
image, source identity and exact original FAT/payload hashes before extracting
the kernel. It preserves the original input provenance and reports the media
artifact as its immediate source. It does not recreate or claim to download
the missing original package. Both sources must produce the identical patched
FAT for the same small-probe compiler.
