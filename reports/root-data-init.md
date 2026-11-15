# First Data overlay initialization

`--stage full --root-data-init --handoff-code-clean` selects an explicit
first-install startup mode. It opens the existing persistent Data backend,
initializes its overlay from the saved seed, and continues normal XNU startup.
It has no intentional diagnostic stop. This is implemented behavior; this
report does not claim a successful host build, device write, resume or desktop.

The fixed 215 GiB seed takes the RamBlock large-disk path. With
`data-persist=0`, reads work but writes return NotReady before ordinary
write/failure counters. This mode enables the existing persistent write path.
Host and device results require their own evidence.

## Exact inputs and arguments

The mode requires the audited full package or the fixed accepted media baseline
used by the root-state workflow. Its FAT must retain SHA-256
`f46ba1674303a37e89dd0e8ad24fe54ed43cd63c7dd29001216b87f36634ed68`.
The original full kernel, ADT, trust cache, packed Data seed and all other FAT
bytes stay unchanged. The root-state diagnostic kernel patch is not applied.
The full-stage Android container remains v3, with the accepted 180-byte
self-cleaning DarwinEnter handoff.

The effective UEFI application handoff is exactly the accepted 775-byte
baseline with its one `data-persist=0` changed to `data-persist=2`, followed by
` data-reset=1`. It is 788 ASCII bytes, SHA-256
`4d84382b8335f5270ecd22166f7065369adcfcd78d19ceee92977a0b414c0ad2`.
`log=0` remains. There is no native UFS probe suffix, delayed diagnostic panic,
`data-reset=2`, `setup=1` or automatic reset option. The canonical string is
`package/UefiKernelProbe/ShengRootDataInitArgs.h`; Python preparation and the
firmware application require that exact string. The FAT configuration remains
the source baseline; the generated manifest distinguishes it from the effective
application handoff.

For local preparation/build, provide one accepted input and a new output path:

```sh
python3 scripts/build-uefi-probe.py --stage full --root-data-init --handoff-code-clean --unixnu ../UniXNU --uefi ../uefi-sheng --full-media-baseline out/root-media-43616475669-1 --output out/root-data-init-001
```

The audited `--full-package` input can replace `--full-media-baseline`.
The mode rejects both inputs together, a non-full stage, missing handoff code
cleaning, drift from the fixed FAT, and combination with any metadata, full-root,
media or state trial. These build commands do not write or boot a device.

In Actions, manually dispatch **UEFI probe**, select `stage=full`, enable
`handoff_code_clean` and `root_data_init`, and leave the other root modes off.
`root_data_init` defaults to false. Push builds do not select it. Mode validation
runs before source preparation or input downloads; invalid combinations stop
there. No first-install write is selected by the automatic diagnostic build.

## Physical selection

The application displays **SHENG FIRST DATA INITIALIZATION** and the matching
build ID. The verified-volume, file and exact-argument gates still apply.
Selecting the startup page opens a confirmation whose initial selection is
**Cancel**. The owner must select **INITIALIZE DATA AND BOOT ONCE** and confirm
with the physical key. The screen states that reset discards existing overlay
changes, enables persistent Data writes and requires later boots to omit reset.
There is no countdown or automatic handoff. Missing input keeps the screen
visible; cancellation does not call the loader. Each accepted confirmation
invokes the loader once, and a returned loader does not automatically retry.

The word ONCE describes that invocation. It does not consume the reset setting
across reboots: booting this initialization image again would reset Data again.
Keep this image separate from the subsequent normal-startup image.

## Store allocation and write effect

The fixed inputs are a 249,497,890,816-byte userdata partition, a 215 GiB logical
Data seed and the unchanged default 1024 MiB end reserve. The store occupies
absolute 4096-byte LBAs 7,382,338..63,745,018, inclusive. In userdata-relative
bytes it is [17,562,607,616, 248,424,148,992). The 15,753,805,824-byte root
allocation ends 1,808,801,792 bytes before the store, exceeding the required
4 MiB guard; the final 1 GiB reserve remains outside the store.

The fixed ShengUfs implementation accepts only mode 2 writes into the opened
LUN 0 store window. Opening requires a ready host, accepted root geometry,
partition/reserve bounds, root clearance, one store opening, 32-bit command
endpoints and no log overlap. Every write rechecks window containment. The
historical quarter-partition comment is not an enforced limit in this source.
Keep `log=0` and the reserve unchanged so the separate log/export writer stays
disabled and the store does not move.

Existing `data-persist=2` without reset preserves a blank/foreign/damaged header
as Kept and cannot make this large disk writable. With reset 1, the existing
overlay implementation writes the zero presence bitmap first, synchronizes,
writes the SHNGDATA header last, then synchronizes again:

| Initial write | Absolute 4 KiB LBAs, inclusive | Bytes |
| --- | --- | ---: |
| Presence bitmap | 7,382,339..7,384,058 | 7,045,120 |
| SHNGDATA header | 7,382,338 | 4,096 |

Initialization totals 7,049,216 bytes, two store API writes and two sync calls.
Transport splitting and retries can issue more commands. Initialization does
not write Data-page blocks, root windows, policy tables, the SHNGROOT manifest
or other partitions. Normal startup then permits additional APFS and service
writes throughout the allocated Data store; the initialization byte count is
not a bound on that later activity.

The header binds the exact logical seed identity
`58f2aecbe9693d1c0344e5dc788c4f546cd0143f47d5710a7615f7d312bd770b`
and 56,360,960 pages. This identity differs from the packed seed file hash.
Fresh initialization sets `native_data_persist_state=3`; a matching later
mode 2 boot without reset resumes directly with state 2. Initialization uses
FUA writes; the existing default write-back and synchronization policy applies
after opening. Successful synchronization and survival across a no-reset reboot
require device evidence.

Retain installation inputs and verify the intended store allocation before
initialization. Do not treat successful Fastboot commands as physical
readback of the storage contents.

## Normal resume, recovery and evidence

Use this mode only for the explicitly authorized first installation or a
separately authorized reset. It discards any existing overlay changes. The
next normal-startup image must keep `data-persist=2` and omit `data-reset`.
The existing `--full-root-trial` deliberately keeps `data-persist=0`, so it is
not a writable-Data resume mode. Reusing the initialization image would discard
the previous run's changes; do not automatically retry it after an unexpected
failure.

Reset starts from the saved immutable seed and requires no root reflash. The
original whole installation image alone would restore the historical vroot
object defect; retain its corrected tables and manifest as recovery inputs too.
Reset invalidates overlay references rather than erasing the page area. A
byte-exact zero-tail rollback after later writes would require a separately
bounded store clear or reinstall plus the retained policy correction.

Before any device execution, save the candidate identity and effective
arguments, retain all inputs and logs, and recheck the intended device and its
userdata geometry. Record actual write errors, visible startup and subsequent
no-reset resume separately. Neither unchanged payload bytes, a host check nor
Fastboot OKAY establishes writable Data, a desktop or durable user files. Earlier device observations remain separate from this new mode.

Implementation references: `scripts/build-uefi-probe.py`,
`scripts/uefi_full_trial.py`, `package/UefiKernelProbe/ShengKernelProbe.c`,
`package/UefiKernelProbe/ShengRootDataInitArgs.h`, and
`.github/workflows/uefi-probe.yml`. Storage behavior is from RamBlock
`60a54ce8f86161db958fd8e6edf577081b3c9ae7` (`NativeRamBlock.cpp`,
`PersistOverlay.h`) and ShengUfs `b11de87c234cf4b8f80a8160fb15e6f37a8e5d0c`
(`NativeUfs.cpp`, `RootCommands.h`). Match these exact source revisions and geometry before device use.
