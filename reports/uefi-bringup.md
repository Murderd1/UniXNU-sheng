# Staged firmware bring-up

Stage 1 passed one complete device run under the owner's acceptance requirement.
Development continues with the menu and file-reading stage. A successful build
or Fastboot `OKAY` response alone does not establish firmware execution.

| Stage | Observable result before continuing |
| --- | --- |
| 0. Stock baseline | Official Android starts normally and the host detects Fastboot. One complete successful check is sufficient. Keep the bootloader unlocked. |
| 1. Standalone UEFI | One complete successful run with a matching probe build ID, visible heartbeat for at least 300 one-second timer ticks, a received physical key and a demonstrated return to Fastboot. Passed on the tested v4 candidate. |
| 2. Menu and payload | UniXNU reads its configuration and referenced payload files; missing files and drivers produce visible errors. |
| 3. Kernel handoff | DarwinBoot validates the inputs and XNU reaches its entry and platform initialization checkpoints. |
| 4. Storage and userland | Root and Data are available and launchd starts. |
| 5. Desktop and peripherals | Verify display, input, GPU, USB, network and audio separately. |

Freeze the source revisions, firmware inputs, image SHA-256 and observations
after each passed gate. A later stage must retain a route back to that image.

## Independent firmware image

`scripts/build-uefi-probe.py` and `.github/workflows/uefi-probe.yml` select the
standalone `package/UefiProbe` application. The probe deliberately shares the
normal UniXNU application's FV GUID so the existing UniXNUDxe boot registration
finds it. The isolated DSC and FDF contain one application with that GUID and no
DarwinBoot. The source checkouts and normal packaging entry point remain intact.

The application draws an embedded bitmap font through GOP and reports
`APP_ENTRY`, `GOP_READY`, `MENU_READY`, heartbeat and key events. It neither opens
a filesystem nor launches another image. Missing GOP/input, timer failure and
watchdog-disable failure prevent a run from satisfying its internal checks.
The 300 timer ticks are a conservative observation interval. Visible output,
the matching build ID, physical input and the return to Fastboot require device
observations. One complete successful run is sufficient for acceptance.

The build adds SEC, DXE registration and BDS stage markers to isolated sources.
The pinned platform maps early DEBUG output to FrameBufferSerialPortLib.
Photograph or record those screens: they are not a physical UART capture.
BootShim has no usable early output in this recipe. A blank screen therefore
cannot by itself distinguish an unexecuted firmware from a broken display
handoff. The manifest reports this limitation and starts with no observed
checkpoints. The ABL splash-region fixup is preserved when packing the image.

## Baseline and input versions

The owner restored Android independently. An initial read-only ADB check on 2026-11-14
reported product `sheng`, build `OS3.0.303.0.WNXCNXM`, `sys.boot_completed=1`,
`ro.boot.flash.locked=0`, and `ro.boot.vbmeta.device_state=unlocked`.
Three subsequent ordinary Android reboots each reached `sys.boot_completed=1`
with a fresh kernel boot ID and the boot animation stopped, in about 30 seconds.
Saved screenshots show the stock lock screen. Fastboot then reported product
`sheng`, active slot `a`, `unlocked=yes`, and `is-userspace=no`.
Temporary boot of the matching CN stock image (header v4, SHA-256
`4156a2369f78bc5df61b6a521b07a508dedf20d5e63c207d30986ae37df3eaea`)
succeeded and Android completed a fresh boot. These tests used reboot and
temporary boot commands; no partition-write command was issued.
The supplied recovery directory is `sheng_images_OS3.0.303.0.WNXCNXM_16.0`;
its `misc.txt` identifies sheng and the CN build, and its anti version is 1.
That local recovery package is separate from the pinned firmware build input;
the successful stock temporary boot above used its matching `boot.img`.

The owner subsequently chose to retain the repository's international firmware
input. `board.toml` remains pinned to `OS3.0.305.0.WNXMIXM`, archive SHA-256
`c6259e1c8dd89b5b16d086cbdda5d21083c2ca445dd4cde4c8917139f490c7ed`.
UniXNU's documentation does not require that region. Record the recovery
baseline and firmware input separately; their compatibility is not established
by this host implementation.

## Built probe evidence

[Actions run 43557744330](https://github.com/Murderd1/UniXNU-sheng/actions/runs/43557744330)
completed the full DEBUG build at device revision
`9499728d6e7082da5840fa3d6a99b87a1654e9d5`. Its
[artifact](https://github.com/Murderd1/UniXNU-sheng/actions/runs/43557744330/artifacts/14099800179)
contains the following frozen outputs:

| Output | Bytes | SHA-256 |
| --- | ---: | --- |
| `boot.img` | 1150976 | `3f3a6b44a29036bc2c57a6fba42f4fdd01ab0b77b1d40d3ab05114b37792a046` |
| `SILICIUM_UEFI.fd` | 3145728 | `619582c6e7d0d774883341394dcc027165a9c46d3f756e88564218f21d3b05e7` |

The displayed build ID is
`sheng-uefi-9499728d6e70-61606b656389-20261114T044040Z`.
The decompressed FV contains the probe application and its build ID; 55 FFS
files and 32 APRIORI references were checked with no dangling references.
The selected minimal firmware contains no vendor modules requiring byte
comparison. Independent Windows checks passed all seven checksum entries,
zero ramdisk, the ARM64 shim header, exact embedded FD equality and the
appended DTB's `cont_splash_region` label and reservation.

The original v0 image returned sending/booting `OKAY`, but the owner observed a
black screen and Fastboot still responded immediately to `getvar product`.
This image failed the visible-interface gate. Android recovered normally
through `fastboot reboot`.

A single-variable comparison replaced only the 4096-byte Android header page
with a v4 header, preserving every following byte: gzip data, BootShim, FD,
appended DTB and padding. The candidate image is 1150976 bytes, SHA-256
`3eb9c7c59fccdff2505050ef11f487399d9c63cc5e2813210f4013941e6e6c27`.
At 2026-11-14 05:05 UTC it was temporarily booted; the owner then reported a
visible picture and responding volume keys. The owner subsequently confirmed
the SHENG UEFI PROBE interface, the matching displayed build ID, a heartbeat
above 300 and continuously responsive keys without a reset. Return to Fastboot
using the hardware key combination was demonstrated. The owner accepts one
complete successful run, so stage 1 is passed. Three cold-boot repetitions were
not performed and were explicitly waived; they are not a pending action.
The result establishes the container-version difference for this image and
restored bootloader; it does not identify which internal ABL check caused the
v0 failure.

`build-uefi-probe.py` now overrides `header_version=4` and `pagesize=4096` in
its isolated in-memory board copy. It records the override and effective image
settings in the manifest and checks the resulting header version. Repository
`board.toml`, firmware inputs, compression, BootShim and drivers are unchanged.
The independent build output still starts with no claimed hardware observations.

## Device acceptance record

One complete successful run is the acceptance requirement. Save the image hash
and manifest, the matching displayed build ID and final run screen, the physical
key response, at least 300 advancing one-second heartbeat ticks without a reset,
and the demonstrated hardware return to Fastboot. These checks passed on the
candidate identified above. Three cold-boot repetitions were not performed and
the owner waived them. Record failures and the last visible checkpoint before
changing one input at a time; a build report alone cannot pass this gate.

Start input testing with a short volume-down press (`SCAN=0002`), followed by
volume-up (`SCAN=0001`), and watch the `KEYS` count and `LAST` field. The
unconditional `ShengKeyInputDxe` supplies this path in the minimal firmware;
its physical volume-key input was verified in the accepted run. A short power
press maps to return (`CHAR=000D`). The minimal branch does not initialize USB host
hardware, and the framebuffer serial library cannot receive characters, so
USB keyboard support and the character commands `C/R/Y` are not acceptance
requirements. Use the device's hardware combination to return to Fastboot.

If `fastboot boot` also rejects the corresponding stock boot image, investigate
that boot method first. A `Load Error` alone does not identify a UEFI driver
failure. The historical notes in ignored output directories are not evidence
for a newly built probe.

## Stage 2 implementation

The `--stage menu` variant restores the pinned normal UniXNU application,
retains the minimal hardware path and removes DarwinBoot. It embeds a 4 MiB
FAT16 image in FV RAW file `79D77DA6-3053-4705-9B3C-18750AE7C3F1`.
`ShengMenuDiskDxe` publishes that image as read-only 512-byte Block I/O;
existing DiskIo and FAT drivers provide filesystem access. This avoids an
unproven GKI boot-ramdisk handoff without writing `vendor_boot` or userdata.

The build first compiles HelloPayload, builds the FAT fixture, reads both
files back with mtools, then rebuilds the final FD. Decompressed FV inspection
requires the embedded RAW SHA-256 to match the verified FAT. The manifest
records source, file, volume and final-image hashes and starts without device
observations. Host driver checks cover read boundaries, media errors, write
protection, installation notification and failure cleanup against real headers.

The menu reads `EFI/UniXNU/unixnu.toml` and shows a build-linked title. Its
default item deliberately refers to an absent EFI file. The second item reads
and starts `Payloads/HelloPayload.efi`, which prints the same build ID and
returns after 15 seconds. The third item powers off. Each item requires a
physical confirmation, with countdown and rotation disabled in the isolated
menu source. Missing input cannot select an item automatically.

The isolated research firmware sets `ENABLE_SECUREBOOT=0` to permit the test
file and skips `SetupSecureBoot`, including its key enrollment and filesystem
callback. This does not alter the stock bootloader or repository board file.
No system or kernel is loaded. Stage 2 requires one device run showing the
matching title, physical navigation, a visible Not Found error, file-loaded
Hello build ID and return to the menu. The owner confirmed all of these
observations on the image identified below; stage 2 passed once.


### Stage 2 host build

[Run 43562670561](https://github.com/Murderd1/UniXNU-sheng/actions/runs/43562670561)
completed both DEBUG build passes at source revision
`e48871c4a505247e78059c463feba1861a06efff`. The downloaded artifact passed
all nine checksum entries, v4 header, empty ramdisk, embedded FD byte equality
and splash-region checks. Its build ID is
`sheng-menu-e48871c4a505-cf463b8c91d5-20261114T054147Z`.

| Output | Bytes | SHA-256 |
| --- | ---: | --- |
| `boot.img` | 786432 | `c7b0bf23f71098f9b829a762d41fcf3b81e1f4e274721c00b669d096026ce51a` |
| `SILICIUM_UEFI.fd` | 3145728 | `49523b1f24e516f695f2aecafd0b729a4df5f0147969ca760878e6298380eae4` |
| `menu-volume.img` | 4194304 | `8119d4f85e90aa1d0b935ad11efe6cf1c6202fcf899195df57f8839294a3ff0a` |

The FV inspection found 56 files, 32 APRIORI references with none dangling,
the normal UniXNU app and the exact verified menu FAT. Both files were read
back from FAT byte for byte. A temporary boot command returned `OKAY` at
2026-11-14 05:50 UTC; device menu and file observations are recorded separately.


### Stage 2 device acceptance

The owner confirmed the expected `Sheng Stage 2` title and build ID containing
`e48871c4a505`, all three entries and physical volume-key navigation. Selecting
the missing-file entry and confirming produced a visible `Not Found` error.
Selecting Hello then showed its matching build ID and returned to the menu
after the pause. This is one complete successful device run, as requested by
the owner; stage 2 is passed. No OS or XNU was started and no partition-write
command was issued. The tablet remains at the menu.

Local frozen baselines are `out/baselines/stage-1-passed/` and
`out/baselines/stage-2-passed/`. Each contains the accepted boot image, source
identity, attributed device observations and SHA256SUMS. Build manifests retain
their original host-only evidence flags; later device records are separate.

## Stage 3 complete-kernel trial

The owner requested trying the existing complete kernel before splitting it.
`repack-sheng-full-trial.py` checks the audited package from run 43467452829,
retains its complete kernel, ADT and runtime sidecars, changes the Android
container to v4, removes installation, and requires physical confirmation.
`data-persist=0` closes persistent Data writes and `log=0` closes the native UFS
log/export path in the exact pinned ShengUfs and RamBlock sources. The root
read path and other original peripheral arguments remain selected. Restored
Android userdata lacks the SHNGROOT layout; this trial does not install it.

Independent host comparison found exactly 2175 changed bytes, all within the
Android header, FAT configuration allocation and its file-size field. All
other payload files and the compressed BootShim/FD/DTB field remained equal.
The candidate SHA-256 was
`a28b4ed1d3fa39e141f1608ae4b836188cb309231afc4500e7c25e904db59e12`.
Fastboot accepted the temporary boot. The owner then reported four menu items,
a later failure message and power-off. The intended trial configuration has
two entries and a `Sheng Full Trial` title. The four entries match the built-in
fallback configuration, so payload discovery is the next diagnostic target.
Neither DarwinBoot handoff nor XNU entry was observed.

The independent `full` build variant retains the same full payload and adds a
direct firmware diagnostic application. It reports the raw entry x0, FDT and
initrd range, reserves the incoming buffers before DXE allocation, and checks
the exact FAT boot sector and entire volume before publishing read-only Block
I/O. A vendor ramdisk prefix may precede the FAT; bounded scanning identifies
the expected bytes rather than treating the entire initrd as a FAT volume.
The application stays visible without an automatic boot or shutdown. A
separate physical confirmation can hand the verified full kernel and seed to
the matching DarwinBoot revision. These are implementation details, not device
success evidence; stage 3 remains unpassed until actual kernel observations.

Run 43568622655 stopped in the native macOS application host check at the
positive CanBoot gate; no new firmware or boot image was produced. Windows
MSVC and native Clang simulations passed. The host check now prints every
boot gate and file status on a positive-case failure. The workflow runs it
before large input downloads, and failed logged commands expose their tail.
No boot gate or device acceptance criterion was relaxed.

Run 43570348254 narrowed the native failure to a mocked UTF-16 string length:
the 62-unit safe argument string and its token matches were correct, but
StrLen reported 1386. The host mock now uses explicit 16-bit volatile reads
and tests a terminator followed by nonzero units. Run 43570697123 at source
5c076c6b16b83af99ee762d07207a76ea1462a55 subsequently passed the real macOS
simulation, AARCH64 compilation and complete DEBUG firmware build. The
firmware argument parser and its boot policy have not changed. Its INF uses
the real EDK II BaseLib; the host-only mock is not part of the firmware.

The downloaded run 43570697123 artifact passed all nine checksum entries,
v4 container layout, exact embedded FD equality, appended DTB splash region
and full ramdisk byte comparison. The image is 185315328 bytes, SHA-256
`9337f8a5ada47c4c74d37f7d2d29553e0d43e78886c2e1187950315daea81f8c`;
FD SHA-256 is `3ba871368afe106a08ca85618a05efa73cefbb9e73ee42e5a9b10a332efd691e`.
The build ID is `sheng-full-5c076c6b16b8-fbd906466f38-20261114T072202Z`.
Its 184549376-byte complete FAT is unchanged from the audited trial input
(`f46ba1674303a37e89dd0e8ad24fe54ed43cd63c7dd29001216b87f36634ed68`).
These are host verification results; device transport and XNU remain to be observed.

An independent direct FD decompression confirmed the diagnostic application,
matching build ID, kernel RAM transport driver and DarwinBoot, including the
expected volume digest and read-only handoff arguments. At 2026-11-14 07:42 UTC,
`fastboot -s 33b62981 boot` returned sending and booting OKAY for that image.
The command did not flash a partition. The owner's five diagnostic photos
confirm the matching build, working page navigation and EFI application at EL1.
The FDT at `0xb5e4b000` is valid (`0xe0e6c` bytes); initrd is present and reserved
at `0xb604c000..0xb7fff2e0`. Driver status is `Bad Buffer Size`, range status is
`Success`, and scanned bytes and both candidate counts are zero. This range
contains 33239776 bytes, below the expected 184549376-byte FAT. `FindFat` rejects
it before scanning, rather than finding a FAT with a bad hash. The raw prefix
is `02 21 4c 18 fd 0d 28 00 e0 30 37 30 37 30 31 30` (legacy LZ4).

The restored CN package's padded vendor and generic ramdisks total 33239040
bytes, just 736 bytes below the observed initrd. The size and prefix support
stock ramdisk delivery instead of the supplied complete FAT. This comparison
does not prove which internal ABL branch selected the ramdisk. No verified
filesystem is published; the file rows remain `Not Ready`. The loader status
is also `Not Ready` because the app returns before querying it after volume
failure; it does not establish a DarwinBoot fault. Boot availability is `NO`
and no XNU handoff occurred.

A v3 container comparison keeps every byte of the kernel/FD/DTB and complete
ramdisk unchanged. It changes header size 1584 to 1580, version 4 to 3 and
clears the v4 signature field, then removes its trailing 4096 zero bytes.
The candidate is 185311232 bytes, SHA-256
`da6935c048ace2c4f3f47cc7d73a88c0211a79aeabec6d3752bd43de2ebc104f`.
This is a pending transport experiment, not a passed kernel boot.
