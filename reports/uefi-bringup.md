# Staged firmware bring-up

The current development gate is a stable, interactive UEFI probe. A successful
build or Fastboot `OKAY` response does not establish firmware execution.

| Stage | Observable result before continuing |
| --- | --- |
| 0. Stock baseline | Official Android starts normally on three starts and the host detects Fastboot. Keep the bootloader unlocked. |
| 1. Standalone UEFI | Matching probe build ID, visible heartbeat for at least 300 one-second timer ticks, a received physical key, three cold boots and a demonstrated return to Fastboot. |
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
The 300 timer ticks are a conservative observation interval, not proof of three
cold boots or of visible output. Those checks remain manual.

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
That local recovery package is not a build input or a claimed successful boot.

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
visible picture and responding volume keys. The owner subsequently confirmed the SHENG UEFI PROBE interface, a heartbeat
above 300 and continuously responsive keys without a reset. Exact build-ID
readback, hardware Fastboot recovery and three cold boots remain pending. The result establishes
the container-version difference for this image and restored bootloader; it
does not identify which internal ABL check caused the v0 failure.

`build-uefi-probe.py` now overrides `header_version=4` and `pagesize=4096` in
its isolated in-memory board copy. It records the override and effective image
settings in the manifest and checks the resulting header version. Repository
`board.toml`, firmware inputs, compression, BootShim and drivers are unchanged.
The independent build output still starts with no claimed hardware observations.

## Device evidence to collect

For each of the three runs, save the image hash and manifest, photograph the
matching build ID and final run screen, record the physical key response and
observe at least five minutes without a reset. Return manually to Fastboot and
save host detection. Record failures and the last visible checkpoint before
changing one input at a time. Do not mark stage 1 passed from the build report.

Start input testing with a short volume-down press (`SCAN=0002`), followed by
volume-up (`SCAN=0001`), and watch the `KEYS` count and `LAST` field. The
unconditional `ShengKeyInputDxe` supplies this path in the minimal firmware;
its SPMI access still requires device verification. A short power press maps
to return (`CHAR=000D`). The minimal branch does not initialize USB host
hardware, and the framebuffer serial library cannot receive characters, so
USB keyboard support and the character commands `C/R/Y` are not acceptance
requirements. Use the device's hardware combination to return to Fastboot.

If `fastboot boot` also rejects the corresponding stock boot image, investigate
that boot method first. A `Load Error` alone does not identify a UEFI driver
failure. The historical notes in ignored output directories are not evidence
for a newly built probe.
