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

The owner restored Android independently. A read-only ADB check on 2026-11-14
reported product `sheng`, build `OS3.0.303.0.WNXCNXM`, `sys.boot_completed=1`,
`ro.boot.flash.locked=0`, and `ro.boot.vbmeta.device_state=unlocked`. No new
device boot or partition write has been performed by this implementation.
The supplied recovery directory is `sheng_images_OS3.0.303.0.WNXCNXM_16.0`;
its `misc.txt` identifies sheng and the CN build, and its anti version is 1.
That local recovery package is not a build input or a claimed successful boot.

The owner subsequently chose to retain the repository's international firmware
input. `board.toml` remains pinned to `OS3.0.305.0.WNXMIXM`, archive SHA-256
`c6259e1c8dd89b5b16d086cbdda5d21083c2ca445dd4cde4c8917139f490c7ed`.
UniXNU's documentation does not require that region. Record the recovery
baseline and firmware input separately; their compatibility is not established
by this host implementation.

## Device evidence to collect

For each of the three runs, save the image hash and manifest, photograph the
matching build ID and final run screen, record the physical key response and
observe at least five minutes without a reset. Return manually to Fastboot and
save host detection. Record failures and the last visible checkpoint before
changing one input at a time. Do not mark stage 1 passed from the build report.

If `fastboot boot` also rejects the corresponding stock boot image, investigate
that boot method first. A `Load Error` alone does not identify a UEFI driver
failure. The historical notes in ignored output directories are not evidence
for a newly built probe.
