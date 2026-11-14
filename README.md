# UniXNU sheng

Device support for Xiaomi Pad 6S Pro 12.4, codename `sheng`, with Qualcomm
SM8550. The device profile selects
[UniXNU-sm8550-common](https://github.com/UniXNU/UniXNU-sm8550-common). One
branch builds every OS profile; `--os 17|26|27` picks the target (the 27
profile is the one under active maintenance).

## Structure

| Path | Contents |
| --- | --- |
| `porting.toml` | Subsystem inputs, findings, evidence and completion criteria |
| `board.toml` | Device configuration and component selection |
| `feeds.toml` | Pinned SoC source |
| `configs/sheng_defconfig` | Device kernel settings |
| `dts/sheng.dts` | Memory, CPU selection, and peripheral configuration |
| `patches/xnu/series` | Board patches |
| `proprietary-files.txt` | Firmware input paths |
| `package/` | Device policy, display, input, and diagnostics |
| `scripts/` | Device build and inspection tools |

`Adreno740` and `AdrenoMetal` provide the GPU implementation. Shared GMU,
command database, and GPU SMMU operations are in the SoC repository's
`Sm8550Platform` kit. sheng supplies GPU votes, signed ZAP firmware,
reserved memory, and display integration. GPU initialization uses the
staged platform build. The hardware DTS contains GPU resources; the ADT
exports nodes with `unixnu,adt-name`.

`ShengUfs` includes the device's storage and persistence policy.
`ShengHidInput` and `ShengNovatekTouch` provide the input integration.
`QcomGeniSpi` provides the shared SPI controller interface.
`Ath12kWifi` supplies the Wi-Fi stack through board PCIe, MSI, DMA,
and network interfaces. The payload volume is 208 MiB. The device selects
sRGB display properties and a 120 Hz display timing request.

## Development record

Maintain [porting.toml](porting.toml) with every subsystem change. It records
hardware, configuration, procedures, findings, evidence and completion criteria.
The [device page](https://unixnu.com/devices/sheng) renders this record.
Maintainers and agents follow the [same guide](https://unixnu.com/porting/records).
The required `Porting record` CI check validates structure, component coverage
and updates to findings or evidence for changed code.

This repository owns the ShengUfs, ShengHidInput, ShengNovatekTouch and
ShengPreflight submodules. Shared components come from the selected profiles
and UniXNU catalog. Read the [UFS guide](https://unixnu.com/porting/ufs) before
changing storage resources or policy.

## UEFI bring-up

Use the independent **UEFI probe** Actions workflow while qualifying firmware.
It builds DEBUG firmware and a boot image without a kernel, IPSW, payload,
installation seed or userdata image. It keeps the stock archive pinned in
`board.toml`; the current input is `OS3.0.305.0.WNXMIXM`.
The isolated probe uses an Android v4 boot header. A device comparison with
identical kernel-field bytes showed a black screen with the inherited v0
header and a visible probe with responsive volume keys after changing to v4.

On macOS, with clean checkouts of UniXNU `d830d23b0d19c9322d906c21afeca1d6c54aeffe`
and uefi-sheng `66421cb7bb5694843aec8de1ca3d1de4c20cca38`:

```sh
python3 scripts/build-uefi-probe.py --self-test
python3 scripts/build-uefi-probe.py --unixnu ../UniXNU --uefi ../uefi-sheng --output out/uefi-probe-001
```

Each output directory must be new. The build changes isolated source copies,
embeds the probe instead of the normal boot manager, and removes DarwinBoot.
It produces `boot.img`, `SILICIUM_UEFI.fd`, input hashes, a manifest and logs.
`--prepare-only` prepares sources without importing stock files or compiling.
Host checks and successful builds alone do not establish hardware acceptance.

First restore a matching official Android package, retain the unlocked
bootloader, and verify Android boot and Fastboot detection. One complete
successful probe run satisfies the owner's acceptance requirement: a matching
displayed build ID, at least 300 visible one-second heartbeat ticks, a real key
response and a demonstrated return to Fastboot. Save the image hash and
observations. The tested v4 candidate passed these checks; three cold-boot
repetitions were not performed and the owner waived them. Stage 1 is passed.
The probe stays in UEFI and never starts an OS.
`R` then `Y` requests an ordinary restart; use the hardware key combination
to enter Fastboot. See [the staged bring-up record](reports/uefi-bringup.md).

The test image consumes the board's existing firmware input even when the
Android recovery baseline uses a different regional package. Record both
versions when investigating the bootloader handoff.

## Menu and file fixture

The workflow's `menu` stage restores UniXNU and embeds a 4 MiB read-only FAT16
volume. It contains `EFI/UniXNU/unixnu.toml` and a file-loaded `HelloPayload.efi`.
All three menu entries require confirmation, and the isolated menu has no
automatic countdown or rotation. Use volume keys to select and a short power
press to enter or confirm. First verify the expected missing-file error, then
run Hello and observe its matching build ID and return to the menu after
15 seconds. One complete successful run satisfies this stage's acceptance.

```sh
python3 scripts/build-uefi-probe.py --stage menu --unixnu ../UniXNU --uefi ../uefi-sheng --output out/uefi-menu-001
```

This stage embeds its own test volume so it needs no boot ramdisk or
`vendor_boot` write. Its isolated research firmware accepts the test EFI file
and skips automatic key enrollment and filesystem security-policy callbacks.
The stock bootloader and `board.toml` remain intact. It does not contain
DarwinBoot, XNU, OS files or an installation image. Build and volume hashes
remain separate from device observations.

## Build

One command from this repository builds everything: dependencies, preflight,
patches, kernel, package, firmware, payload, boot image and the manifest.

```sh
UNIXNU_UNIQUE_CHIP_ID=<8 hex digits> scripts/package.sh --os 27 --uefi ../uefi-sheng
```

- The firmware inputs come from the official fastboot archive pinned in
  `board.toml` `[firmware.image]`: the preflight downloads it with concurrent
  HTTP ranges, keeps only the porting inputs, deletes the archive and
  generates the `Binaries/sheng` modules the firmware volume builds from.
  Extracted firmware lives in no repository.
- `UNIXNU_UNIQUE_CHIP_ID` is the platform seed of the device, 8 hex digits.
  It is baked into the images and stays out of every repository.
- The kernelcache, trust caches and OS volumes come from the IPSW the OS
  profile pins; the generated GPU headers come from the pinned sources the
  kernel archives fetch.
- Outputs land under `out/sheng/<profile>/<config>/` of the UniXNU checkout:
  `boot/boot.img`, `payload/payload.img`, `kernel/kernel.macho` and
  `package.manifest.json`.
- `--check` stops after deps, preflight and patches; `--no-deps` skips
  fetching on a machine whose sources are already pinned.

See the [packaging script](https://unixnu.com/porting/packaging) page for the
fixed steps, the board.toml keys and the verification the run performs.

## Build on GitHub

`.github/workflows/package.yml` runs the same script on a macOS runner and
offers the images as the run's artifacts. Select `sheng-build` to use the
registered Apple Silicon self-hosted runner, or select a GitHub-hosted macOS
runner when this Mac is unavailable. The self-hosted runner requires full
Xcode, the pinned Rust toolchain and the Homebrew tools listed in the workflow.
Its service PATH must include Homebrew Python 3.11+ and
`$(brew --prefix rustup)/bin`; installing a Rust toolchain does not put
Homebrew's `cargo` shim in `~/.cargo/bin`. The workflow checks these tools
and the iPhoneOS SDK before packaging.

For this installation, keep the original Data backup outside the runner's
checkout. Set `SHENG_DATA_SEED_PATH` and `SHENG_DATA_SEED_SHA256` in the
runner's `.env` to import it with a hash check. A different cached seed stops
the job. Reuse the original platform seed secret and leave `init_data`
unchecked for later builds. Self-hosted checkouts preserve build outputs.
Select `check_only` for a short Actions job that checks the runner, compiles
Rust and an iOS object, and verifies the saved seed before a full build.

1. Fork this repository and set its `UNIXNU_UNIQUE_CHIP_ID` secret to the
   platform seed of the device.
2. Actions, package, Run workflow, pick the OS profile.
3. Download the run's artifacts, then delete the run. The images serve the one
   device whose seed they bake; they are not kept.

The run installs and asserts its own tools; nothing else is needed on the
runner.

For a first iPadOS 27 installation, select `init_data`. The workflow also
builds `first-install-userdata-27` on a separate runner. Its Android sparse
image contains the unchanged OS and SystemOS windows, their restored signed
verification tables, and explicit zeros through the end of userdata. Flashing
it erases Android user data. Compare the target's actual GPT geometry with
`first-install.json` before use; the capacity label alone is insufficient.
Keep the separate installation-seed backup and the platform seed for updates.
An existing installation must not use the first-install userdata image.

To build this image locally after obtaining the pinned UniXNU checkout:

```sh
python3 scripts/check-first-install-userdata.py
python3 scripts/build-first-install-userdata.py --unixnu ../UniXNU
```

The USB submodule uses published revision `e4efe95c903a737e0f5955e5b50a8fb4d2a7d718`.
The board probe still uses `usb=1`. Forced role diagnostics in this revision
use `sheng-usb-host` and `sheng-usb-back`; normal cable role selection needs
neither argument.

## Documentation

The documentation site is maintained in UniXNU:

- [sheng device guide](https://unixnu.com/devices/sheng)
- [Building](https://unixnu.com/building)
- [Device repository specification](https://unixnu.com/porting/device-repository)
- [Device-tree specification](https://unixnu.com/porting/device-tree)
- [Component catalog](https://unixnu.com/reference/components)
- [Migration](https://unixnu.com/porting/migration)

Report build results and device boot, storage, display, input, and GPU
observations separately, with source revisions and commands.

## GPU frame diagnostics

`gpu-trace=1 diag-export=240` exports the latency capture at 240 seconds of boot-log time. It does not schedule a reboot. The capture holds the render server's frame trace, GPU submission and display arrival, large GPU allocations, CPU occupancy, render thread waits, faults, shared-region unnests and the touch report times. `scripts/read-sheng-log.py` extracts the files and runs the decoders; the `*.touch.*` outputs keep only the touch windows. See [GPU frame diagnostics](https://unixnu.com/porting/gpu-diagnostics).

On macOS, starting the Ethernet controller without the BSD wait and the display's hot plug binding follow [macOS-DroidVM](https://github.com/Droid-VM/macOS-DroidVM), the DroidVM port booted with UniXNU.
