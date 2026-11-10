# First-install cloud build, 2026-11-10

Target: Xiaomi Pad 6S Pro (sheng), reported 12 GB RAM and 256 GB storage,
unlocked bootloader, first installation. This session builds host files only.
The target tablet is not connected. No partition has been read or written.

## Sources and commands

The successful userdata job used device revision
`da0c23d31d0f4922832359937a364a8bc7d9a433` and UniXNU revision
`82b847c4ac3f68a57024b3082ffa3a03442defd9`, with the pinned
`ipados-27.0.1-24A446` OS profile. See the exact revision recorded in the
artifact's `first-install.json` when reproducing this run.

```sh
python3 device/scripts/check-first-install-userdata.py
python3 device/scripts/build-first-install-userdata.py --unixnu UniXNU
```

[Successful userdata job](https://github.com/Murderd1/UniXNU-sheng/actions/runs/42804909759/job/129791455420).
The overall run is marked failed because its separate boot-package job failed.

## Userdata result

Seven host tests pass on the macOS runner. Both original policy signatures,
raw image digests and reconstructed block-table digests match. The existing
signed headers and keys are preserved. No private signing key is required.

| Output | Bytes | SHA-256 |
| --- | ---: | --- |
| Artifact ZIP | 10,744,408,854 | `2046a85d535c36f8306782c92be24f5a5384d263a8b6a59e69b03b31d3567250` |
| `userdata-first-install.img` | 14,732,319,540 | `1dad4810d16d9fc1b4306879c892b7417bf19fddcd97203dae0c0b5305b27bf6` |

The Android sparse image expands to 249,497,890,816 bytes. It includes OS,
SystemOS, OS.vroot and SystemOS.vroot, then explicit zero fills through the
remaining userdata partition. Flashing it erases Android user data.

Root manifest SHA-256:
`49e2593b7c7f4b2c17e47a15695fec88748a673cc01b129602bb8346c7342ae2`.

## Boot-package failures and repairs

The first clean checkout failed because the QcomDwc3 gitlink named unavailable
revision `0dd83827279ee070dca7ddb486c90365567cc99d`. The fork selects published
revision `e4efe95c903a737e0f5955e5b50a8fb4d2a7d718`. The board USB gate and
default cable role selection match its interface. Forced role diagnostic
arguments retain their `sheng-` prefix in this published driver.

The next boot build created and backed up the first-install Data seed, then
failed applying `turnip-frame-diagnostics.patch`: the new diagnostic header
diff lacked `new file mode 100644`. An isolated clean repository reproduces
the failure; the metadata repair passes application and reverse checking.
The boot retry pins personal UniXNU fork revision
`3e239995903ae59a2ea506c52c8e31341d357044`, based on the original tool revision.
The new run reuses the installation seed cache.

[Boot retry](https://github.com/Murderd1/UniXNU-sheng/actions/runs/42807344441).
This retry passed Mesa patch application and GPU/audio runtime generation, then
failed because Wi-Fi firmware was a local-only input. All three original Wi-Fi
file identities were recovered from an immutable public source and verified
locally. Run [42815226492](https://github.com/Murderd1/UniXNU-sheng/actions/runs/42815226492)
verified all firmware inputs, then exposed a missing output parent in the early
host fixture. After creating the parent, run
[42816370728](https://github.com/Murderd1/UniXNU-sheng/actions/runs/42816370728)
reached an outdated whitelist assertion: the test rejected `join.txt`, which
the production reader already accepts for optional unattended testing. The
fixture now exercises all five existing names, rejects unknown/traversal names,
creates its own output parents and retains sanitizer/assertion stderr. No
production Wi-Fi behavior was changed.

Run [42817825877](https://github.com/Murderd1/UniXNU-sheng/actions/runs/42817825877)
passes the early Wi-Fi firmware-input step, including the existing ASan/UBSan
reader fixture, and enters the full package step with the preserved Data seed.
It generated the GPU/audio runtime but failed because the supplicant preparation
checks locked inputs without fetching them: `Ath12kWifi/deps/linux` was absent.
The board builder now runs the component's existing `tools/fetch-sources.py`
before `tools/build-supplicant.py`. An early workflow step builds and signs
the Wi-Fi userspace layer before the long runtime build. Source pins are
unchanged; no wireless driver or authentication behavior is changed.

The userdata artifact ZIP and extracted image pass local SHA-256 checks. A
streaming sparse decoder also verifies the SHNGROOT header, each original
window, both existing signed policy headers, the complete reconstructed block
tables and explicit zero fills after the root. The decoded partition size
matches the cloud report. No 249 GB raw partition file is created.

## Device checkpoints

Boot, storage mount, display, touch input and GPU: not tested in this session.
Before any installation, compare the actual userdata GPT start/end and logical
block size with the artifact report, check the boot partition size and retain
the original Android boot images and user-file backup. Successful image
assembly does not establish device boot or daily-use compatibility.

## Cloud host capacity

Run [42824136714](https://github.com/Murderd1/UniXNU-sheng/actions/runs/42824136714)
was not acquired by a hosted runner after repeated attempts. GitHub annotations
report macOS ARM capacity constraints; the job executed no build steps. The
workflow now offers the standard macos-26-intel host and resolves Homebrew
tool paths from its installed prefixes. This changes the build host only.
The iPadOS profile, component pins and preserved installation seed are unchanged.

The standard Intel host was allocated immediately in run
[42829591813](https://github.com/Murderd1/UniXNU-sheng/actions/runs/42829591813).
Its tools step failed before compilation because Homebrew resolved ipsw as a
cask whose zap stanza was incompatible with the runner. Both tools steps now
select the official formula explicitly with `brew install --formula`.

Run [42831462960](https://github.com/Murderd1/UniXNU-sheng/actions/runs/42831462960)
still parsed the invalid cask even with --formula. The workflow now uses
`scripts/install-ipsw.py`: official ipsw 3.1.743 release archives, architecture
selection and the SHA-256 values published in the official Homebrew formula.
It extracts only the regular ipsw executable and checks its version.

Run [42833337024](https://github.com/Murderd1/UniXNU-sheng/actions/runs/42833337024)
passes tool installation and the firmware-reader check. The early userspace
step exposes Ath12kWifi's cone-mode sparse checkout rejecting the lock's
anchored patterns and individual files. Personal Ath12kWifi fork commit
e62ba34 selects `sparse-checkout set --no-cone`; a local actual-Git fixture
passes directory/file selection and check-only identity. Dependency pins and
production runtime source are unchanged.
