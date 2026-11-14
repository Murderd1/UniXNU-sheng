# Stage 4 root installation proposal

The owner explicitly authorized clearing Android and writing userdata, with
bounded chunks to avoid a long continuous Fastboot transaction. No userdata
write had been performed when this plan was prepared.

Target: sheng, serial `33b62981`, unlocked bootloader Fastboot. The accepted
probe read userdata from 4 KiB LBA `0x2f3840` through `0x3d0abfa`, inclusive:
249497890816 bytes. The current partition contains Android data without a
SHNGROOT header. This matches the earlier Fastboot capacity and candidate
image geometry.

## Input

```text
D:\6spro\UniXNU-sheng\out\first-install-package\userdata\ipados-27.0.1-24A446\sheng_ipados27\userdata\userdata-first-install.img
```

- Format: Android sparse v1, with explicit zero fill and no DONT_CARE chunks.
- File size: 14732319540 bytes; expanded size: 249497890816 bytes.
- Fresh complete SHA-256: `1dad4810d16d9fc1b4306879c892b7417bf19fddcd97203dae0c0b5305b27bf6`.
- Root manifest: version 2, two image windows and two signed-policy objects.
- Existing policy signatures, block tables, actual kernel key and ADT root UUID
  have been checked against this candidate.

## Effect and authorization

Writing this image overwrites the entire userdata partition, including an
explicitly zero-filled 233744084992-byte tail. It clears the restored Android
apps, accounts, photos and files. Returning to Android afterward requires
restoring its userdata/system state with the matching stock package. The
owner's CN factory package remains available at
`C:\Users\MECHREVO\Downloads\sheng_images_OS3.0.303.0.WNXCNXM_16.0`.

Authorization covers this userdata write and one subsequent temporary boot.
Before writing, recheck serial, product, bootloader mode,
unlocked state, partition size, logical block size and the selected file's
identity. Stop on a mismatch or Fastboot failure. Save the command output.
Do not automatically retry a partially completed write.

## Exact proposed operations

The original one-file flash is replaced by independently verified sparse
fragments. Each fragment requests at most 512 MiB of explicit RAW/FILL writes;
each transfer is bounded by `-S 128M`, below the observed 768 MiB device limit.
There are 465 logical ranges. The first range, containing SHNGROOT, is written
last. Only one temporary fragment exists during writing. Its prefix/suffix
DONT_CARE chunks retain original addresses and preserve other ranges; its
explicit bytes are checked against the original input before each command.
All explicit ranges together cover the original image, including the zero tail.

The host checks request ranges, not the proprietary bootloader's internal
physical write amplification or exact transaction duration. Merely specifying
`-S` on the original file would still leave the huge FILL zero tail in one
transaction. The fragment module and eight synthetic corruption/boundary tests
pass, as do real first/last-range sample checks.

The guarded executor saves a per-fragment range, SHA and Fastboot result. It
has no automatic retry/resume or boot action. For each range its device command
is the following; the subsequent boot is allowed only when all ranges passed:

```powershell
& 'C:\adb\fastboot.exe' -s 33b62981 -S 128M flash userdata '<one verified temporary sparse fragment>'
& 'C:\adb\fastboot.exe' -s 33b62981 boot 'D:\6spro\UniXNU-sheng\out\handoff-code-clean-43586887818-1\boot.img'
```

Only userdata is written. The demonstrated boot image runs temporarily in RAM;
boot, init_boot, vendor_boot, firmware, GPT and lock state are unchanged.
The old first-install package's v0 boot image is not part of this proposal.

The executor is `out/flash-userdata-chunks-once.py`; the bounded sparse module
is `scripts/sparse_flash_chunks.py`. The temporary image has SHA-256
`e3d6e4cab37d664bb2fd06a533be6f87dad4ea248e09421655fd0c24044273d7`.
It retains probe 10, `log=0` and `data-persist=0`, so its physical confirmation
collects root metadata and deliberately parks again. Expected installed-candidate
output is `manifest status=0 windows=2`: the two vroot objects are counted
separately and are not printed by this probe. This checks manifest acceptance;
it does not mount APFS or start launchd. A subsequent full-kernel trial is a
separate checkpoint after that result.
