# Normal startup with existing Data

`--stage full --root-data-resume --handoff-code-clean` selects normal full
startup with the installed Data overlay. It removes the first initialization
mode's `data-reset=1` and retains every other effective argument, including
`data-persist=2` and `log=0`. The exact 775-byte string has SHA-256
`25236a5f7e75b6d2b70e1956f666faa44851f960fb7914700a623e00ca68d824`.
No reset token, native UFS probe or delayed diagnostic stop is present.

The original FAT (`f46ba1674303a37e89dd0e8ad24fe54ed43cd63c7dd29001216b87f36634ed68`),
full kernel, Data seed and sidecars remain unchanged. The accepted Android v3
container and handoff code cleaning remain. This change does not tune GPU,
CPU, charging or other drivers. Preserve the first successful image and its
inputs while qualifying normal startup separately.

## Build and selection

Use a fresh output directory and the audited complete package or fixed media
baseline, as for the initialization image. For Actions, select **full-resume**
as the stage, enable **handoff_code_clean**, and leave all other root trial
options, including **root_data_init**, off. The workflow maps this manual
choice to the full stage and `--root-data-resume`; its existing default remains
menu. It rejects conflicting choices before downloads. Push builds do not
select resume or initialization. Existing workflow options remain available.

The application displays **SHENG NORMAL DATA STARTUP**. On page 4, select
**Boot with existing Data once**, then **BOOT WITH EXISTING DATA ONCE**.
Confirmation defaults to Cancel. No timeout or missing-input path boots the
system; each accepted selection invokes the loader once. Normal startup can
write and synchronize the existing Data store, but requests no initialization.

The canonical resume whitelist is independent of the initialization whitelist.
It rejects omitted, added, duplicated or changed arguments, including every
reset request. Legacy diagnostic modes keep their existing no-write gates.
Payload verification, seed loading and the one-shot event loop remain.

## Data behavior and limits

The existing RamBlock mode 2 path resumes an overlay only when its header
matches the packed seed identity and page count. Without reset, a blank,
foreign or damaged store is kept unchanged rather than initialized. It may
then prevent normal writable startup; a failure is not permission to fall back
to reset. Preserve the observed error and existing store for diagnosis.

The store geometry and write bounds remain those described in
[first initialization](root-data-init.md#store-allocation-and-write-effect).
Normal APFS and service writes stay within that allocated userdata store.
No boot/firmware partition, GPT or root-window reflash is required.

Native C simulation and seven freestanding AARCH64 application modes pass.
The builder verifies mutually exclusive trial modes and exact argument strings.
Device resume, retained user files, cross-reboot durability and performance
require their own observations; a successful build does not establish them.
