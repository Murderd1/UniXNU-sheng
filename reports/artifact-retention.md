# Build input and artifact retention

Keep complete input packages and build attachments until the owner explicitly
requests their deletion. This includes Actions runs and artifacts, downloaded
archives, local packages, installation seeds, build outputs, manifests and logs.
Downloading, extracting, rebuilding or superseding a package does not authorize
deletion of its earlier inputs or build evidence.

## Actions and local backups

All four artifact uploads in `package.yml` request 90 days of retention:
first-install userdata, installation seed, build logs and packaged images.
`uefi-probe.yml` requests the same period for probe outputs and diagnostics.

The settings apply to new uploads. They do not restore expired artifacts or
extend the expiry of existing uploads. Actions retention is finite. Keep a
complete local copy before expiry, including the input packages, every build
attachment, manifests and logs. Record file sizes, SHA-256 checksums, the
source revision, run ID and artifact name. Retain the original installation
seed unchanged.

## Firmware archive extraction

Normal board preflight and the isolated probe builder retain the complete
stock fastboot archive after extracting their selected firmware inputs.
Neither caller supplies `--delete-archive` automatically. The extractor's
explicit option remains available only for an owner-requested deletion.
It removes the downloaded stock `.tgz`; it does not remove a UniXNU package
or Actions run.

Existing `archive_deleted=true` records describe earlier extractions. They
do not establish that the complete archive is present. Retain or reacquire
any missing complete input needed for a later build.
