# WCN7850 firmware inputs

Run `python3 scripts/fetch-wifi-firmware.py` from the device repository to
fetch missing amss.bin, m3.bin and board-2.bin under `wcn7850/`.
`wcn7850/manifest.json` pins their sizes and SHA-256 hashes. Firmware binaries
stay local; the repository contains the manifest and packaging code.
The source is `ianchb/sheng-firmware` revision
`ebdd6f89ee5aaa132f03860c211bdfb4294bd954`, directory
`ath12k/WCN7850/hw2.0`. Its three files match the existing manifest exactly.
`--check` verifies local files without a download. An existing file with a
different identity is rejected. The Wi-Fi userspace builder also fetches
missing inputs before staging them.

`scripts/build-wifi-userspace.py OUT ios27` validates the inputs and stages
them for the Data addon. `package/WifiFirmware.h` defines the shared loader
and packer path: `/private/var/ngpu/firmware/ath12k/WCN7850/hw2.0/`.

After addon installation, the VFS reader validates regular-file type and
size, reads each file and retains successful results for the boot lifetime.
The payload build preserves the Data seed and OS-saved credentials.
