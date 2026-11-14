# Kernel transport probe host checks

Run from the device checkout:

```sh
python3 scripts/check-uefi-kernel-probe.py --edk2 /path/to/Mu_Basecore --unixnu /path/to/UniXNU --cc cc --aarch64-cc clang
```

On Windows, run in a Visual Studio x64 tools environment and use `--cc cl`.
The checker uses the actual application and protocol headers. It generates a
16-byte seed configuration only in a temporary directory; it does not replace
the repository's configuration placeholder.

The host simulation checks verified-volume and loader gates, guarded arguments,
exact seed size and contents, partial reads, failure cleanup, a single callback,
manual confirmation, and a persistent recovery display. Native ARM64 hosts skip
the privileged `CurrentEL` read. The separate AARCH64 freestanding compile keeps
that instruction and checks the actual firmware build path against EDK II.

These checks do not demonstrate firmware, XNU, or tablet execution.
