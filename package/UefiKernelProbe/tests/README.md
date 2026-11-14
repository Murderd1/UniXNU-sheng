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
manual confirmation, a persistent recovery display, and the exact root-readonly
whitelist with its dedicated confirmation text. Both full-kernel and root-readonly
configurations receive a freestanding compile. Native ARM64 hosts skip
the privileged `CurrentEL` read. The separate AARCH64 freestanding compile keeps
that instruction and checks the actual firmware build path against EDK II.

These checks do not demonstrate firmware, XNU, or tablet execution.

The native mock reads CHAR16 through explicit volatile 16-bit accesses and
checks termination before following nonzero units. An optimized macOS run
reported an incorrect string length with the ordinary loop; firmware uses
EDK II BaseLib rather than this host mock. Boot policy remains unchanged.
