# Root media report

Use `--stage full --root-media-probe --handoff-code-clean` with the same
audited complete package. The media diagnostic is mutually exclusive with
the root-metadata probe and the full-root trial. Other stages and missing
handoff cleaning are rejected before source preparation.

The effective arguments are the exact 775-byte accepted baseline followed
only by ` native-ufs-probe=12`. The result is 795 bytes, SHA-256
`0e29632941bb5a79b4af422526f0689a874584b38d4c5fed506af74c9a31abfa`.
`log=0` and `data-persist=0` remain. The complete FAT, kernel, signed policies,
packed Data seed and 180-byte self-cleaning DarwinEnter are reused. The menu
requires manual confirmation before one loader callback.

The fixed ShengUfs driver already implements probe 12. It runs the normal
root-window preparation, signed policy and UUID checks, schedules publication
and starts a separate media-report thread. That thread normally waits up to
about 20 seconds for media discovery and then deliberately panics to keep its
report visible. Its polling can finish earlier when any four IOMedia services
exist. Scheduling and execution time can extend the total wait.

The report lists a snapshot of IOMedia services, read and failure counts and
the number of started root block devices. It can also contain the Data seed
or other media. A count of four media or two root devices alone does not prove
root mounting, persistent Data or launchd. Record the displayed names, sizes
and UUIDs before assigning a completion level.

This diagnostic does not bypass Data creation: after UFS start returns, source
storage still starts the seed-backed Data device. The unchanged arguments
keep the UFS store and disk-log write windows closed. No Data initialization,
reset or automatic reboot option is added.

The blue and magenta entry bands remain after execution passes their paint
instructions. They establish kernel entry and the pre-MMU-enable checkpoint;
they do not locate a later stall. The iPadOS 27 display build provides
BootProgress stubs, so adding a progress argument alone cannot enable the
full progress screen in this kernel.

A successful build and Fastboot boot response are intermediate evidence.
Keep the exact image/source identity with the actual photographed report.
