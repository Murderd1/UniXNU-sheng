# Full root trial

Use the explicit combination `--stage full --full-root-trial --handoff-code-clean`
with the same audited complete package. This mode rejects the read-only probe
option, non-full stages, missing self-code cleaning and argument drift.

The effective loader arguments are the exact 775-byte Stage 3 baseline, SHA-256
`452563097518e626be38881b9da8e47b68fb5161608cddfe91088b1691811a03`.
It removes only the ` native-ufs-probe=10` suffix from the accepted metadata
diagnostic. `log=0` and `data-persist=0` remain; no Data reset or automatic reset
is introduced. The existing full-kernel menu requires manual confirmation.

The 180-byte self-cleaning DarwinEnter overlay remains independently checked.
The same FAT, full kernel, ADT, trust cache and packed Data seed are reused.
The final Android container remains v3. The build manifest distinguishes
`full-root-trial` from `root-readonly-probe` and ordinary `full-kernel`.

Host fixtures exercise the real normal-mode callback with the complete fixed
arguments and compile the normal, metadata-probe and full-root configurations
for AARCH64. A successful build does not establish root mounting. Observe the
actual APFS/root and Data/launchd results separately. A large sparse Data seed
without an active persistent overlay does not provide writable Data, so this
trial alone cannot qualify userland or persistence.
