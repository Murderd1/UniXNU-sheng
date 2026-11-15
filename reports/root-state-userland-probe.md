# Process names and display state in the root-state report

The delayed root-state diagnostic keeps all 32 existing fields and adds eight
read-only display fields. It queries the fixed kernel's existing proc_name API
for PID 1 and, when positive, the single sampled display-client PID. It does
not traverse the process list or enable process/stack tracing. The exact
821-byte handoff retains log=0 and data-persist=0.

The strict original-kernel, thread, PAC and unused-text guards remain. The new
call target additionally pins the complete 108-byte proc_name function hash.
The kernel's existing API supplies BSD short names, at most 16 characters plus
a terminator. A missing PID returns an empty name. The probe forces its two
32-byte name buffers to terminate even if a host fixture omits the terminator.
All added stores remain on the probe stack; Darwin x18 is explicitly reserved.
The original mount, storage, authentication and userspace paths do not change.

Native formatter checks and exact input/target/field/branch guards pass. The
local body is 1947 of the 2160 permitted bytes. Its own maximum frame is 1296
bytes and its conservative own probe-frame total is 1456. These values exclude
stack use inside existing kernel callees. The longest formatter fixture is
1024 bytes in a 1152-byte output buffer. Actual AARCH64 cloud bytes and device
behavior require their own independent checks.

PID 1 named launchd identifies that process at the query time; it does not
prove completed startup. The recorded client PID belongs to the latest
newUserClient attempt and must be interpreted with its call count and status.
Accepted swaps are validation events. Transfer status and copy counts add
transport evidence, but no counter establishes a correct visible desktop.
A non-read-only Data mount still does not prove that backend writes succeeded;
early NotReady returns remain outside the ordinary counters.

This build is separate from the earlier root-state image. Preserve both source
identities, images, manifests and observations. No device milestone is inferred
from formatter, compilation or source review results.
