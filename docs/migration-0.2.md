# Migration to version 0.2.0

Report schema 1 and CLI command names remain supported. The package still has
no third-party runtime dependencies and requires Python 3.11 or newer.

Prepare a fresh lab after upgrading. The new driver is embedded at preparation
time, so an already prepared lab continues to contain its original driver.
The standalone manifest parser now rejects ambiguous JSON, invalid scalar types,
non-synthetic tokens and paths inconsistent with the prepared layout. Moving a
prepared lab without regenerating its absolute paths is unsupported.

Mandatory skipped file/process observations cannot establish complete evidence.
Optional disabled checks remain SKIP rather than DENY and cannot satisfy a deny
policy. The demo never discovers or connects to host Docker/SSH sockets; use
--no-sockets to disable those probes and baselines elsewhere as well.

Capture and JSON limits are intentional input restrictions. Ambiguous streams
or malformed current output remain incomplete. Interrupted or repeated manual
runs need a fresh lab; retained results describe their original execution and
must not be treated as proof of a later attempt.

Post-creation I/O failures now report ERROR. They cannot prove denied access once
creation has succeeded. Permission failures during directory safety validation
also remain inconclusive. See the threat model for platform and adversarial limits.
