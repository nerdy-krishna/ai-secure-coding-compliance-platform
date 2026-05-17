---
concern_area: Device Application & Data Protection
isvs_chapter: V2 — User Space Application
edition: OWASP ISVS 1.0
---

# Device Application & Data Protection

This concern-area covers the security of the application software that
runs in the device's user space — the code closest to sensors,
actuators, and the user — together with the data that application
holds. It maps to the user-space application chapter of the OWASP ISVS.

The recurring weakness is treating the device as a trusted, private
environment when it is in fact physically accessible to an attacker. A
device application stores credentials, API tokens, or session keys in
plaintext on the filesystem or in shared preferences, so anyone who can
read the storage medium recovers them. Sensitive data — personal
information, telemetry, captured media — is written to disk
unencrypted or copied into world-readable logs. Local inter-process
communication channels (sockets, named pipes, intents, shared memory)
are exposed without authentication, so a co-resident process can drive
privileged functionality. Application-level access control is enforced
only in the companion phone app or cloud, leaving the on-device
operation itself unguarded.

Sound practice treats on-device storage as hostile. Credentials and
keys are kept in a hardware-backed keystore or secure element rather
than in application files, and sensitive data at rest is encrypted with
keys the application cannot trivially export. Logs are scrubbed of
secrets and personal data. Local IPC endpoints authenticate their peer
and expose the narrowest possible surface. Every privileged on-device
operation enforces its own authorization check rather than trusting a
remote caller, so a compromise of the companion app or a spoofed cloud
message cannot bypass it.
