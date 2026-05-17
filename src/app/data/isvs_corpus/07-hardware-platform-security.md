---
concern_area: Hardware Platform Security
isvs_chapter: V5 — Hardware Platform
edition: OWASP ISVS 1.0
---

# Hardware Platform Security

This concern-area covers the physical and silicon-level security of the
device, on the assumption that an attacker can hold the device in their
hands. It maps to the hardware-platform chapter of the OWASP ISVS and
spans debug and test interfaces, tamper resistance, secure elements and
trusted execution environments, and resistance to side-channel and
fault-injection attacks.

The recurring weakness is leaving manufacturing and debug capabilities
accessible on shipped units. Hardware debug ports — JTAG, SWD, UART
consoles — remain enabled, giving anyone with physical access a direct
path to halt the processor, dump memory, and extract firmware and keys.
Test points and unlocked configuration fuses let an attacker re-flash
or reconfigure the device. Secrets are stored in general-purpose flash
rather than in a secure element, so a memory read-out recovers them.
There is no tamper detection, so physical intrusion leaves no trace and
triggers no protective response. Cryptographic code is written without
regard for side channels, leaking key material through timing or power
analysis, and is not hardened against fault injection, so a glitched
operation can skip a verification step.

Sound practice disables or locks debug and test interfaces on
production units, or gates them behind strong authentication. Secrets
and cryptographic keys are held in a secure element, trusted platform
module, or trusted execution environment that resists extraction even
with physical access. Tamper-evident or tamper-responsive measures
detect intrusion and react — zeroising keys where the threat model
warrants it. Cryptographic implementations are chosen and reviewed for
constant-time behaviour and side-channel resistance, and security
decisions are written so that a single glitched instruction cannot turn
a failed check into a pass.
