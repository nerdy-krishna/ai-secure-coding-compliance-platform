---
concern_area: Firmware Integrity & Secure Boot
isvs_chapter: V3 — Software Platform
edition: OWASP ISVS 1.0
---

# Firmware Integrity & Secure Boot

This concern-area covers the chain of trust that decides whether a
device will only run firmware its manufacturer authorised. It maps to
the software-platform chapter of the OWASP ISVS and spans secure and
verified boot, the bootloader, firmware image signing, anti-rollback,
and the authenticity and integrity of over-the-air updates.

The recurring weakness is a boot or update path that accepts firmware
without proving where it came from. Secure boot is absent, so modified
firmware runs unchallenged. A boot stage verifies the next stage with a
weak or hard-coded check, or the verification can be skipped through a
debug or recovery path. Firmware images are unsigned, or the signature
is checked with a key an attacker can substitute. The update mechanism
fetches an image over an unauthenticated channel, or applies it without
verifying a signature, so a network attacker can install their own
build. There is no anti-rollback protection, so an attacker downgrades
the device to an older, vulnerable version that is still validly
signed.

Sound practice establishes a hardware root of trust and verifies each
boot stage's signature before transferring control to it, with no path
that bypasses the check. Firmware images are signed with a key held in
a protected store, and the verification key is immutable on the device.
Updates are delivered over an authenticated, integrity-protected
channel, and the device verifies the image signature and a monotonic
version counter before installing, rejecting both tampered images and
downgrades. The update process is atomic, with a verified fallback so a
failed update cannot brick or weaken the device.
