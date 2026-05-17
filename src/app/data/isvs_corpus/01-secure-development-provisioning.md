---
concern_area: Secure Development & Provisioning
isvs_chapter: V1 — IoT Ecosystem
edition: OWASP ISVS 1.0
---

# Secure Development & Provisioning

This concern-area covers the ecosystem-level practices that decide
whether a connected device starts life in a defensible state. It maps
to the IoT ecosystem chapter of the OWASP ISVS and spans the secure
development lifecycle, threat modeling, device identity, provisioning
and onboarding, and supply-chain integrity.

The recurring weakness is treating a fleet of devices as if each were a
one-off product. A device ships with a shared default credential or a
key common to every unit, so compromising one unit compromises all of
them. A device has no unique, attestable identity, so the back end
cannot tell a genuine unit from an impostor. Onboarding accepts a
device onto the network before its identity is verified, or transfers
provisioning secrets over an unauthenticated channel. The bill of
materials for firmware and hardware is unknown, so a vulnerable
component cannot be located when an advisory lands. Decommissioning
leaves credentials and keys live on a device that has left the
operator's control.

Sound practice gives every device a unique identity established at
manufacture and bound to hardware where possible, and provisions
per-device secrets rather than shared ones. Threat modeling is
performed for the device, its companion app, and its cloud services
together, since the trust boundaries that matter span all three.
Onboarding authenticates the device before granting it network access
and protects provisioning data in transit. A maintained software and
hardware bill of materials makes component risk auditable. A defined
decommissioning path revokes identity and wipes secrets when a device
is retired, returned, or resold.
