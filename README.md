# Eminent EM6325 IP Camera — Security Advisory

Security research disclosure for the **Eminent EM6325** IP camera.

**Affected firmware:** `EM6325_V11.4.5.1.5-20171227` (other versions not tested)
**Impact:** Remote, authenticated-to-root code execution via weak credentials and unsigned firmware/configuration upload; usable as a network pivot.
**Weakness classes:** CWE-521 (Weak Password Requirements), CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-494 (Download of Code Without Integrity Check).

## Summary

The device's web management interface protects the administrator account with a four-digit numeric password and enforces no rate limiting, making the credential trivially brute-forceable. After authenticating, the configuration-restore and firmware-upgrade functions accept attacker-modified images without verifying their authenticity or integrity, allowing the telnet service to be enabled (or firmware to be uploaded that starts telnet with a login bypass) and yielding a root shell.

This is distinct from the previously published backdoor account (CVE-2017-8224) and from the predecessor EM6220 RCE issues, which were verified as fixed on the EM6325.

## Full advisory

See **[EM6325-advisory.md](EM6325-advisory.md)** for the complete technical details, impact analysis, and remediation guidance.

## Disclosure

This advisory describes the vulnerability at the level needed for verification and remediation. It does not provide a ready-to-run exploit. Operators should isolate affected devices from the internet and apply vendor updates where available.
