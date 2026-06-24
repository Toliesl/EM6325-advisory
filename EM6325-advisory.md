# Security Advisory: Eminent EM6325 IP Camera — Weak Credentials and Unsigned Firmware/Configuration Upload Leading to Remote Root

**Affected product:** Eminent EM6325 IP camera
**Affected firmware:** `EM6325_V11.4.5.1.5-20171227` (other versions not tested)
**Vulnerability classes:** CWE-521 (Weak Password Requirements), CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-494 (Download of Code Without Integrity Check)
**Impact:** Unauthenticated-to-root remote code execution; network pivot

---

## Summary

The Eminent EM6325 is a consumer IP camera based on a generic OEM hardware/SDK platform that is rebranded and resold under multiple vendor names. The device exposes a web management interface that protects the administrator account with a four-digit numeric password and applies no rate limiting, making the credential trivially brute-forceable. Once authenticated, the device's configuration-restore and firmware-upgrade functions accept attacker-modified images without any signature or integrity verification. An attacker can use these functions to enable the telnet daemon — or upload modified firmware that starts telnet with a login bypass — obtaining a root shell and the ability to execute arbitrary code on the device. A compromised camera can then be used as an entry point to attack other systems on the same network.

This finding is distinct from the previously published backdoor account (CVE-2017-8224) and from the remote code execution issues documented in the predecessor model (EM6220), which were verified as fixed on the EM6325. The chain described here relies on weak credentials plus unsigned firmware/configuration handling, not on those earlier issues.

---

## Affected versions

Verified on firmware `EM6325_V11.4.5.1.5-20171227`. Because this device shares hardware and SDK with several rebranded products, other vendors' equivalents and other firmware revisions may be affected, but only the version above was tested.

---

## Technical details

### 1. Weak, brute-forceable administrator password (CWE-521 / CWE-307)

The web interface is served over port 443 (note: the service speaks plain HTTP on this port despite the port choice). The administrator account uses the username `admin` and a password consisting of four numeric digits (range `0000`–`9999`). The interface enforces no lockout, throttling, or rate limiting on failed HTTP Basic authentication attempts.

The entire keyspace is 10,000 candidates and can be exhausted in seconds. In testing, the valid credential was recovered programmatically (a simple loop over the four-digit space, checking the HTTP response code to detect success) and independently with an intruder-style tool by iterating the base64-encoded Basic auth value over the same range. This maps directly to the OWASP IoT Top 10 (2018) number-one entry, "Weak, Guessable, or Hardcoded Passwords."

### 2. Configuration restore accepts unsigned, modified images (CWE-494)

Within **System Maintenance**, the interface allows the administrator to download a backup of the device configuration and to upload one to restore settings.

The downloaded backup is a maximum-compression gzip stream. Decompressing it yields a set of configuration files, several of which contain sensitive data (for example Wi-Fi SSID and passphrase, and FTP/email credentials when configured). One file, `config_debug.ini`, contains a `[telnet]` section with a `tenable` flag set to `0`, indicating the telnet service is disabled.

The configuration file is not authenticated or integrity-protected. An attacker can flip the `tenable` flag from `0` to `1`, repack the archive, and upload it. Two practical details matter when repacking: the archive must be re-created with maximum gzip compression, and trailing data present after the gzip stream in the original file must be preserved and re-appended, because the device relies on it when validating that the uploaded file is an acceptable configuration. With the modified configuration restored, the telnet service is re-enabled, confirmed by a port scan showing the telnet port open.

### 3. Firmware upgrade accepts unsigned, modified images, enabling a telnet login bypass (CWE-494)

Re-enabling telnet via configuration alone leaves a custom telnet login prompt with unknown credentials. To obtain a shell without those credentials, the firmware-upgrade function is abused.

The official firmware for the model is downloadable from the vendor and is distributed as a ZIP archive with no signing or integrity protection. The archive contains the device's startup scripts, including the routine that conditionally launches the telnet daemon based on the `tenable` flag. By replacing that conditional logic so that the telnet daemon is started unconditionally with a login bypass (`telnetd -l /bin/sh`), an attacker produces firmware that exposes a root shell with no authentication.

As with the configuration file, the device validates trailing data that follows the ZIP structure (the end-of-central-directory marker `50 4b 05 06` and the fixed-length record after it). The modified firmware is repacked and the original trailing data is re-appended so the device accepts it. To survive the device reset that follows an upgrade, the attacker-controlled default configuration is also bundled so telnet remains enabled after reboot.

After uploading the modified firmware through the web interface and allowing the device to reboot, connecting over telnet yields a root shell (`whoami` returns `root`), confirming arbitrary code execution as root.

### 4. Post-exploitation / pivot

The device runs a minimal BusyBox environment. Additional tooling can be cross-compiled for the device's ARM architecture and transferred onto it (the device supports TFTP), enabling further actions on the network. As a proof of concept, a cross-compiled networking utility on the camera was used to send control requests to a smart bulb on the same network, demonstrating that a compromised camera can reach and manipulate other devices — i.e. it is a viable pivot point, not merely a standalone compromise.

---

## Impact

An attacker who can reach the device's web interface can recover the admin credential in seconds and then escalate to a persistent, unauthenticated root shell via the unsigned upgrade path. From there the camera can be used to surveil, to extract stored network credentials, and to pivot to other hosts on the network.

A Shodan query against a string unique to this device's login page returned approximately 1,962 internet-exposed units at the time of research, concentrated in Belgium and the Netherlands. Because the underlying platform is rebranded across multiple vendors, the true exposed population is likely larger.


## References
- CVE-2017-8224 — backdoor account in related camera firmware (distinct from this finding).
- OWASP Internet of Things Top 10 (2018).
