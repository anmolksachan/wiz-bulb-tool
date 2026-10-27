# Security Policy

## Purpose

This tool was built for **authorized security research and educational use only**.  
It documents vulnerabilities discovered during a home network security audit on devices owned by the author, following responsible disclosure practices per ISO/IEC 29147.

## Responsible Disclosure

Findings covered by this tool have been responsibly disclosed:

| Vendor | Contact | Disclosed | Response |
|---|---|---|---|
| Signify (WiZ / Philips) | vulnerabilities@signify.com | 2026-10-24 | Acknowledged 2026-10-26 — Won't Fix (works as intended) |

CVE submissions filed with MITRE CNA-LR on 2026-10-27:
- **CAN-2026-2040961** — Unauthenticated info disclosure via getSystemConfig / getModelConfig / getUserConfig
- **CAN-2026-2040964** — Cloud homeId passively leaked in cleartext UDP broadcast packets

## Intended Use

This tool is intended for:

- Security researchers auditing devices they **own**
- IoT security education and awareness
- CTF challenges and lab environments
- Network administrators assessing their own infrastructure

**Do not use this tool against devices or networks you do not own or have explicit written permission to test.**  
Unauthorized access to computer systems is illegal under the CFAA, Computer Misuse Act, and equivalent laws worldwide.

## Reporting a Vulnerability

If you discover a vulnerability in this tool itself, please report it via GitHub's private vulnerability reporting or email:

**anmol221999@gmail.com**

Please do not open a public issue for security vulnerabilities.

## CVE References

| CVE | Description |
|---|---|
| CVE-2019-18980 | Unauthenticated WiZ LAN control (prior art — this tool extends to newer hardware) |

## Author

**Anmol K Sachan** ([@FR13ND0x7F](https://twitter.com/FR13ND0x7F)) — Independent Security Researcher
