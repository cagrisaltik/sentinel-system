# Security Policy

## Overview

Security is a core design principle of Sentinel System.

Sentinel System is currently an **Alpha security research and development project**. The security architecture is actively evolving and the project has not yet undergone a complete independent security audit or penetration test.

We appreciate responsible security research and vulnerability reports that help improve the project.

---

## Supported Versions

Sentinel System is currently under active Alpha development.

| Version | Supported |
| ------- | --------- |
| `0.1.x-alpha` | ✅ Yes |
| Older versions | ❌ No |

Support status may change as the project moves toward stable releases.

---

## Reporting a Vulnerability

If you believe you have discovered a security vulnerability in Sentinel System, please report it **privately**.

Please avoid opening a public GitHub issue for vulnerabilities that could be exploited before a fix is available.

When reporting a vulnerability, please provide as much of the following information as possible:

- A clear description of the vulnerability
- Affected component
- Affected version or commit
- Steps required to reproduce the issue
- Security impact
- Proof of concept, if available
- Suggested mitigation or remediation, if known

Please do not include real credentials, private keys, production secrets, personal data, or other sensitive information in the report.

---

## Responsible Disclosure

We ask security researchers to:

1. Report vulnerabilities privately.
2. Allow reasonable time for investigation and remediation.
3. Avoid accessing, modifying, deleting, or exfiltrating data that does not belong to them.
4. Avoid disrupting services or infrastructure.
5. Avoid publicly disclosing exploitation details before coordinated disclosure.

Security testing should only be performed against systems and environments that you own or have explicit authorization to test.

---

## Scope

Security reports are particularly valuable for issues affecting:

- Authentication
- Authorization
- Session management
- Agent authentication
- mTLS
- WebSocket communication
- Task authorization
- Replay protection
- Input validation
- Command execution
- Certificate handling
- Cryptographic implementation
- API security
- Database security
- Sensitive information exposure
- Privilege escalation
- Remote code execution
- Authentication bypass

---

## Out of Scope

The following generally do not qualify as security vulnerabilities unless they demonstrate a meaningful security impact:

- Issues affecting unsupported or obsolete versions
- Self-XSS requiring significant user interaction
- Missing security headers without demonstrated impact
- Informational findings without practical security consequences
- Vulnerabilities in third-party dependencies that do not affect Sentinel System
- Denial-of-service reports against development-only environments
- Issues requiring already-compromised administrator access
- Social engineering attacks against project contributors

Out-of-scope classifications may be reconsidered when a report demonstrates a realistic security impact.

---

## Sensitive Information

Never commit the following to the repository:

- Private keys
- Passwords
- API tokens
- Session secrets
- Database credentials
- Production certificates containing sensitive material
- `.env` files containing real credentials
- Personal or customer data

Development credentials and cryptographic keys should remain outside version control.

---

## Security Development Practices

Sentinel System aims to follow these principles:

- Defense in depth
- Least privilege
- Secure defaults
- Strong authentication
- Certificate-based Agent identity
- Input validation
- Short-lived authorization data
- Replay protection
- Cryptographic agility
- No custom cryptographic primitives

Security-sensitive functionality should rely on established standards and well-maintained cryptographic libraries rather than custom cryptographic implementations.

---

## Disclosure Process

Reported vulnerabilities will be evaluated based on:

1. Reproducibility
2. Security impact
3. Affected components
4. Exploitability
5. Potential scope of impact

Where appropriate, fixes may be developed privately before public disclosure.

A security advisory may be published after remediation and coordinated disclosure.

---

## Security Contact

A dedicated security contact will be published here before the first stable release.

Until then, security researchers should use the repository's available private communication channels rather than publicly disclosing potentially exploitable vulnerabilities.

---

## Disclaimer

Sentinel System is an Alpha project.

Security guarantees should not be assumed from the current implementation. Users deploying Sentinel System are responsible for applying appropriate network isolation, access controls, secret management, monitoring, and other operational security measures.
