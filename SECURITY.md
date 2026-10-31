# Security Policy

Thank you for helping keep this project and its users safe.

## Supported Versions

This package follows [SemVer](https://semver.org/). Security fixes are released for the latest version of the current major branch.

| Version | Supported          |
|---------|--------------------|
| 2.x     | :white_check_mark: |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

This package implements an SSH server — including key exchange, authentication, host-key handling, and packet parsing — so please report suspected security vulnerabilities **privately** instead of opening a public GitHub issue.

Use GitHub's private vulnerability reporting form:

<https://github.com/WilliamEggers/reactphp-ssh-server/security/advisories/new>

When reporting, please include as much of the following as possible:

- the affected version(s) of `williameggers/reactphp-ssh-server`;
- a description of the issue and the code path involved;
- steps or proof-of-concept code to reproduce the behavior.

Reports are typically acknowledged within seven days. The maintainer will work with you to coordinate disclosure, including a security advisory and CVE assignment where appropriate.

## Scope Note

This library is not presented as hardened for exposure to untrusted public networks. Operational guidance — host keys, authentication strategies, and connection restrictions — is available in the README and the `examples/` directory.
