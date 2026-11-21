# Security Policy

## Reporting a Vulnerability

If you discover a firewall bypass, PII leakage vector, wire-protocol crash, or authentication issue in **pgveil**, please report it responsibly rather than opening a public issue:

- Use GitHub's **Private Vulnerability Reporting** ("Security" tab → "Report a vulnerability"), or
- Email `duhan06@gmail.com` with `[pgveil-security]` in the subject line.

Please include:
- A minimal SQL payload or wire reproduction case
- Active `pgveil.yaml` role profile configuration
- Expected vs. observed behavior

We aim to acknowledge reports within **48 hours** and release fixes with regression test cases promptly.
