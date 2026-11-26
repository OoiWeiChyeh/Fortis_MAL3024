VENDOR BULLETIN ADV-06 — OpenSSH signal-handler race condition (regreSSHion)

CVE-2024-6387 is a race condition in the SIGALRM handler of OpenSSH sshd (8.5p1 up to 9.7p1) on glibc-based
Linux. A remote unauthenticated attacker may gain root code execution, but exploitation needs thousands of
attempts over several hours against 32-bit targets; no reliable in-the-wild exploitation is reported.
Initial access path: exploitation of an internet-facing service.

Mitigation: upgrade to OpenSSH 9.8p1, or set LoginGraceTime 0 in sshd_config as a temporary measure
(this exposes sshd to connection exhaustion). No indicators of compromise are published.
