# Advisory ADV-10 — Jenkins CLI arbitrary file read exploited

CVE-2024-23897 in the Jenkins built-in command line interface lets an unauthenticated attacker read
arbitrary files on the controller (the args4j "@file" expansion feature). Attackers read secrets such as
credentials.xml and master.key, then use them to run code. Ransomware affiliates have used it.

Affected: Jenkins 2.441 and earlier, LTS 2.426.2 and earlier. Fixed: 2.442 / LTS 2.426.3.

ATT&CK: T1190 Exploit Public-Facing Application; T1552.001 Credentials In Files; T1005 Data from Local System.

Observed source addresses: 203.0.113[.]150, 198.51.100[.]5
