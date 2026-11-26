# Advisory ADV-04 — Mass data theft through MOVEit Transfer SQL injection

## Summary
An extortion group exploited CVE-2023-34362, a SQL injection in Progress MOVEit Transfer, to install a web
shell (human2.aspx) and steal files from hundreds of organisations.

## Techniques
T1190 (Exploit Public-Facing Application) · T1505.003 (Web Shell) · T1567 (Exfiltration Over Web Service)

## Indicators
- Web shell SHA-256: e22d0ba6f3d3774800b3f8e5f37ae94cbaa843d33461c31324199cdbb61fa767
- Exploitation sources: 198.51.100[.]133, 192.0.2[.]61
- Exfiltration host: dl-mvt-archive[.]cloud

## Actions
Patch MOVEit Transfer, review the IIS logs for requests to human2.aspx, and search for the web shell hash.
