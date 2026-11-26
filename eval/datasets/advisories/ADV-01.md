# Advisory ADV-01 — Active exploitation of PAN-OS GlobalProtect command injection

**Severity:** Critical · **Status:** exploitation observed · **Audience:** network and SOC teams

## Summary
Threat actors are exploiting CVE-2024-3400, an unauthenticated command injection in the GlobalProtect
feature of Palo Alto Networks PAN-OS. Successful exploitation gives root command execution on the firewall.

## Observed activity (MITRE ATT&CK)
- T1190 Exploit Public-Facing Application — crafted SESSID cookie sent to the GlobalProtect portal.
- T1059.004 Unix Shell — commands executed through bash on the appliance.
- T1053.003 Cron — a cron job fetches a script every minute for persistence.

## Indicators of compromise
| Type | Indicator |
|---|---|
| IPv4 | 198.51.100[.]77 |
| IPv4 | 203.0.113[.]41 |
| URL | hxxps://kq7-sync-portal[.]top/update/policy.py |
| SHA-256 (policy.py) | 439f6ff71c4df2d450c338f61b649b564346bb8e7eaf15b0ab1fa2336da532a7 |

## Recommended actions
Apply the vendor hotfix for your PAN-OS 10.2 / 11.0 / 11.1 train, hunt for the cron entry and the indicators
above, and rotate any credentials stored on the device if compromise is suspected.
