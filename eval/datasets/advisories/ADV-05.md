# Advisory ADV-05 — FortiOS SSL-VPN out-of-bounds write exploited

**Affected:** Fortinet FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13 with SSL-VPN enabled.

CVE-2024-21762 lets an unauthenticated attacker run code through crafted HTTP requests to the SSL-VPN
daemon. Exploitation is confirmed (MITRE ATT&CK T1190, followed by T1133 External Remote Services using
created VPN accounts).

Indicators: scanning and exploitation from 203.0.113[.]88 and 198.51.100[.]250; payload
fetched from hxxps://fgt-cfg-backup[.]top/x/sslvpnd.

Workaround: disable SSL-VPN (disabling the web mode alone is not enough). Fix: upgrade to 7.4.3 / 7.2.7 / 7.0.14.
Management interface netmask in the vendor example is 255.255.255.0 — not an indicator.
