VENDOR BULLETIN ADV-12 — Cisco IOS XE web UI privilege escalation exploited

Cisco reports active exploitation of CVE‑2023‑20198 (note: published with a non-breaking hyphen) in the web
UI feature of Cisco IOS XE software when "ip http server" or "ip http secure-server" is enabled. Attackers
create a local level-15 account, then implant a configuration-file web shell.

Example vulnerable config line: ip http server  — on devices with management address 10.10.1.1 (internal,
not an indicator) and wildcard mask 0.0.0.255.

Indicators: implant check URL hxxps://ios-cfg-check[.]xyz/webui/logoutconfirm.html;
exploitation from 192.0.2[.]17.
Affected software train 17.9.3 is referenced as a version number, not an address.

Mitigation: disable the HTTP server feature on internet-facing devices and upgrade to a fixed release.
