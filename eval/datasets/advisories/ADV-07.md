# Advisory ADV-07 — Chained Ivanti Connect Secure authentication bypass and command injection

Threat actors chain CVE-2023-46805 (authentication bypass) with CVE-2024-21887 (command injection) in Ivanti
Connect Secure and Policy Secure gateways to run commands as root, then deploy web shells into legitimate
CGI files.

ATT&CK: T1190, T1059 (Command and Scripting Interpreter), T1505.003 (Web Shell).

IOCs
- 192.0.2[.]230
- 203.0.113[.]17
- ivt-sync-cdn[.]xyz
- web shell (modified compcheckresult.cgi) SHA256 11595fd13a17bed884bd41ea33c9f60404f4f7fbd03356fd99ab696e77541e20
- dropper MD5 7b2c52b74fc7f13dde4bedcd11e0a39d

Run the vendor's external integrity checker; apply the mitigation XML until patched.
