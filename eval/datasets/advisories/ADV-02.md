MyCERT-style ADVISORY ADV-02
Title: Session hijacking through NetScaler information disclosure
Sectors affected: banking and financial services, government

1.0 Introduction
Attackers are abusing an information-disclosure flaw, CVE-2023-4966 ("Citrix Bleed"), in Citrix NetScaler ADC
and NetScaler Gateway. The flaw leaks memory
that contains valid session tokens.

2.0 Impact
Stolen session cookies are replayed from attacker infrastructure, which bypasses passwords and MFA. The
actors then log in as legitimate users and move to internal systems.

3.0 Indicators
Replay sources: 192.0.2[.]144, 198.51.100[.]9
Operator mailbox used in follow-on phishing: it-helpdesk[at]nsg-verify[.]xyz
Staging domain: nsg-verify[.]xyz

4.0 Recommendation
Upgrade to a fixed build (14.1-8.50 / 13.1-49.15 or later), then terminate all active and persistent sessions,
because tokens stolen before patching remain valid.
