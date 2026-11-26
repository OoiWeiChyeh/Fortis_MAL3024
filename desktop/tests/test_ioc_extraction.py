"""Unit tests for deterministic IOC extraction (core/intel/ioc.py)."""
from datetime import date

import pytest

from core.intel.ioc import defang, extract_iocs, iocs_by_type, refang

TODAY = date(2026, 11, 22)

ADVISORY = """
MyCERT observed phishing from hxxps://login-maybank2u[.]com[.]my-secure[.]xyz/verify?id=7
and payloads served from 185.220.101[.]47. Contact: abuse[at]evil-actor[.]top
Exploited: CVE‑2024‑3400 (PAN-OS) and cve-2023-4966; techniques T1566.001 and T1190.
Dropper SHA256: 3F79BB7B435B05321651DAEFD374CDC681DC06FAA65E374CB337B7B5A8D2A6D6
MD5 d41d8cd98f00b204e9800998ecf8427e
"""


def by_type(text):
    return iocs_by_type(extract_iocs(text, today=TODAY))


def test_realistic_defanged_advisory():
    got = by_type(ADVISORY)
    assert got["url"] == ["https://login-maybank2u.com.my-secure.xyz/verify?id=7"]
    assert "login-maybank2u.com.my-secure.xyz" in got["domain"]
    assert "evil-actor.top" in got["domain"]
    assert got["ipv4"] == ["185.220.101.47"]
    assert got["email"] == ["abuse@evil-actor.top"]
    assert got["cve"] == ["CVE-2023-4966", "CVE-2024-3400"]
    assert got["attack_technique"] == ["T1190", "T1566.001"]
    assert got["sha256"] == ["3f79bb7b435b05321651daefd374cdc681dc06faa65e374cb337b7b5a8d2a6d6"]
    assert got["md5"] == ["d41d8cd98f00b204e9800998ecf8427e"]


def test_defanged_flag_and_context():
    iocs = {i.value: i for i in extract_iocs(ADVISORY, today=TODAY)}
    assert iocs["185.220.101.47"].defanged is True
    assert iocs["CVE-2024-3400"].defanged is False
    assert "PAN-OS" in iocs["CVE-2024-3400"].context


@pytest.mark.parametrize("text", [
    "Run setup.sh then open README.md and vulnerable-app.py",
    "unzip invoice.zip and play demo.mov",
    "return self.name if request.host else user.email",
    "session.id = obj.to(device)",
    "Upgrade to version 10.0.0.1 or v1.2.3.4",
    "build 2.4.6.8 shipped",
    "Timestamp 12:30:45 and MAC de:ad:be:ef:00:11",
    "Not a hash: 0123456789abcdef0123456789abcdef0123456789abcdef (48 hex)",
    "999.1.1.1 and 1.2.3 are not addresses",
    "CVE-1980-1234 and CVE-2099-0001 are out of range",
    # Cisco config values (found in training/sample-lab-docs/firewall-config.txt)
    "access-list 10 permit any 0.0.0.255 ! wildcard 0.0.255.255",
    "ip address x 255.255.255.0 / 255.255.0.0 ; bind 0.0.0.0 ; bcast 255.255.255.255",
])
def test_false_positive_traps(text):
    assert extract_iocs(text, today=TODAY) == []


def test_ambiguous_tld_accepted_with_strong_signal():
    got = by_type("payload at hxxp://update-check[.]zip/a and c2 at files[.]sh")
    assert "update-check.zip" in got["domain"]
    assert "files.sh" in got["domain"]


def test_code_like_cctld_needs_three_labels():
    assert by_type("phish kit on bank-login.co.id")["domain"] == ["bank-login.co.id"]
    assert by_type("user.id") == {}


def test_malaysian_domains_kept():
    got = by_type("Lure mimics www.hasil.gov.my and portal.kwsp.gov.my")
    assert got["domain"] == ["portal.kwsp.gov.my", "www.hasil.gov.my"]


def test_private_ip_is_annotated_not_dropped():
    [ioc] = extract_iocs("beacon to 10.0.0.5", today=TODAY)
    assert ioc.value == "10.0.0.5" and "private/reserved" in ioc.notes


def test_hash_not_sliced_from_longer_hex():
    # a 64-char sha256 must not also yield md5/sha1 sub-strings
    got = by_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert list(got) == ["sha256"]


def test_url_trailing_punctuation_and_brackets():
    got = by_type("See (https://example.org/a_(b)) and https://example.net/x.")
    assert got["url"] == ["https://example.net/x", "https://example.org/a_(b)"]


def test_deduplication_and_case_normalisation():
    got = by_type("EVIL.COM evil.com evil[.]com CVE-2024-3400 cve-2024-3400")
    assert got == {"domain": ["evil.com"], "cve": ["CVE-2024-3400"]}


def test_ipv6():
    got = by_type("C2 2001:db8::dead:beef and 2001:0db8:0000:0000:0000:0000:0000:0001")
    assert got["ipv6"] == ["2001:db8::1", "2001:db8::dead:beef"]


def test_refang_and_defang_round_trip():
    assert refang("hxxps[:]//a[.]b[.]com") == "https://a.b.com"
    assert defang("https://evil.com/x.php", "url") == "hxxps://evil[.]com/x.php"
    assert defang("1.2.3.4", "ipv4") == "1[.]2[.]3[.]4"
    assert defang("a@b.com", "email") == "a[@]b[.]com"


def test_never_invents_indicators():
    """Every extracted value must be recoverable from the refanged source."""
    src = refang(ADVISORY).lower()
    for ioc in extract_iocs(ADVISORY, today=TODAY):
        assert ioc.value.lower() in src, ioc


def test_empty_input():
    assert extract_iocs("") == []


def test_phrased_version_strings_are_not_ips():
    # found by eval/ioc_bench.py: "the loader version string is 4.2.0.1"
    from core.intel.ioc import extract_iocs
    ips = lambda t: [i.value for i in extract_iocs(t) if i.type == "ipv4"]
    assert ips("the loader version string is 4.2.0.1 here") == []
    assert ips("build number: 6.1.0.3; firmware 7.2.6.1") == []
    # a real address after an unrelated mention of "version" still counts
    assert ips("connect to 198.51.100.4 for the version check") == ["198.51.100.4"]
    assert ips("released v2, then contacted 198.51.100.8") == ["198.51.100.8"]
