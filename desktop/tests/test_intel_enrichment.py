"""Tests for the vendored ATT&CK / CISA KEV catalogues and enrichment."""
import re

from core.intel import enrich, sync


def test_catalogues_load_with_versions():
    v = enrich.catalogue_versions()
    assert v["attack"] not in ("", "None")
    assert re.match(r"^\d{4}\.\d{2}\.\d{2}$", v["kev"])
    assert len(enrich.attack_catalogue()["techniques"]) > 600
    assert enrich.kev_catalogue()["count"] > 1000


def test_technique_status():
    assert enrich.technique_status("T1566.001") == "valid"
    assert enrich.technique_status("t1190") == "valid"
    assert enrich.technique_status("T9999") == "unknown"
    revoked = next(k for k, v in enrich.attack_catalogue()["techniques"].items() if v["revoked"])
    assert enrich.technique_status(revoked) == "revoked"


def test_kev_lookup():
    pan = enrich.lookup_kev("cve-2024-3400")
    assert pan and pan["vendor"].startswith("Palo Alto")
    assert enrich.lookup_kev("CVE-2099-0001") is None


def test_enrich_text_end_to_end():
    out = {d["value"]: d for d in enrich.enrich_text("CVE-2024-3400 via T1190; fake T9999; 1.2.3[.]4")}
    assert out["CVE-2024-3400"]["kev"] is True
    assert out["T1190"]["status"] == "valid" and "initial-access" in out["T1190"]["tactics"]
    assert out["T9999"]["status"] == "unknown"
    assert out["1.2.3.4"]["defanged"] is True


def test_sync_builders_treat_feeds_as_untrusted():
    bundle = {"objects": [
        {"type": "attack-pattern", "name": "X" * 1000,
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1234"}]},
        {"type": "attack-pattern", "name": "bad id",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T12;rm -rf"}]},
    ]}
    attack = sync.build_attack(bundle)
    assert list(attack["techniques"]) == ["T1234"]
    assert len(attack["techniques"]["T1234"]["name"]) == 160

    kev = sync.build_kev({"vulnerabilities": [
        {"cveID": "cve-2024-0001", "dateAdded": "2024-01-01", "cwes": ["CWE-79", "<script>"]},
        {"cveID": "not-a-cve"},
    ]})
    assert list(kev["vulnerabilities"]) == ["CVE-2024-0001"]
    assert kev["vulnerabilities"]["CVE-2024-0001"]["cwes"] == ["CWE-79"]
