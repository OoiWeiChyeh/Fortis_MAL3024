"""
Validates triage exports with the reference open-source parsers (not Fortis's own
code): OASIS stix2 for STIX 2.1 objects and patterns, SigmaHQ pySigma for Sigma
rules, plus a Navigator layer shape check.

    pip install stix2 pysigma        # in a separate venv; not a Fortis dependency
    python eval/validate_exports.py "%APPDATA%\Fortis\reports"

Validates the newest *.stix.json / *.sigma.yml / *.layer.json in the folder.
"""
import glob
import json
import os
import sys
from importlib.metadata import version

d = sys.argv[1]
stix_path = max(glob.glob(os.path.join(d, "*.stix.json")), key=os.path.getmtime)
sigma_path = max(glob.glob(os.path.join(d, "*.sigma.yml")), key=os.path.getmtime)
layer_path = max(glob.glob(os.path.join(d, "*.layer.json")), key=os.path.getmtime)

print(f"$ validate {os.path.basename(stix_path)}  (stix2 {version('stix2')})")
import stix2
from stix2.pattern_visitor import create_pattern_object

bundle = stix2.parse(open(stix_path, encoding="utf-8").read(), allow_custom=False)
counts = {}
for o in bundle.objects:
    counts[o.type] = counts.get(o.type, 0) + 1
    if o.type == "indicator":
        create_pattern_object(o.pattern)  # raises on invalid STIX patterning grammar
print(f"  OK  strict STIX 2.1 parse, {len(bundle.objects)} objects: {counts}")
print(f"  OK  every indicator pattern parses under the STIX patterning grammar")
for o in bundle.objects:
    if o.type == "indicator":
        print(f"      {o.pattern}")

print(f"\n$ validate {os.path.basename(sigma_path)}  (pySigma {version('pysigma')})")
from sigma.collection import SigmaCollection

coll = SigmaCollection.from_yaml(open(sigma_path, encoding="utf-8").read())
errors = [e for r in coll.rules for e in getattr(r, "errors", [])] + list(getattr(coll, "errors", []))
for r in coll.rules:
    print(f"  OK  {r.level.name.lower():8s} {r.logsource.category:16s} {r.title[-45:]}")
print(f"  {'OK' if not errors else 'FAIL'}  {len(coll.rules)} Sigma rules parsed, {len(errors)} errors")

print(f"\n$ validate {os.path.basename(layer_path)}")
layer = json.load(open(layer_path, encoding="utf-8"))
assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"]
print(f"  OK  Navigator layer v{layer['versions']['layer']}, ATT&CK v{layer['versions']['attack']}, "
      f"{len({t['techniqueID'] for t in layer['techniques']})} techniques: "
      f"{sorted({t['techniqueID'] for t in layer['techniques']})}")
