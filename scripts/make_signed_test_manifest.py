#!/usr/bin/env python3
"""Generate a throwaway signed-quorum DNA from TEST-ONLY public keys."""
import argparse
import base64
import binascii
import json
import re
import secrets
import sys
from pathlib import Path

class ManifestError(Exception):
    pass

def canonical_key(value):
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ManifestError("invalid base64 Roughtime public key") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode() != value:
        raise ManifestError("Roughtime key must be canonical 32-byte standard base64")
    return raw

def make_manifest(template, fixture, seed):
    if fixture.get("test_only") is not True:
        raise ManifestError("fixture must be explicitly test_only")
    keys = fixture.get("roughtime_servers")
    if not isinstance(keys, list) or len(keys) != 4 or not all(isinstance(k, str) for k in keys):
        raise ManifestError("need exactly four public Roughtime test keys")
    raw = [canonical_key(k) for k in keys]
    if len(set(raw)) != 4:
        raise ManifestError("duplicate test signer identity")
    if not re.fullmatch(r"[a-f0-9]{16,64}", seed):
        raise ManifestError("invalid test network seed")
    if "REPLACE_WITH" not in template:
        raise ManifestError("source must be the checked-in placeholder DNA; won't overwrite real keys")
    rt = re.compile(r'(?m)^    roughtime_servers:\s*\n(?:      - "[^"]+"\s*\n)+')
    ora = re.compile(r'(?m)^    oracles:\s*\n(?:      - "[^"]+"\s*\n)+')
    if len(rt.findall(template)) != 1 or len(ora.findall(template)) != 1:
        raise ManifestError("unexpected DNA manifest key layout")
    value = rt.sub('    roughtime_servers:\n' + ''.join(
        '      - "' + k + '"\n' for k in keys), template)
    value = ora.sub('    oracles: []\n', value)
    if value.count("  network_seed: ~") != 1:
        raise ManifestError("source network seed must be null")
    value = value.replace("  network_seed: ~",
        '  network_seed: "DO-NOT-DEPLOY-signed-quorum-' + seed + '"')
    if "REPLACE_WITH" in value or not value.startswith("---\n"):
        raise ManifestError("test manifest replacement incomplete")
    return "# HC_VTIME_SIGNED_TEST_ONLY -- known insecure keys -- NEVER DEPLOY\n" + value

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--template", type=Path, required=True)
    ap.add_argument("--fixture-json", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--run-seed", default=None)
    a = ap.parse_args()
    try:
        fixture = json.loads(a.fixture_json.read_text(encoding="utf8"))
        result = make_manifest(a.template.read_text(encoding="utf8"), fixture,
                               a.run_seed or secrets.token_hex(12))
        a.out.write_text(result, encoding="utf8")
    except (OSError, ValueError, TypeError, ManifestError) as exc:
        print("BLOCKED:", exc, file=sys.stderr)
        return 3
    print("Created public-key-only TEST DNA manifest; NEVER deploy it")
    return 0

if __name__ == "__main__":
    sys.exit(main())
