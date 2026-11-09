#!/usr/bin/env python3
"""Strict stdlib preflight for test DNA key syntax and count, NOT source trust."""
import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path

class ConfigError(Exception):
    pass

def location(core):
    h = hashlib.blake2b(core, digest_size=16).digest()
    return bytes(h[i] ^ h[i+4] ^ h[i+8] ^ h[i+12] for i in range(4))

def agent_key(s):
    if not s.startswith("u") or len(s) != 53:
        raise ConfigError("agent key must be canonical Holochain base64url")
    try:
        raw = base64.urlsafe_b64decode(s[1:] + "===")
    except (ValueError, binascii.Error) as exc:
        raise ConfigError("invalid agent key text") from exc
    if len(raw) != 39 or raw[:3] != bytes([0x84,0x20,0x24]) or location(raw[3:35]) != raw[35:]:
        raise ConfigError("agent key length, prefix or checksum invalid")
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != s[1:]:
        raise ConfigError("noncanonical agent key spelling")
    return raw[3:35]

def rt_key(s):
    try:
        k = base64.b64decode(s, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ConfigError("invalid Roughtime standard base64") from exc
    if len(k) != 32 or base64.b64encode(k).decode() != s:
        raise ConfigError("Roughtime key must be 32 canonical bytes")
    return k

def keys_under(lines, name):
    ids = [i for i, x in enumerate(lines) if re.fullmatch(r"    " + name + r":\s*", x)]
    if len(ids) != 1:
        raise ConfigError("expected one DNA properties list: " + name)
    keys = []
    for line in lines[ids[0]+1:]:
        if not line.strip() or line.lstrip().startswith("#"): continue
        m = re.fullmatch(r'      - "([^"]+)"\s*', line)
        if not m: break
        keys.append(m.group(1))
    return keys

def check(s):
    if "REPLACE_WITH" in s:
        raise ConfigError("placeholder keys present")
    lines = s.splitlines()
    def num(field):
        hits = re.findall(r"^    " + field + r":\s*(\d+)\s*$",s,re.M)
        if len(hits)!=1: raise ConfigError("missing/ambiguous "+field)
        return int(hits[0])
    f, n = num("max_faulty"),num("min_sources")
    if f < 0 or n < 1 or n > 32 or n < 2*f+1:
        raise ConfigError("invalid fault quorum")
    rt = [rt_key(k) for k in keys_under(lines,"roughtime_servers")]
    oracle = [agent_key(k) for k in keys_under(lines,"oracles")]
    sources = rt + oracle
    if len(sources) != len(set(sources)):
        raise ConfigError("duplicate trusted key")
    if len(sources) < n+f:
        raise ConfigError("insufficient independent keys for outage-count promise")
    return {"key_format":"valid", "roughtime_count":len(rt),"oracle_count":len(oracle),
            "min_sources":n,"max_faulty":f,"operator_independence_proven":False,
            "bundle_manifest_match_proven":False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest",type=Path,required=True)
    args=parser.parse_args()
    try: result=check(args.manifest.read_text(encoding="utf8"))
    except (OSError,ConfigError) as exc:
        print(json.dumps({"status":"BLOCKED","reason":str(exc)}));return 3
    print(json.dumps({"status":"PREFLIGHT_ONLY",**result},sort_keys=True));return 0

if __name__=="__main__":sys.exit(main())
