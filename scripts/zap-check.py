#!/usr/bin/env python3
"""Fails on ZAP baseline alerts of medium or high risk that .zap/rules.tsv
does not accept with a reason (M19, G3)."""
import json
import sys

report, rules = sys.argv[1], sys.argv[2]
accepted = {}
for line in open(rules, encoding="utf-8"):
    if line.startswith("#") or not line.strip():
        continue
    parts = line.rstrip("\n").split("\t")
    if len(parts) >= 3 and parts[1] == "ACCEPTED" and parts[2].strip():
        accepted[parts[0]] = parts[2]

data = json.load(open(report, encoding="utf-8"))
failed = []
for site in data.get("site", []):
    for a in site.get("alerts", []):
        risk = int(a.get("riskcode", "0"))
        name = f'{a.get("pluginid")} {a.get("name")} (risk {a.get("riskdesc")}, {a.get("count")} instances)'
        print(("ACCEPTED " if a.get("pluginid") in accepted else "") + name)
        if risk >= 2 and a.get("pluginid") not in accepted:
            failed.append(name)
for f in failed:
    print(f"::error::ZAP: {f}")
sys.exit(1 if failed else 0)
