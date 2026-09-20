#!/usr/bin/env python3
"""Runs the full schema_matrix check set + the 3 knob-probe checks against
one running server, and writes the combined result list to a JSON file.

Usage: python3 collect_full.py <base_url> <output_json_path>
"""
import json
import sys

from lib import Client
from schema_walk import walk_schemas
import checks
from extra_checks import run_extra_checks


def main(base_url, out_path):
    client = Client(base_url)
    r = client.get("/Schemas")
    if r.status != 200:
        print(f"FATAL: GET /Schemas failed: {r.status} {r.body[:300]}")
        sys.exit(1)
    nodes = walk_schemas(r.json())

    results = []
    for node in nodes:
        d = node.definition
        mut = d.get("mutability")
        if mut == "readOnly":
            results.extend(checks.check_readonly(client, node))
        if mut == "immutable":
            results.extend(checks.check_immutable(client, node))
        if d.get("required"):
            results.extend(checks.check_required(client, node))
        if d.get("caseExact"):
            results.extend(checks.check_caseexact(client, node))
        if d.get("uniqueness") in ("server", "global"):
            results.extend(checks.check_uniqueness(client, node))
        if d.get("returned") == "never":
            results.extend(checks.check_returned_never(client, node))
        if mut != "readOnly":
            results.extend(checks.check_type(client, node))

    results.extend(run_extra_checks(client))

    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    from collections import Counter
    v = Counter(x["verdict"] for x in results)
    print(f"{out_path}: total={len(results)} " + " ".join(f"{k}={v.get(k,0)}" for k in ("PASS", "FAIL", "SKIP", "ERROR")))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
