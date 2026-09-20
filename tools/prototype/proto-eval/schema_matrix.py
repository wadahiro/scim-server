#!/usr/bin/env python3
"""Task 1: schema-driven enforcement + type conformance checks.

Usage: python3 schema_matrix.py <base_url> <output_json_path>
e.g.   python3 schema_matrix.py http://127.0.0.1:3300/scim/v2 schema_matrix.json
"""
import json
import sys
from collections import Counter

from lib import Client
from schema_walk import walk_schemas
import checks


def run(base_url, out_path):
    client = Client(base_url)
    r = client.get("/Schemas")
    if r.status != 200:
        print(f"FATAL: GET /Schemas failed: {r.status} {r.body[:300]}")
        sys.exit(1)
    schemas_json = r.json()
    nodes = walk_schemas(schemas_json)

    total_node_count = len(nodes) + sum(
        1 for res in schemas_json["Resources"] if res["name"] == "ServiceProviderConfig"
        for _ in _count(res)
    )
    print(f"Walked {len(nodes)} attribute/sub-attribute nodes (excluding ServiceProviderConfig).")

    results = []

    def flush():
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)

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

        flush()

    flush()
    print_summary(results)
    return results


def _count(res):
    def rec(attrs):
        for a in attrs:
            yield a
            if a.get("subAttributes"):
                yield from rec(a["subAttributes"])
    return list(rec(res.get("attributes", [])))


def print_summary(results):
    verdicts = Counter(r["verdict"] for r in results)
    chars = Counter(r["characteristic"] for r in results)
    print("\n=== SUMMARY ===")
    print(f"Total cells: {len(results)}")
    for v in ("PASS", "FAIL", "SKIP", "ERROR"):
        print(f"  {v}: {verdicts.get(v, 0)}")
    print("\nCells per characteristic:")
    for c, n in sorted(chars.items()):
        print(f"  {c}: {n}")

    fails = [r for r in results if r["verdict"] == "FAIL"]
    print(f"\n=== FAILS ({len(fails)}) ===")
    for f in fails:
        print(f"- [{f['resource']}] {f['attribute']} :: {f['characteristic']} ({f['method']})")
        print(f"    basis: {f['basis'].get('rfc')} {f['basis'].get('section')} {f['basis'].get('lines')}")
        print(f"    detail: {f['detail']}")


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3300/scim/v2"
    out = sys.argv[2] if len(sys.argv) > 2 else "schema_matrix.json"
    run(base, out)
