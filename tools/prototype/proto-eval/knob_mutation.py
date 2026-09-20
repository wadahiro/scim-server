#!/usr/bin/env python3
"""Task 2: detection power of the 7 compatibility knobs.

For each knob, starts the server with only that knob flipped away from its
default, runs the full schema_matrix check set plus 3 hand-written probes,
and compares the resulting verdicts against an all-defaults baseline.

Must be run in the foreground; total runtime is a few tens of seconds
(8 server start/stop cycles).
"""
import json
import os
import subprocess
import sys
import time
from collections import Counter

from lib import Client
from schema_walk import walk_schemas
import checks
from extra_checks import run_extra_checks

BINARY = "/Users/wadahiro/dev/src/github.com/wadahiro/scim-server/target/debug/scim-server"
OUTDIR = os.path.dirname(os.path.abspath(__file__))

DEFAULTS = {
    "meta_datetime_format": "rfc3339",
    "show_empty_groups_members": True,
    "include_user_groups": True,
    "support_group_members_filter": True,
    "support_group_displayname_filter": True,
    "support_patch_replace_empty_array": True,
    "support_patch_replace_empty_value": False,
}

# one knob flipped away from its default, all others at default
KNOB_FLIPS = {
    "meta_datetime_format": "epoch",
    "show_empty_groups_members": False,
    "include_user_groups": False,
    "support_group_members_filter": False,
    "support_group_displayname_filter": False,
    "support_patch_replace_empty_array": False,
    "support_patch_replace_empty_value": True,
}

PORTS = {
    "baseline": 3301,
    "meta_datetime_format": 3302,
    "show_empty_groups_members": 3303,
    "include_user_groups": 3304,
    "support_group_members_filter": 3305,
    "support_group_displayname_filter": 3306,
    "support_patch_replace_empty_array": 3307,
    "support_patch_replace_empty_value": 3308,
}


def yaml_bool(v):
    return "true" if v else "false"


def render_compat_block(values):
    lines = ["compatibility:"]
    for k, v in values.items():
        if isinstance(v, bool):
            lines.append(f'  {k}: {yaml_bool(v)}')
        else:
            lines.append(f'  {k}: "{v}"')
    return "\n".join(lines)


def write_config(path, port, compat_values):
    compat_block = render_compat_block(compat_values)
    content = f"""server: {{host: "127.0.0.1", port: {port}}}
backend: {{type: "database", database: {{type: "sqlite", url: ":memory:", max_connections: 1}}}}
tenants:
  - id: 1
    path: "/scim/v2"
    auth: {{type: "unauthenticated"}}
{compat_block}
"""
    with open(path, "w") as f:
        f.write(content)


def start_server(cfg_path, port):
    proc = subprocess.Popen(
        [BINARY, "-c", cfg_path, "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return proc


def wait_ready(port, timeout=10):
    client = Client(f"http://127.0.0.1:{port}/scim/v2")
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get("/ServiceProviderConfig")
        if r.status == 200:
            return True
        time.sleep(0.3)
    return False


def stop_server(proc, port):
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    subprocess.run(["pkill", "-f", f"scim-server -c .* --port {port}"], check=False)
    subprocess.run(["pkill", "-f", f"scim-server --port {port}"], check=False)


def collect(base_url):
    client = Client(base_url)
    r = client.get("/Schemas")
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
    return results


def key_of(row):
    return (row["resource"], row["attribute"], row["characteristic"], row["method"])


def run_one(name, compat_values, port):
    cfg_path = os.path.join(OUTDIR, f"config_{name}.yaml")
    write_config(cfg_path, port, compat_values)
    proc = start_server(cfg_path, port)
    try:
        time.sleep(3)
        ok = wait_ready(port)
        if not ok:
            print(f"FATAL: server for {name} on port {port} did not become ready")
            return None
        results = collect(f"http://127.0.0.1:{port}/scim/v2")
        return results
    finally:
        stop_server(proc, port)


def main():
    all_results = {}

    print("=== baseline (all defaults) ===")
    all_results["baseline"] = run_one("baseline", DEFAULTS, PORTS["baseline"])
    if all_results["baseline"] is None:
        print("FATAL: baseline run failed"); sys.exit(1)
    with open(os.path.join(OUTDIR, "knob_baseline.json"), "w") as f:
        json.dump(all_results["baseline"], f, indent=2)
    baseline_map = {key_of(r): r["verdict"] for r in all_results["baseline"]}
    print(f"baseline: {len(all_results['baseline'])} checks")

    knob_summary = {}
    for knob, flipped_value in KNOB_FLIPS.items():
        values = dict(DEFAULTS)
        values[knob] = flipped_value
        print(f"\n=== knob: {knob} = {flipped_value} (default {DEFAULTS[knob]}) ===")
        results = run_one(knob, values, PORTS[knob])
        if results is None:
            knob_summary[knob] = {"error": "server did not start"}
            continue
        all_results[knob] = results
        knob_map = {key_of(r): r["verdict"] for r in results}

        changed = []
        for k, base_verdict in baseline_map.items():
            knob_verdict = knob_map.get(k)
            if knob_verdict is None:
                changed.append({"key": k, "baseline": base_verdict, "knob": "MISSING"})
            elif knob_verdict != base_verdict:
                changed.append({"key": k, "baseline": base_verdict, "knob": knob_verdict})
        # keys present only in knob run (shouldn't normally happen; same schema)
        for k in knob_map:
            if k not in baseline_map:
                changed.append({"key": k, "baseline": "MISSING", "knob": knob_map[k]})

        knob_summary[knob] = {
            "flipped_to": flipped_value,
            "default": DEFAULTS[knob],
            "num_changed": len(changed),
            "changed": changed,
        }
        print(f"  changed checks: {len(changed)}")
        for c in changed:
            print(f"    {c['key']}: baseline={c['baseline']!r} -> knob={c['knob']!r}")

    out = {
        "defaults": DEFAULTS,
        "flips": KNOB_FLIPS,
        "knob_summary": knob_summary,
    }
    with open(os.path.join(OUTDIR, "knob_mutation.json"), "w") as f:
        json.dump(out, f, indent=2)

    for name, results in all_results.items():
        if results is None:
            continue
        with open(os.path.join(OUTDIR, f"knob_full_{name}.json"), "w") as f:
            json.dump(results, f, indent=2)

    print("\n=== DETECTION TABLE ===")
    for knob, info in knob_summary.items():
        if "error" in info:
            print(f"{knob}: ERROR - {info['error']}")
            continue
        detected = "DETECTED" if info["num_changed"] > 0 else "NOT DETECTED"
        print(f"{knob} (default={info['default']!r} -> {info['flipped_to']!r}): {detected} ({info['num_changed']} changed checks)")


if __name__ == "__main__":
    main()
