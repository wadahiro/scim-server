"""Three hand-written knob-sensitive probes for Task 2."""
from lib import base_user, base_group, USER_URN

PATCHOP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


def _shape(v, present):
    if not present:
        return "absent"
    if v is None:
        return "null"
    if isinstance(v, list) and len(v) == 0:
        return "empty_array"
    return f"non_empty:{v!r}"[:60]


def check_empty_members_shape(client):
    payload = base_group()
    r = client.post("/Groups", payload)
    if r.status not in (200, 201):
        return [{"attribute": "members", "schema": "Group", "resource": "Group",
                  "characteristic": "knob_probe_empty_members_shape", "method": "POST",
                  "verdict": "ERROR", "basis": {}, "detail": f"create failed: {r.status} {r.body[:150]}"}]
    gid = r.json()["id"]
    rg = client.get(f"/Groups/{gid}")
    rj = rg.json() or {}
    present = "members" in rj
    shape = _shape(rj.get("members"), present)
    return [{
        "attribute": "members", "schema": "Group", "resource": "Group",
        "characteristic": "knob_probe_empty_members_shape", "method": "GET",
        "verdict": shape, "basis": {}, "detail": f"GET of empty group -> members={rj.get('members')!r} present={present}",
    }]


def check_user_groups_presence(client):
    u = base_user()
    ru = client.post("/Users", u)
    if ru.status not in (200, 201):
        return [{"attribute": "groups", "schema": "User", "resource": "User",
                  "characteristic": "knob_probe_user_groups_presence", "method": "POST",
                  "verdict": "ERROR", "basis": {}, "detail": f"create user failed: {ru.status}"}]
    uid = ru.json()["id"]
    g = base_group()
    g["members"] = [{"value": uid, "type": "User"}]
    rg = client.post("/Groups", g)
    if rg.status not in (200, 201):
        return [{"attribute": "groups", "schema": "User", "resource": "User",
                  "characteristic": "knob_probe_user_groups_presence", "method": "POST",
                  "verdict": "ERROR", "basis": {}, "detail": f"create group with member failed: {rg.status} {rg.body[:150]}"}]
    rgu = client.get(f"/Users/{uid}")
    rj = rgu.json() or {}
    present = "groups" in rj
    return [{
        "attribute": "groups", "schema": "User", "resource": "User",
        "characteristic": "knob_probe_user_groups_presence", "method": "GET",
        "verdict": "present" if present else "absent", "basis": {},
        "detail": f"GET user after group membership -> groups={rj.get('groups')!r} present={present}",
    }]


def check_patch_replace_empty_phonenumbers(client):
    u = base_user()
    u["phoneNumbers"] = [{"value": "+1-555-0100", "type": "work"}]
    r = client.post("/Users", u)
    if r.status not in (200, 201):
        return [{"attribute": "phoneNumbers", "schema": "User", "resource": "User",
                  "characteristic": "knob_probe_patch_replace_empty_array", "method": "POST",
                  "verdict": "ERROR", "basis": {}, "detail": f"create failed: {r.status} {r.body[:150]}"}]
    uid = r.json()["id"]
    patch_body = {
        "schemas": [PATCHOP],
        "Operations": [{"op": "replace", "path": "phoneNumbers", "value": []}],
    }
    rp = client.patch(f"/Users/{uid}", patch_body)
    rj = rp.json() or {}
    if rp.status not in (200, 201):
        verdict = f"rejected:{rp.status}"
        cleared = None
    else:
        pn = rj.get("phoneNumbers")
        cleared = (pn is None) or (isinstance(pn, list) and len(pn) == 0) or ("phoneNumbers" not in rj)
        verdict = f"status={rp.status}:cleared={cleared}"
    return [{
        "attribute": "phoneNumbers", "schema": "User", "resource": "User",
        "characteristic": "knob_probe_patch_replace_empty_array", "method": "PATCH",
        "verdict": verdict, "basis": {},
        "detail": f"PATCH replace phoneNumbers=[] -> status={rp.status} body_phoneNumbers={rj.get('phoneNumbers')!r}",
    }]


def run_extra_checks(client):
    rows = []
    rows += check_empty_members_shape(client)
    rows += check_user_groups_presence(client)
    rows += check_patch_replace_empty_phonenumbers(client)
    return rows
