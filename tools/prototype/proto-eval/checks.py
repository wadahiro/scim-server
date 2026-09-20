"""Check implementations for the schema-driven conformance matrix."""
from lib import (
    Client, base_user, base_group, ensure_enterprise, set_attr, get_attr,
    dotted_path, patch_path, patch_value_for, resource_endpoint, short_uid,
    valid_value_for, wrong_value_for, ENTERPRISE_URN,
)
from schema_walk import AttrNode

PATCHOP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

BASIS = {
    "mutability_readOnly": {
        "rfc": "RFC 7644", "section": "3.3",
        "lines": "rfc7644.txt:583-584",
        "text": 'attributes whose mutability is "readOnly" ... SHALL be ignored',
    },
    "mutability_immutable": {
        "rfc": "RFC 7643", "section": "7",
        "lines": "rfc7643.txt:1764-1766",
        "text": 'immutable: MAY be defined at resource creation ... SHALL NOT be updated',
    },
    "required": {
        "rfc": "RFC 7643", "section": "7",
        "lines": "rfc7643.txt:1731-1732",
        "text": "required: A Boolean value that specifies whether or not the attribute is required",
    },
    "caseExact": {
        "rfc": "RFC 7643", "section": "7",
        "lines": "rfc7643.txt:1747-1753",
        "text": "caseExact: ... the server SHALL preserve case for any value submitted",
    },
    "uniqueness": {
        "rfc": "RFC 7643", "section": "7",
        "lines": "rfc7643.txt:1811-1815",
        "text": "uniqueness: A server MAY reject an invalid value based on uniqueness by returning HTTP response code 400",
    },
    "returned_never": {
        "rfc": "RFC 7643", "section": "7",
        "lines": "rfc7643.txt:1782-1784",
        "text": "never: The attribute is never returned",
    },
    "type": {
        "rfc": "RFC 7643", "section": "2.3",
        "lines": "rfc7643.txt:438",
        "text": "Attribute Data Types",
    },
}


def row(node, characteristic, method, verdict, basis, detail):
    return {
        "attribute": node.dotted,
        "schema": node.urn,
        "resource": node.resource,
        "characteristic": characteristic,
        "method": method,
        "verdict": verdict,
        "basis": basis,
        "detail": detail,
    }


def skip_row(node, characteristic, method, reason):
    return row(node, characteristic, method, "SKIP", BASIS.get(characteristic, {}), reason)


def make_baseline(resource_kind):
    if resource_kind in ("User", "EnterpriseUser"):
        return base_user()
    return base_group()


def is_container_skip(node):
    return (
        len(node.path) == 1
        and node.definition.get("type") == "complex"
        and bool(node.definition.get("subAttributes"))
    )


def forged_value_for(node):
    t = node.definition.get("type")
    if t == "string":
        return f"FORGED-{short_uid()}"
    if t == "boolean":
        return True
    if t == "integer":
        return 999999
    if t == "decimal":
        return 9.99
    if t == "dateTime":
        return "2001-01-01T00:00:00Z"
    if t == "reference":
        return "http://forged.example.com/ref"
    return f"FORGED-{short_uid()}"


def _fresh_member_user_id(client):
    """Create a throwaway User and return its id, for tests that need a
    Group `members` value to reference a real, existing resource (this
    server validates member references against actual User/Group rows)."""
    r = client.post("/Users", make_baseline("User"))
    if r.status in (200, 201):
        return r.json().get("id")
    return None


def is_group_member_ref(node):
    return node.resource == "Group" and node.path and node.path[0] == "members" and node.path[-1] in ("value", "$ref")


def values_match(node, sent, got):
    """Equality check that tolerates known, legitimate server-side rewriting
    of a submitted value (e.g. Group members.$ref is always re-derived by
    this server as an absolute URL built from the member's `value`, rather
    than echoing the client's literal string -- RFC 7643 SS7 "immutable"
    only says the attribute MAY be defined at creation, it does not require
    verbatim echo)."""
    if is_group_member_ref(node) and node.path[-1] == "$ref":
        if not isinstance(got, str) or not isinstance(sent, str):
            return False
        return got.rstrip("/").endswith(sent.rstrip("/"))
    return sent == got


def is_group_member_subattr(node):
    return node.resource == "Group" and len(node.path) > 1 and node.path[0] == "members"


def set_member_attr(client, payload, node, value):
    """Set a Group.members sub-attribute. This server derives/keeps a member
    entry only when it carries a resolvable `value` (a real User/Group id),
    so any sub-attribute other than `value` itself is set alongside a real
    companion `value` rather than in isolation."""
    sub = node.path[1]
    elem = {sub: value}
    real_id = None
    if sub != "value":
        real_id = _fresh_member_user_id(client)
        if real_id is not None:
            elem["value"] = real_id
    payload["members"] = [elem]
    return real_id


def member_ref_override(client, node):
    """Returns a real, resolvable value for Group members.value / members.$ref,
    or None if unavailable."""
    uid = _fresh_member_user_id(client)
    if uid is None:
        return None
    if node.path[-1] == "$ref":
        return f"/Users/{uid}"
    return uid


def _patch_body(node, value):
    return {
        "schemas": [PATCHOP],
        "Operations": [
            {"op": "replace", "path": patch_path(node), "value": patch_value_for(node, value)}
        ],
    }


# ---------------------------------------------------------------- readOnly
def check_readonly(client, node):
    if is_container_skip(node):
        return [
            skip_row(
                node, "mutability_readOnly", "N/A",
                "complex container decomposed into per-subattribute readOnly checks",
            )
        ]
    basis = BASIS["mutability_readOnly"]
    endpoint = resource_endpoint(node.resource)
    forged = forged_value_for(node)
    rows = []

    payload = make_baseline(node.resource)
    set_attr(payload, node, forged)
    r = client.post(endpoint, payload)
    rj = r.json()
    if r.status not in (200, 201):
        rows.append(row(node, "mutability_readOnly", "POST", "ERROR", basis,
                         f"baseline POST failed: {r.status} {r.body[:200]}"))
        return rows
    ok, val = get_attr(rj, node)
    if (not ok) or val != forged:
        rows.append(row(node, "mutability_readOnly", "POST", "PASS", basis,
                         f"forged={forged!r} ignored; actual={val!r} present={ok}"))
    else:
        rows.append(row(node, "mutability_readOnly", "POST", "FAIL", basis,
                         f"forged value {forged!r} took effect on POST"))
    rid = rj.get("id")
    if not rid:
        rows.append(row(node, "mutability_readOnly", "PUT", "ERROR", basis, "no id from baseline POST"))
        rows.append(row(node, "mutability_readOnly", "PATCH", "ERROR", basis, "no id from baseline POST"))
        return rows

    getr = client.get(f"{endpoint}/{rid}")
    current = getr.json() or {}
    put_body = dict(current)
    set_attr(put_body, node, forged)
    r2 = client.put(f"{endpoint}/{rid}", put_body)
    rj2 = r2.json()
    if r2.status not in (200, 201):
        rows.append(row(node, "mutability_readOnly", "PUT", "ERROR", basis,
                         f"PUT failed: {r2.status} {r2.body[:200]}"))
    else:
        ok2, val2 = get_attr(rj2, node)
        if (not ok2) or val2 != forged:
            rows.append(row(node, "mutability_readOnly", "PUT", "PASS", basis,
                             f"forged={forged!r} ignored; actual={val2!r} present={ok2}"))
        else:
            rows.append(row(node, "mutability_readOnly", "PUT", "FAIL", basis,
                             f"forged value {forged!r} took effect on PUT"))

    r3 = client.patch(f"{endpoint}/{rid}", _patch_body(node, forged))
    rj3 = r3.json()
    if r3.status == 400:
        rows.append(row(node, "mutability_readOnly", "PATCH", "PASS", basis,
                         f"PATCH of readOnly attribute rejected with 400: {r3.body[:150]}"))
    elif r3.status in (200, 201):
        ok3, val3 = get_attr(rj3, node)
        if (not ok3) or val3 != forged:
            rows.append(row(node, "mutability_readOnly", "PATCH", "PASS", basis,
                             f"forged={forged!r} ignored; actual={val3!r} present={ok3}"))
        else:
            rows.append(row(node, "mutability_readOnly", "PATCH", "FAIL", basis,
                             f"forged value {forged!r} took effect on PATCH"))
    else:
        rows.append(row(node, "mutability_readOnly", "PATCH", "ERROR", basis,
                         f"unexpected status {r3.status}: {r3.body[:200]}"))
    return rows


# --------------------------------------------------------------- immutable
def check_immutable(client, node):
    basis = BASIS["mutability_immutable"]
    endpoint = resource_endpoint(node.resource)
    rows = []
    valid_val = valid_value_for(node)
    if is_group_member_ref(node) and node.path[-1] == "value":
        override = member_ref_override(client, node)
        if override is not None:
            valid_val = override

    payload = make_baseline(node.resource)
    if is_group_member_subattr(node) and node.path[1] != "value":
        real_id = set_member_attr(client, payload, node, valid_val)
        if node.path[-1] == "$ref" and real_id is not None:
            valid_val = f"/Users/{real_id}"
    else:
        set_attr(payload, node, valid_val)
    r = client.post(endpoint, payload)
    rj = r.json()
    if r.status not in (200, 201):
        rows.append(row(node, "mutability_immutable", "POST-create", "ERROR", basis,
                         f"creation with immutable attribute set failed: {r.status} {r.body[:200]}"))
        return rows
    ok, val = get_attr(rj, node)
    if ok and values_match(node, valid_val, val):
        rows.append(row(node, "mutability_immutable", "POST-create", "PASS", basis,
                         f"value {valid_val!r} accepted at creation (observed {val!r})"))
    else:
        rows.append(row(node, "mutability_immutable", "POST-create", "FAIL", basis,
                         f"value not accepted/persisted at creation: got {val!r} present={ok}"))
    rid = rj.get("id")
    if not rid:
        rows.append(row(node, "mutability_immutable", "PATCH-change", "ERROR", basis, "no id from creation"))
        return rows

    changed = forged_value_for(node)
    if changed == valid_val:
        changed = forged_value_for(node)
    r2 = client.patch(f"{endpoint}/{rid}", _patch_body(node, changed))
    rj2 = r2.json()
    if r2.status in (400, 409):
        rows.append(row(node, "mutability_immutable", "PATCH-change", "PASS", basis,
                         f"change correctly rejected with status {r2.status}"))
    elif r2.status in (200, 201):
        ok2, val2 = get_attr(rj2, node)
        if ok2 and values_match(node, changed, val2):
            rows.append(row(node, "mutability_immutable", "PATCH-change", "FAIL", basis,
                             f"immutable value changed via PATCH to {val2!r}"))
        else:
            rows.append(row(node, "mutability_immutable", "PATCH-change", "PASS", basis,
                             f"PATCH returned 200 but value unchanged: {val2!r}"))
    else:
        rows.append(row(node, "mutability_immutable", "PATCH-change", "ERROR", basis,
                         f"unexpected status {r2.status}: {r2.body[:200]}"))
    return rows


# ---------------------------------------------------------------- required
def check_required(client, node):
    basis = BASIS["required"]
    if node.definition.get("mutability") == "readOnly":
        return [skip_row(node, "required", "N/A",
                          "attribute is server-generated (readOnly); client omission at creation is normal, not a violation")]
    endpoint = resource_endpoint(node.resource)
    rows = []

    payload = make_baseline(node.resource)
    target = ensure_enterprise(payload) if node.resource == "EnterpriseUser" else payload
    if len(node.path) == 1 and node.path[0] in target:
        del target[node.path[0]]
    r = client.post(endpoint, payload)
    if r.status == 400:
        rows.append(row(node, "required", "POST-omit", "PASS", basis, f"correctly rejected: {r.body[:150]}"))
    else:
        rows.append(row(node, "required", "POST-omit", "FAIL", basis,
                         f"expected 400, got {r.status}: {r.body[:150]}"))

    good = make_baseline(node.resource)
    r2 = client.post(endpoint, good)
    if r2.status not in (200, 201):
        rows.append(row(node, "required", "PUT-omit", "ERROR", basis, "could not create baseline resource"))
        return rows
    rj2 = r2.json()
    rid = rj2["id"]
    put_body = dict(rj2)
    if node.path[0] in put_body:
        del put_body[node.path[0]]
    r3 = client.put(f"{endpoint}/{rid}", put_body)
    if r3.status == 400:
        rows.append(row(node, "required", "PUT-omit", "PASS", basis, f"correctly rejected: {r3.body[:150]}"))
    else:
        rows.append(row(node, "required", "PUT-omit", "FAIL", basis,
                         f"expected 400, got {r3.status}: {r3.body[:150]}"))
    return rows


# ---------------------------------------------------------------- caseExact
def check_caseexact(client, node):
    basis = BASIS["caseExact"]
    if node.definition.get("mutability") == "readOnly" or node.definition.get("returned") == "never":
        return [skip_row(node, "caseExact", "N/A",
                          "attribute is readOnly or never-returned; case preservation cannot be verified via client write + read")]
    if is_group_member_ref(node):
        return [skip_row(node, "caseExact", "N/A",
                          "members.value/$ref must reference an existing User/Group id (server-generated ids are always lowercase); "
                          "a mixed-case probe cannot resolve to an existing member, so case preservation cannot be isolated from the "
                          "existence check")]
    endpoint = resource_endpoint(node.resource)
    mixed = f"MiXeD-{short_uid()}-CaSe"
    payload = make_baseline(node.resource)
    set_attr(payload, node, mixed)
    r = client.post(endpoint, payload)
    if r.status not in (200, 201):
        return [row(node, "caseExact", "POST", "ERROR", basis, f"create failed: {r.status} {r.body[:150]}")]
    ok, val = get_attr(r.json(), node)
    if ok and val == mixed:
        return [row(node, "caseExact", "POST", "PASS", basis, f"case preserved: {val!r}")]
    return [row(node, "caseExact", "POST", "FAIL", basis, f"case not preserved: sent {mixed!r}, got {val!r}")]


# --------------------------------------------------------------- uniqueness
def check_uniqueness(client, node):
    basis = BASIS["uniqueness"]
    if node.definition.get("mutability") == "readOnly":
        return [skip_row(node, "uniqueness", "N/A",
                          "attribute is server-assigned (readOnly); client cannot set its value to force a duplicate")]
    endpoint = resource_endpoint(node.resource)
    rows = []

    dup1 = f"dup-{short_uid()}"
    pA = make_baseline(node.resource)
    set_attr(pA, node, dup1)
    client.post(endpoint, pA)
    pB = make_baseline(node.resource)
    set_attr(pB, node, dup1)
    rB = client.post(endpoint, pB)
    stB = rB.json().get("scimType") if rB.json() else None
    if rB.status in (400, 409):
        rows.append(row(node, "uniqueness", "POST-duplicate", "PASS", basis,
                         f"status={rB.status} scimType={stB}"))
    else:
        rows.append(row(node, "uniqueness", "POST-duplicate", "FAIL", basis,
                         f"expected 400/409, got {rB.status}: {rB.body[:150]}"))

    dup2 = f"dup-{short_uid()}"
    pA2 = make_baseline(node.resource)
    set_attr(pA2, node, dup2)
    client.post(endpoint, pA2)
    pC = make_baseline(node.resource)
    rC = client.post(endpoint, pC)
    if rC.status not in (200, 201):
        rows.append(row(node, "uniqueness", "PUT-duplicate", "ERROR", basis, "could not create baseline C"))
    else:
        cid = rC.json()["id"]
        put_body = dict(rC.json())
        set_attr(put_body, node, dup2)
        rPut = client.put(f"{endpoint}/{cid}", put_body)
        stPut = rPut.json().get("scimType") if rPut.json() else None
        if rPut.status in (400, 409):
            rows.append(row(node, "uniqueness", "PUT-duplicate", "PASS", basis,
                             f"status={rPut.status} scimType={stPut}"))
        else:
            rows.append(row(node, "uniqueness", "PUT-duplicate", "FAIL", basis,
                             f"expected 400/409, got {rPut.status}: {rPut.body[:150]}"))

    dup3 = f"dup-{short_uid()}"
    pA3 = make_baseline(node.resource)
    set_attr(pA3, node, dup3)
    client.post(endpoint, pA3)
    pD = make_baseline(node.resource)
    rD = client.post(endpoint, pD)
    if rD.status not in (200, 201):
        rows.append(row(node, "uniqueness", "PATCH-duplicate", "ERROR", basis, "could not create baseline D"))
    else:
        did = rD.json()["id"]
        rPatch = client.patch(f"{endpoint}/{did}", _patch_body(node, dup3))
        stPatch = rPatch.json().get("scimType") if rPatch.json() else None
        if rPatch.status in (400, 409):
            rows.append(row(node, "uniqueness", "PATCH-duplicate", "PASS", basis,
                             f"status={rPatch.status} scimType={stPatch}"))
        else:
            rows.append(row(node, "uniqueness", "PATCH-duplicate", "FAIL", basis,
                             f"expected 400/409, got {rPatch.status}: {rPatch.body[:150]}"))
    return rows


# ------------------------------------------------------------ returned:never
def check_returned_never(client, node):
    basis = BASIS["returned_never"]
    endpoint = resource_endpoint(node.resource)
    rows = []
    val = f"S3cr3t-{short_uid()}!"
    payload = make_baseline(node.resource)
    set_attr(payload, node, val)
    r = client.post(endpoint, payload)
    ok, _ = get_attr(r.json(), node)
    rows.append(row(node, "returned_never", "POST", "FAIL" if ok else "PASS", basis, f"present_in_response={ok}"))
    rid = r.json().get("id") if r.json() else None
    if not rid:
        rows.append(row(node, "returned_never", "GET", "ERROR", basis, "no id from create"))
        return rows

    rg = client.get(f"{endpoint}/{rid}")
    okg, _ = get_attr(rg.json(), node)
    rows.append(row(node, "returned_never", "GET", "FAIL" if okg else "PASS", basis, f"present_in_response={okg}"))

    put_body = dict(rg.json())
    set_attr(put_body, node, val + "-2")
    rp = client.put(f"{endpoint}/{rid}", put_body)
    okp, _ = get_attr(rp.json(), node)
    rows.append(row(node, "returned_never", "PUT", "FAIL" if okp else "PASS", basis, f"present_in_response={okp}"))

    rpa = client.patch(f"{endpoint}/{rid}", _patch_body(node, val + "-3"))
    okpa, _ = get_attr(rpa.json(), node)
    rows.append(row(node, "returned_never", "PATCH", "FAIL" if okpa else "PASS", basis, f"present_in_response={okpa}"))
    return rows


# --------------------------------------------------------- type conformance
def check_type(client, node):
    basis = BASIS["type"]
    if node.definition.get("mutability") == "readOnly":
        return []
    endpoint = resource_endpoint(node.resource)
    rows = []

    wrong = wrong_value_for(node)
    payload = make_baseline(node.resource)
    if is_group_member_subattr(node) and node.path[1] != "value":
        set_member_attr(client, payload, node, wrong)
    else:
        set_attr(payload, node, wrong)
    r = client.post(endpoint, payload)
    scimType = r.json().get("scimType") if r.json() else None
    if r.status == 400:
        rows.append(row(node, "type_wrong", "POST", "PASS", basis,
                         f"wrong-typed value {wrong!r} rejected with 400 scimType={scimType}"))
    else:
        rows.append(row(node, "type_wrong", "POST", "FAIL", basis,
                         f"wrong-typed value {wrong!r} not rejected: status={r.status} body={r.body[:150]}"))

    if node.definition.get("returned") == "never":
        rows.append(row(node, "type_valid", "POST", "SKIP", basis,
                         "attribute is returned:never; a valid-value round trip cannot be observed in any response"))
        return rows

    if node.definition.get("type") == "complex" and len(node.path) == 1:
        subs = node.definition.get("subAttributes") or []
        writable_subs = [s for s in subs if s.get("mutability") != "readOnly"]
        if not writable_subs:
            rows.append(row(node, "type_valid", "POST", "SKIP", basis,
                             "no writable sub-attribute available to exercise a valid round trip"))
            return rows
        chosen = writable_subs[0]
        temp = AttrNode(node.resource, node.urn, list(node.path) + [chosen["name"]],
                         chosen, node.definition.get("multiValued", False))
        valid = valid_value_for(temp)
        if is_group_member_ref(temp) and temp.path[-1] == "value":
            override = member_ref_override(client, temp)
            if override is not None:
                valid = override
        payload2 = make_baseline(node.resource)
        set_attr(payload2, temp, valid)
        r2 = client.post(endpoint, payload2)
        if r2.status not in (200, 201):
            rows.append(row(node, "type_valid", "POST", "ERROR", basis,
                             f"valid nested value under {temp.dotted} rejected: {r2.status} {r2.body[:150]}"))
        else:
            ok, got = get_attr(r2.json(), temp)
            if ok and values_match(temp, valid, got):
                rows.append(row(node, "type_valid", "POST", "PASS", basis,
                                 f"round-tripped via {temp.dotted}: {got!r}"))
            else:
                rows.append(row(node, "type_valid", "POST", "FAIL", basis,
                                 f"expected {valid!r} at {temp.dotted}, got {got!r} present={ok}"))
        return rows

    valid = valid_value_for(node)
    if is_group_member_ref(node) and node.path[-1] == "value":
        override = member_ref_override(client, node)
        if override is not None:
            valid = override
    payload2 = make_baseline(node.resource)
    if is_group_member_subattr(node) and node.path[1] != "value":
        real_id = set_member_attr(client, payload2, node, valid)
        if node.path[-1] == "$ref" and real_id is not None:
            valid = f"/Users/{real_id}"
    else:
        set_attr(payload2, node, valid)
    r2 = client.post(endpoint, payload2)
    if r2.status not in (200, 201):
        rows.append(row(node, "type_valid", "POST", "ERROR", basis,
                         f"valid value {valid!r} rejected unexpectedly: {r2.status} {r2.body[:150]}"))
    else:
        ok, got = get_attr(r2.json(), node)
        if ok and values_match(node, valid, got):
            rows.append(row(node, "type_valid", "POST", "PASS", basis, f"round-tripped: {got!r}"))
        else:
            rows.append(row(node, "type_valid", "POST", "FAIL", basis,
                             f"expected {valid!r}, got {got!r} present={ok}"))
    return rows
