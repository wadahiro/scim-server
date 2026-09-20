"""Shared helpers for the SCIM schema-driven conformance prototype."""
import json
import urllib.request
import urllib.error
import uuid

USER_URN = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_URN = "urn:ietf:params:scim:schemas:core:2.0:Group"
ENTERPRISE_URN = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

TYPE_WRONG = {
    "string": 123,
    "boolean": "yes",
    "integer": "abc",
    "decimal": "abc",
    "dateTime": "not-a-date",
    "reference": 42,
    "complex": "flat-string-value",
}

# Special-cased valid values for attributes with server-side format validation
# (see src/schema/validation.rs). Keyed by dotted path (relative to the
# resource, ignoring which top-level container it lives under).
SPECIAL_VALID = {
    "emails.value": lambda u: f"user-{u}@example.com",
    "photos.value": lambda u: "http://example.com/photo.jpg",
    "profileUrl": lambda u: "http://example.com/profile",
    "timezone": lambda u: "America/New_York",
    "locale": lambda u: "en-US",
    "x509Certificates.value": lambda u: "M" * 120,
    "members.$ref": lambda u: f"/Users/{u}",
    "manager.value": lambda u: f"manager-{u}",
}

CANONICAL_FALLBACK = {
    "type": "work",
}


def short_uid():
    return uuid.uuid4().hex[:10]


class Resp:
    def __init__(self, status, body, headers=None):
        self.status = status
        self.body = body
        self.headers = headers or {}

    def json(self):
        try:
            return json.loads(self.body) if self.body else None
        except Exception:
            return None


class Client:
    def __init__(self, base):
        self.base = base.rstrip("/")

    def _req(self, method, path, payload=None, headers=None):
        url = self.base + path
        data = None
        hdrs = {"Content-Type": "application/scim+json"}
        if headers:
            hdrs.update(headers)
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                body = r.read().decode("utf-8", errors="replace")
                return Resp(r.status, body, dict(r.headers))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return Resp(e.code, body, dict(e.headers or {}))
        except Exception as e:
            return Resp(-1, json.dumps({"error": str(e)}))

    def get(self, path):
        return self._req("GET", path)

    def post(self, path, payload):
        return self._req("POST", path, payload)

    def put(self, path, payload):
        return self._req("PUT", path, payload)

    def patch(self, path, payload):
        return self._req("PATCH", path, payload)

    def delete(self, path):
        return self._req("DELETE", path)


def base_user(username=None):
    username = username or f"u-{short_uid()}"
    return {"schemas": [USER_URN], "userName": username}


def base_group(name=None):
    name = name or f"g-{short_uid()}"
    return {"schemas": [GROUP_URN], "displayName": name}


def ensure_enterprise(payload):
    if ENTERPRISE_URN not in payload["schemas"]:
        payload["schemas"].append(ENTERPRISE_URN)
    return payload.setdefault(ENTERPRISE_URN, {})


def set_attr(payload, node, value):
    """Set `value` at the location described by `node` (see schema_walk.AttrNode)."""
    if node.resource == "EnterpriseUser":
        target = ensure_enterprise(payload)
    else:
        target = payload

    path = node.path
    if len(path) == 1:
        target[path[0]] = value
    else:
        top, sub = path[0], path[1]
        if node.top_multivalued:
            target[top] = [{sub: value}]
        else:
            target[top] = {sub: value}


def get_attr(resource_json, node):
    """Read back the value at node's location from a response JSON body."""
    if resource_json is None:
        return (False, None)
    if node.resource == "EnterpriseUser":
        target = resource_json.get(ENTERPRISE_URN)
        if target is None:
            return (False, None)
    else:
        target = resource_json

    path = node.path
    if len(path) == 1:
        if path[0] in target:
            return (True, target[path[0]])
        return (False, None)
    else:
        top, sub = path[0], path[1]
        if top not in target or target[top] is None:
            return (False, None)
        container = target[top]
        if node.top_multivalued:
            if isinstance(container, list) and len(container) > 0:
                first = container[0]
                if isinstance(first, dict) and sub in first:
                    return (True, first[sub])
            return (False, None)
        else:
            if isinstance(container, dict) and sub in container:
                return (True, container[sub])
            return (False, None)


def dotted_path(node):
    p = ".".join(node.path)
    if node.resource == "EnterpriseUser":
        return f"{ENTERPRISE_URN}:{p}"
    return p


def patch_path(node):
    """PATCH `path` for a node: container-level when it's a sub-attr of a
    multi-valued complex attribute (no per-element filter target exists),
    full dotted path otherwise."""
    if len(node.path) > 1 and node.top_multivalued:
        top = node.path[0]
        if node.resource == "EnterpriseUser":
            return f"{ENTERPRISE_URN}:{top}"
        return top
    return dotted_path(node)


def patch_value_for(node, value):
    """PATCH `value` payload matching patch_path()."""
    if len(node.path) > 1 and node.top_multivalued:
        sub = node.path[1]
        return [{sub: value}]
    return value


def resource_endpoint(resource):
    return "/Users" if resource in ("User", "EnterpriseUser") else "/Groups"


def dotted_key(node):
    return ".".join(node.path)


def valid_value_for(node):
    key = dotted_key(node)
    if key in SPECIAL_VALID:
        return SPECIAL_VALID[key](short_uid())
    t = node.definition.get("type")
    canon = node.definition.get("canonicalValues")
    if canon:
        return canon[0]
    if node.path and node.path[-1] in CANONICAL_FALLBACK and t == "string":
        return CANONICAL_FALLBACK[node.path[-1]]
    if t == "string":
        return f"Valid-{short_uid()}"
    if t == "boolean":
        return True
    if t == "integer":
        return 42
    if t == "decimal":
        return 4.2
    if t == "dateTime":
        return "2024-01-01T00:00:00Z"
    if t == "reference":
        return f"http://example.com/ref/{short_uid()}"
    return f"Valid-{short_uid()}"


def wrong_value_for(node):
    t = node.definition.get("type")
    return TYPE_WRONG.get(t, "###WRONG###")
