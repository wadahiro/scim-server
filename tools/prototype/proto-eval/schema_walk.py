"""Walks GET /Schemas into a flat list of AttrNode records."""


class AttrNode:
    def __init__(self, resource, urn, path, definition, top_multivalued):
        self.resource = resource          # "User" / "Group" / "EnterpriseUser"
        self.urn = urn
        self.path = tuple(path)           # e.g. ("name", "givenName")
        self.definition = definition      # raw JSON attribute definition (this node)
        self.top_multivalued = top_multivalued  # multiValued-ness of path[0]

    @property
    def dotted(self):
        return ".".join(self.path)

    def __repr__(self):
        return f"<AttrNode {self.resource}:{self.dotted}>"


def walk_schemas(schemas_json, skip_resources=("ServiceProviderConfig",)):
    nodes = []
    for r in schemas_json["Resources"]:
        rname = r["name"]
        if rname in skip_resources:
            continue
        urn = r["id"]

        def rec(attrs, path, top_mv):
            for a in attrs:
                p = path + [a["name"]]
                this_top_mv = a.get("multiValued", False) if len(p) == 1 else top_mv
                nodes.append(AttrNode(rname, urn, p, a, this_top_mv))
                if a.get("subAttributes"):
                    rec(a["subAttributes"], p, this_top_mv)

        rec(r.get("attributes", []), [], False)
    return nodes
