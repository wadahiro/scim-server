# What this tool looks at, and what it does not

A per-section map of RFC 7643 (core schema) and RFC 7644 (protocol), stating
plainly which behaviours the axis catalogue observes. It is maintained by
hand: a ratio computed from a keyword count would imply a precision the
denominator cannot support, and this table is more useful anyway — it doubles
as the work queue.

`covered` means at least one axis observes that section's behaviour, not that
the section is exhausted.

## RFC 7644 — protocol

| § | Subject | Status | Axes |
|---|---|---|---|
| 3.1 | Background / `Content-Type` negotiation | not yet | — |
| 3.2 | Operation overview | n/a (no observable behaviour of its own) | — |
| 3.3 | Creating resources | partial | readOnly-on-POST (derived matrix), projection on POST |
| 3.4.1 | Retrieving a known resource | partial | via every GET-based axis |
| 3.4.2 | Query / ListResponse envelope | partial | discovery presence (envelope members) |
| 3.4.2.1 | `startIndex` / `count` pagination semantics | **not yet** | — |
| 3.4.2.2 | Filtering | partial | the two Group-filter axes; operators beyond `eq` untouched |
| 3.4.2.3 | Sorting | **not yet** | — |
| 3.4.2.4 | Pagination | **not yet** | — |
| 3.4.3 | Query via POST `/.search` | not yet | — |
| 3.5.1 | Replacing with PUT | partial | readOnly/immutable/type on PUT, projection on PUT |
| 3.5.2 | Modifying with PATCH | partial | mutability on PATCH, sequential application, atomicity, primary demotion, the two empty-value patterns |
| 3.6 | Deleting resources | partial | `DELETE` × `If-Match` only |
| 3.7 | Bulk | out of scope | OPTIONAL and rarely implemented; revisit if a diagnosed provider advertises it |
| 3.8 | Data input/output formats | not yet | — |
| 3.9 | Attribute projection | covered | 16 projection axes over the target's declared resource types |
| 3.10 | Attribute notation / name case | not yet | — |
| 3.11 | `X-HTTP-Method-Override` | out of scope | a transport workaround, not a behaviour worth emulating |
| 3.12 | Error responses | partial | `scimType` on duplicate values; the error-body shape itself untouched |
| 3.13 | Related resources | not yet | — |
| 3.14 | Versioning / ETags | covered | 16 axes: representation, conditional read, conditional write, `DELETE` × `If-Match` |

## RFC 7643 — core schema

| § | Subject | Status | Axes |
|---|---|---|---|
| 2.1-2.2 | Attribute characteristics | covered | the derived matrix reads all of them off the target's own `/Schemas` |
| 2.3 | Attribute data types | covered | type conformance, both directions, POST and PUT |
| 2.4 | Multi-valued attributes / `primary` | partial | primary demotion; `$ref`/`display` resolution untouched |
| 2.5 | Unassigned / null / empty equivalence | covered | empty multi-valued rendering |
| 3 | SCIM resources | partial | via the derived matrix |
| 4.1-4.3 | User / Group / EnterpriseUser schemas | covered structurally | the matrix derives from whatever the target declares, so custom schemas are covered too |
| 5 | ServiceProviderConfig | covered | 22 discovery-presence axes |
| 6 | ResourceType | covered | 8 discovery-presence axes |
| 7 | Schema definitions | covered | 10 discovery-presence axes, plus the whole derived matrix rests on §7's characteristic definitions |
| 8 | JSON representations | out of scope | non-normative examples |
| 9 | Security considerations | not observable black-box | — |

## The honest summary

Deep on what a target declares about itself — attribute characteristics are
observed per declared attribute, so a provider with custom schemas or resource
types gets *more* axes, not fewer. Thin on protocol mechanics that no schema
describes: pagination, sorting, filter operators, and the `/.search` endpoint
are the largest gaps, and §3.4's mechanics are the obvious next family.
