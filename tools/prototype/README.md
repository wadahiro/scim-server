# RFC-extraction prototypes — the differential oracle

These scripts are **Python prototypes**, kept for one purpose: they define
the expected output that the eventual Rust extractor/conformance
implementation must reproduce. The acceptance test for the Rust code is
"same input, byte-identical JSON output" against the files in
[`golden/`](golden/). Nothing here is meant to run in production or in CI as
a long-term dependency — once a Rust implementation exists for a given
script, that script's role ends.

All scripts read the vendored, unmodified RFC text in `spec/rfc/` (see
`spec/rfc/README.md`) and/or a live scim-server instance; none of them fetch
anything from the network.

## Layout

```
tools/prototype/
├── extract.py              # whole-document block extraction + classification
├── extract_attrdefs.py     # attribute-definition ("REQUIRED"/"OPTIONAL"/…) extraction
├── run_attrdef_checks.py   # runs extract_attrdefs.py's output against a live server
├── verify-quotes.rb        # checks that a ledger's `quote` occurs verbatim in its `lines` span
├── golden/                 # committed expected outputs (see below)
└── proto-eval/             # schema-driven check generation + compatibility-knob detection
```

## `extract.py`

Segments an RFC `.txt` file into logical blocks (paragraph, heading, table,
JSON/ABNF/HTTP example, ...), classifies each block, and tags blocks that
carry RFC 2119 keywords or an attribute-definition (`REQUIRED`/`OPTIONAL`/
`RECOMMENDED`) shape. Line numbers in the output are **raw-file** line
numbers (i.e. numbers into `spec/rfc/rfc7643.txt` / `rfc7644.txt` directly).

```bash
python3 tools/prototype/extract.py spec/rfc out.json              # default: includes 'text'
python3 tools/prototype/extract.py --no-text spec/rfc out.json    # 'text' replaced by 'text_sha256'
```

`--no-text` drops the literal `text` field from every record and replaces it
with `text_sha256`: the sha256 of the block's text after whitespace
normalization (all runs of whitespace collapsed to a single space, then
trimmed). This is what lets `golden/` avoid re-typesetting RFC prose while
still letting a re-implementation prove it reconstructed the same text.
Default behavior (no `--no-text`) is unchanged from before this flag existed.

The script always processes the **whole document** for both RFC 7643 and RFC
7644 in one invocation — there is no option to select a single section (e.g.
"just §3"). Keep that in mind when reading `golden/extract-7644.json`: it is
the whole-document output for RFC 7644, not a §3-only slice.

## `extract_attrdefs.py`

Extracts "attribute definition" entries: lines of the form `   name` or
`   name  Description...` (3/6/9-space indentation) whose description
contains `REQUIRED`, `OPTIONAL`, or `RECOMMENDED`, including conditional
cardinality (`REQUIRED if ...`). Tracks nesting via indentation so
sub-attributes (`patch.supported`, etc.) record their `parent`.

```bash
python3 tools/prototype/extract_attrdefs.py spec/rfc out.json
```

Against the vendored `spec/rfc/rfc7643.txt` + `rfc7644.txt`, this produces 61
entries (39 `REQUIRED`, 21 `OPTIONAL`, 1 `RECOMMENDED`; 4 conditional).

## `run_attrdef_checks.py`

Takes `extract_attrdefs.py`'s output and a running server's base URL, and
checks — for the four sections it knows how to map to an endpoint
(RFC 7643 §5 → `/ServiceProviderConfig`, §6 → `/ResourceTypes`, §7 →
`/Schemas`, RFC 7644 §3.4.2 → `/Users?count=1`) — whether each
unconditionally-`REQUIRED` attribute is actually present in the response.
Conditional requirements are reported as `SKIP` (the condition text is
printed, not evaluated). Needs a running scim-server:

```bash
cargo run &
python3 tools/prototype/run_attrdef_checks.py http://127.0.0.1:3000/scim/v2 out.json
```

## `verify-quotes.rb`

Given a ledger YAML file (see `spec/ledger/`) and a directory containing the
RFC text it cites, checks that every entry's `quote` occurs verbatim
(after whitespace normalization) inside the line range given by `lines`.
This is the mechanical guarantee that a ledger's quotations are not
paraphrased or hand-typo'd.

```bash
ruby tools/prototype/verify-quotes.rb spec/ledger/rfc7644-3.5.2.yaml spec/rfc
```

Note: as vendored, this script expects a `clean-<doc>.txt` file in the given
directory (its historical working format). The `lines` in
`spec/ledger/rfc7644-3.5.2.yaml` are, as documented at the top of that file,
against that reflowed working copy, not against `spec/rfc/rfc7644.txt`
directly — converting them and re-pointing this check at the vendored raw
file is deferred to a later task.

## `proto-eval/`

Requires a **running scim-server** (`cargo run`, or the binary path baked
into `knob_mutation.py`) — these scripts issue real HTTP requests against a
live instance and are not meant to run offline.

- `schema_matrix.py <base_url> <out.json>` — reads `GET /Schemas`, derives a
  matrix of {attribute × characteristic × HTTP method} cells (readOnly/
  immutable enforcement, required-on-create, caseExact preservation,
  uniqueness rejection, `returned: never` absence, and type validation), runs
  each cell against the live server, and writes a verdict (`PASS`/`FAIL`/
  `SKIP`/`ERROR`) with an RFC `basis` (doc/section/line) per cell. Because it
  reads its check inputs from the server's own `/Schemas` response instead of
  a fixed attribute list, it automatically follows any schema extension the
  server advertises.
- `knob_mutation.py` — starts the server 8 times (once per
  `config_*.yaml`, including an all-defaults baseline), running
  `schema_matrix` plus 3 hand-written probes each time, and reports which
  checks change verdict when a single compatibility knob is flipped away
  from its default. It manages its own server process; do not run it
  against a server you started yourself.
- `checks.py`, `extra_checks.py`, `schema_walk.py`, `lib.py` — shared library
  code used by the two entry points above (HTTP client, schema-tree walker,
  the individual per-characteristic check implementations). Not meant to be
  run directly.
- `collect_full.py <base_url> <out.json>` — runs the full check set (schema
  matrix + extra checks) once and dumps every verdict; used to produce a full
  snapshot for manual comparison, not part of the golden set below.
- `config_*.yaml` — one `scim-server` config per compatibility knob
  (`config_baseline.yaml` plus one per knob under test), each binding to its
  own port so `knob_mutation.py` can run them back-to-back.

## `golden/` — what to regenerate, and how

All three files were produced by running the scripts above against
**exactly** `spec/rfc/rfc7643.txt` and `spec/rfc/rfc7644.txt` (verify with
`shasum -a 256 -c spec/rfc/SHA256SUMS` first). Every file is JSON serialized
with `indent=1, sort_keys=True`, followed by a trailing newline, and none of
them contain RFC prose verbatim (`text` fields are replaced by
`text_sha256`, or dropped along with `detail` in the schema-matrix case) —
that's what keeps them regeneratable without re-typesetting RFC text.

### `attrdefs.json`

The 61-entry output of `extract_attrdefs.py`, with `text` replaced by
`text_sha256` (extract_attrdefs.py itself always emits `text` — it has no
`--no-text` flag of its own, unlike `extract.py` — so the replacement is a
golden-formatting step applied after running it, not a script option).

```bash
python3 tools/prototype/extract_attrdefs.py spec/rfc /tmp/attrdefs_raw.json
python3 - <<'PY'
import json, hashlib, re

def norm(t):
    return re.sub(r'\s+', ' ', t).strip()

d = json.load(open('/tmp/attrdefs_raw.json'))
for e in d:
    if 'text' in e:
        e['text_sha256'] = hashlib.sha256(norm(e.pop('text')).encode('utf-8')).hexdigest()

with open('tools/prototype/golden/attrdefs.json', 'w') as f:
    json.dump(d, f, indent=1, sort_keys=True, ensure_ascii=False)
    f.write('\n')
PY
```

### `extract-7644.json`

The RFC-7644 portion of `extract.py --no-text`'s whole-document output.
Named `extract-7644.json` rather than `extract-7644-3.json`: as noted above,
`extract.py` has no section-selection option, so this is the whole document,
not a §3-only slice.

```bash
python3 tools/prototype/extract.py --no-text spec/rfc /tmp/extract_raw.json
python3 - <<'PY'
import json

d = json.load(open('/tmp/extract_raw.json'))
with open('tools/prototype/golden/extract-7644.json', 'w') as f:
    json.dump(d['7644'], f, indent=1, sort_keys=True, ensure_ascii=False)
    f.write('\n')
PY
```

### `schema_matrix.json`

**Not regenerated from scratch** — this requires a running server plus the
242-cell prototype run captured during evaluation. If you have a fresh
`schema_matrix.py` output (242 cells, from a run against a stock, unmodified
scim-server), reproduce the golden by dropping `detail` and `basis.text`
from every cell:

```bash
python3 - <<'PY'
import json

d = json.load(open('/path/to/schema_matrix.json'))
for cell in d:
    cell.pop('detail', None)
    if isinstance(cell.get('basis'), dict):
        cell['basis'].pop('text', None)

with open('tools/prototype/golden/schema_matrix.json', 'w') as f:
    json.dump(d, f, indent=1, sort_keys=True, ensure_ascii=False)
    f.write('\n')
PY
```
