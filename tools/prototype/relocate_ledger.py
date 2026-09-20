#!/usr/bin/env python3
"""Relocate a ledger's `lines` (recorded against a reflowed "clean" copy of
an RFC) to line numbers into the verbatim, vendored raw file in `spec/rfc/`.

Builds a clean -> raw line map with `difflib.SequenceMatcher` over the two
files' lines (rstrip'ed), rewrites every entry's `lines` to raw
coordinates, then for every entry with a `quote` checks the quote occurs
(whitespace-normalized) inside the raw span *after* furniture lines are
removed from that span. Exits non-zero (listing every failing entry) if any
quote does not verify.

The rewrite is a targeted text edit of the `lines:` values (not a full
YAML parse/re-serialize): PyYAML round-tripping loses comments and
reformats flow-style mappings, and this ledger's comments and layout are
part of what makes it readable. `entries` appear in the file in the same
order as in the parsed YAML, and each entry has exactly one `lines: [a, b]`
occurrence, so entries are matched to occurrences positionally.

Usage:
    python3 tools/prototype/relocate_ledger.py \\
        spec/ledger/rfc7644-3.5.2.yaml \\
        /path/to/clean-7644.txt \\
        spec/rfc/rfc7644.txt
"""
import difflib
import re
import sys

try:
    import yaml
except ImportError:
    print("PyYAML is required (pip install pyyaml)", file=sys.stderr)
    sys.exit(2)

FURNITURE_RE = re.compile(r"^(RFC \d+\s|Hunt,|.*\[Page \d+\]\s*$)")


def is_furniture(line: str) -> bool:
    return bool(FURNITURE_RE.match(line)) or "\f" in line


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def build_clean_to_raw_map(clean_lines, raw_lines):
    """Maps 0-based clean line index -> 0-based raw line index for every
    line SequenceMatcher considers part of an equal block."""
    sm = difflib.SequenceMatcher(None, clean_lines, raw_lines, autojunk=False)
    mapping = {}
    for block in sm.get_matching_blocks():
        for i in range(block.size):
            mapping[block.a + i] = block.b + i
    return mapping


def nearest_mapped(mapping, idx, n, direction):
    """Finds the nearest clean index with a mapping, searching outward from
    `idx` in `direction` (+1 or -1), bounded by [0, n)."""
    i = idx
    while 0 <= i < n:
        if i in mapping:
            return i
        i += direction
    return None


def relocate_span(mapping, n_clean, start_1based, end_1based):
    """Converts a 1-based inclusive [start, end] clean-file line span to a
    1-based inclusive raw-file span."""
    start0 = start_1based - 1
    end0 = end_1based - 1
    start_src = nearest_mapped(mapping, start0, n_clean, +1)
    end_src = nearest_mapped(mapping, end0, n_clean, -1)
    if start_src is None or end_src is None:
        raise ValueError(
            f"could not relocate span [{start_1based}, {end_1based}]: no nearby mapped line"
        )
    raw_start = mapping[start_src] + 1
    raw_end = mapping[end_src] + 1
    if raw_end < raw_start:
        raw_end = raw_start
    return raw_start, raw_end


def quote_verifies(raw_lines, raw_start, raw_end, quote):
    span_lines = raw_lines[raw_start - 1 : raw_end]
    kept = [l for l in span_lines if not is_furniture(l)]
    body = norm(" ".join(kept))
    return norm(quote) in body, body


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    ledger_path, clean_path, raw_path = sys.argv[1:4]

    with open(clean_path, encoding="utf-8") as f:
        clean_lines = [l.rstrip("\n") for l in f]
    with open(raw_path, encoding="utf-8") as f:
        raw_lines = [l.rstrip("\n") for l in f]

    mapping = build_clean_to_raw_map(clean_lines, raw_lines)

    with open(ledger_path, encoding="utf-8") as f:
        ledger_text = f.read()
    ledger = yaml.safe_load(ledger_text)

    # ---- relocate the section-level span (before "entries:") ----
    sec_start, sec_end = ledger["lines"]
    new_sec_start, new_sec_end = relocate_span(mapping, len(clean_lines), sec_start, sec_end)

    entries_idx = ledger_text.index("\nentries:")
    header_text = ledger_text[: entries_idx + 1]
    entries_text = ledger_text[entries_idx + 1 :]

    lines_pat = re.compile(r"lines:\s*\[\s*(\d+)\s*,\s*(\d+)\s*\]")

    # section-level "lines: [a, b]" appears once in header_text.
    header_matches = list(lines_pat.finditer(header_text))
    if len(header_matches) != 1:
        print(
            f"expected exactly 1 section-level 'lines:' occurrence in the header, found {len(header_matches)}",
            file=sys.stderr,
        )
        sys.exit(2)
    header_text = (
        header_text[: header_matches[0].start()]
        + f"lines: [{new_sec_start}, {new_sec_end}]"
        + header_text[header_matches[0].end() :]
    )

    # ---- relocate each entry's span, in document order ----
    entries = ledger["entries"]
    occurrences = list(lines_pat.finditer(entries_text))
    if len(occurrences) != len(entries):
        print(
            f"entry count ({len(entries)}) != 'lines:' occurrence count ({len(occurrences)}) "
            "in the entries section -- positional matching assumption broken",
            file=sys.stderr,
        )
        sys.exit(2)

    failures = []
    relocated = []
    new_entries_text_parts = []
    cursor = 0
    for entry, occ in zip(entries, occurrences):
        old_start, old_end = entry["lines"]
        assert (int(occ.group(1)), int(occ.group(2))) == (old_start, old_end), (
            f"entry {entry['id']}: occurrence {occ.group(0)} does not match "
            f"parsed lines {entry['lines']}"
        )
        try:
            raw_start, raw_end = relocate_span(mapping, len(clean_lines), old_start, old_end)
        except ValueError as e:
            failures.append((entry["id"], str(e)))
            raw_start, raw_end = old_start, old_end

        new_entries_text_parts.append(entries_text[cursor : occ.start()])
        new_entries_text_parts.append(f"lines: [{raw_start}, {raw_end}]")
        cursor = occ.end()
        relocated.append((entry["id"], old_start, old_end, raw_start, raw_end))

        quote = entry.get("quote")
        if quote:
            ok, body = quote_verifies(raw_lines, raw_start, raw_end, quote)
            if not ok:
                failures.append(
                    (
                        entry["id"],
                        f"quote not found verbatim in raw L{raw_start}-{raw_end}\n"
                        f"    quote: {norm(quote)[:150]!r}\n"
                        f"    raw:   {body[:150]!r}",
                    )
                )
    new_entries_text_parts.append(entries_text[cursor:])
    new_entries_text = "".join(new_entries_text_parts)

    new_ledger_text = header_text + new_entries_text

    moved = sum(1 for (_id, a, b, c, d) in relocated if (a, b) != (c, d))
    print(f"relocated {len(relocated)} entries ({moved} changed span, {len(relocated) - moved} unchanged)")
    print(f"section span: [{sec_start}, {sec_end}] (clean) -> [{new_sec_start}, {new_sec_end}] (raw)")
    for eid, a, b, c, d in relocated:
        marker = "  " if (a, b) == (c, d) else "->"
        print(f"  {eid}: clean [{a:>5}, {b:>5}] {marker} raw [{c:>5}, {d:>5}]")

    if failures:
        print(f"\n{len(failures)} FAILURE(S):", file=sys.stderr)
        for eid, msg in failures:
            print(f"  {eid}: {msg}", file=sys.stderr)
        sys.exit(1)

    with open(ledger_path, "w", encoding="utf-8") as f:
        f.write(new_ledger_text)
    print(f"\nwrote {ledger_path}")


if __name__ == "__main__":
    main()
