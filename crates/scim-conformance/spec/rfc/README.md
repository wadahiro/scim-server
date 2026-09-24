# RFC 7643 / RFC 7644 — vendored specification text

This directory contains **verbatim, unmodified** copies of the plain-text
renditions of RFC 7643 ("System for Cross-domain Identity Management: Core
Schema") and RFC 7644 ("System for Cross-domain Identity Management:
Protocol"), fetched from the IETF RFC repository.

## Source

```
https://www.rfc-editor.org/rfc/rfc7643.txt
https://www.rfc-editor.org/rfc/rfc7644.txt
```

## Why these files may be redistributed unmodified

RFC 7643 and RFC 7644 are IETF Contributions/IETF Documents published under
the IETF Trust Legal Provisions (TLP), currently the "Corrected Trust Legal
Provisions 5.0" (https://trustee.ietf.org/documents/trust-legal-provisions/).
Section 3.c.i of the TLP grants:

> "to copy, publish, display and distribute IETF Contributions and IETF
> Documents in full and without modification"

as a non-exclusive, royalty-free, worldwide right and license under all
copyrights and rights of authors, for use outside the IETF Standards
Process. This repository exercises only that reproduction right: both files
below are byte-identical copies of the RFC editor's own `.txt` rendition
(the two are also RFCs themselves, so each carries its own Copyright Notice
citing BCP 78 and the Trust Legal Provisions — see e.g. `rfc7644.txt`
L63-75). No edits, reflowing, or reformatting has been applied.

Because the license only covers unmodified reproduction, this repository
never commits a "cleaned" or reflowed version of these files. Any derived
data (extracted spans, quotes, JSON records) is produced at build/test time
by code in `crates/scim-conformance` (see `src/gen/`, `src/ledger.rs`, and
`src/spec_extract.rs`) and is committed instead as `span` + `sha256`, never
as re-typeset RFC prose.

**RFC 6749** (OAuth 2.0) is deliberately **not** vendored here: confirm its
redistribution terms before adding it.

## Files

| File | RFC | Title |
|---|---|---|
| `rfc7643.txt` | RFC 7643 | SCIM: Core Schema |
| `rfc7644.txt` | RFC 7644 | SCIM: Protocol |

## Verifying integrity

```bash
cd crates/scim-conformance/spec/rfc
shasum -a 256 -c SHA256SUMS
```

Both files must report `OK`. If either fails, do not use the file — re-fetch
per the procedure below and update `SHA256SUMS` only after confirming the new
hash against a second, independent source (e.g. the RFC's own errata page or
a mirror).

## Re-fetching

```bash
cd crates/scim-conformance/spec/rfc
curl -sSf https://www.rfc-editor.org/rfc/rfc7643.txt -o rfc7643.txt
curl -sSf https://www.rfc-editor.org/rfc/rfc7644.txt -o rfc7644.txt
shasum -a 256 rfc7643.txt rfc7644.txt > SHA256SUMS
shasum -a 256 -c SHA256SUMS
```

RFC text is expected to never change once published (only errata are tracked
separately by the RFC Editor), so a hash mismatch after a re-fetch is a sign
of a network/proxy problem, not a legitimate update — investigate before
overwriting `SHA256SUMS`.
