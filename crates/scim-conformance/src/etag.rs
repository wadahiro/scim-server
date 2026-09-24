//! RFC 7644 §3.14 (Versioning Resources -- ETags and conditional requests),
//! T13: this family's checks, gated end to end on `Capability::Etag`.
//!
//! §3.14's own text is unusual among the sections this crate checks: its
//! core paragraph mixes three different RFC 2119 keywords in one sentence
//! (RFC 7644 §3.14, `rfc7644.txt:3963-3969`): "Service providers **MAY**
//! support weak ETags ... When supported, SCIM ETags **MUST** be specified
//! as an HTTP header and **SHOULD** be specified within the 'version'
//! attribute". Every earlier check family in this crate (schema matrix,
//! `crate::probes`, `crate::templates`) judges MUST/SHALL rules only, so
//! `Verdict::Fail` has always meant "a violation." A `MAY` or `SHOULD` rule
//! doesn't fit that: reporting a missing (but merely recommended)
//! `meta.version` as `Fail` would overstate what RFC 7644 actually
//! requires. `crate::matrix::Keyword` (`Must`/`Should`/`May`) is this
//! module's addition to the shared `Outcome`/`Finding` model, and this
//! module's policy for using it is:
//!
//! - `Must`/`Shall` deviation -> [`Verdict::Fail`] (a real violation).
//! - `Should` deviation -> [`Verdict::Info`], never `Fail` -- recorded as
//!   an observation in `detail`/`observed`, not reported as broken.
//! - `May` -> never a failure; a `May`-keyworded check only records what it
//!   observed (`Verdict::Pass` or `Verdict::Info`), e.g. which ETag form
//!   (weak/strong) a provider chose.
//!
//! Every row below sets `keyword` accordingly, and [`crate::render::render_text`]
//! prints it (`[MUST]`/`[SHOULD]`/`[MAY]`) next to the verdict tag so a
//! reader can tell a violation from a deviation from a recorded
//! observation at a glance. Future MUST/SHOULD/MAY-mixed families should
//! follow the same policy rather than inventing a new one.
//!
//! RFC 7232 (HTTP Conditional Requests, which §3.14 incorporates by
//! reference for ETag comparison semantics, `If-Match`, and
//! `If-None-Match`) is **not vendored** in this repository's `crates/scim-conformance/spec/rfc/`.
//! Every citation below that depends on RFC 7232's operative detail (weak
//! vs. strong comparison, the exact `If-Match`/`If-None-Match` grammar)
//! cites the §3.14 sentence that incorporates it by reference instead of
//! inventing a line number into an unvendored document -- see each
//! `Basis` constant's own doc comment in `crate::basis`. Vendoring RFC
//! 7232 outright (so those details could be cited directly) is a
//! reasonable follow-up, but is *not* done here -- see this crate's task
//! report for the concrete steps that would take (SHA256SUMS entry, README
//! attribution, Dockerfile COPY, matching the T0 treatment `rfc7643.txt`/
//! `rfc7644.txt` already got).
//!
//! # The matrix
//!
//! Four groups of rows, generated mechanically from §3.14's own axes
//! rather than hand-picked one at a time:
//!
//! 1. **Representation** (one `POST`, read once): is `ETag` present as a
//!    response header (`Must`); is `meta.version` present in the body
//!    (`Should`); do the two agree when both are present (`Must`, the
//!    consequence of both being *the same* version per the RFC's own
//!    worked example, `rfc7644.txt:4003-4037`); which form (weak/strong)
//!    was used (`May`, recorded either way, never judged).
//! 2. **Conditional read**: `GET` x `If-None-Match` in
//!    `{current, stale, *}` -> `{304 empty body, 200, 304}` (`Must`).
//! 3. **Conditional write**: `{PUT, PATCH}` x `If-Match` in
//!    `{current, stale, *}` -> `{2xx (version advances), 412, 2xx}`
//!    (`Must`) -- §3.14 (`rfc7644.txt:4054-4058`) names exactly these two
//!    methods for `If-Match`, so both are in scope on §3.14's own
//!    authority. The PATCH leg is additionally gated on
//!    `Capability::Patch`, since a `patch.supported: false` provider would
//!    otherwise fail these rows for an unrelated reason (PATCH itself
//!    being unsupported), not for anything §3.14 governs.
//! 4. **`DELETE` x `If-Match`**: *not* named by §3.14, whose If-Match
//!    sentence lists only PUT and PATCH. Included anyway, but judged
//!    `Info`-only (never `Fail`) and cited primarily to a deliberately
//!    weaker basis: RFC 7644 §3.12 **Table 8** "SCIM HTTP Status Code
//!    Usage" (`rfc7644.txt:3779-3781`), whose 412 row does list DELETE
//!    alongside PUT/PATCH. (The task brief that scoped this family named
//!    "Table 9" for this row; Table 9 is actually the `scimType`
//!    detail-error-keyword table a few pages later and has no
//!    `preconditionFailed`/412 entry at all -- Table 8 is the correct
//!    citation, corrected here.) This is the one row in the whole family
//!    whose authority is weaker than the rest: it never fails a provider
//!    either way, it only records what a provider that *does* implement
//!    DELETE preconditions does.
//!
//! # `--read-only`
//!
//! This whole family is wired into [`crate::full_suite`]/[`crate::diagnose`]
//! (the non-read-only path), the same way `crate::probes` and
//! `crate::ledger_suite` are -- not split so its GET-only conditional-read
//! rows run under `--read-only`. Two reasons: (1) `DiagOptions::read_only`
//! is already a coarse, family-level gate (see that field's own doc
//! comment) that runs *only* `checks_from_attrdefs` and skips every other
//! family outright, schema matrix and probes included -- carving out a
//! read-only-safe subset of just this one family would be a new, finer
//! granularity nothing else in the CLI has. (2) Even the conditional-read
//! rows are not meaningfully read-only in practice: they need a resource
//! whose *current* ETag is known and a genuinely *stale* one to contrast it
//! with (see `conditional_read`'s doc comment on producing "stale" via a
//! real, unconditional write) -- finding a pre-existing resource via
//! `GET /Users?count=1` would only get the read half right, since the
//! "stale" reference still requires a write this family doesn't control
//! (or own) under `--read-only`.

use serde_json::{json, Value};

use crate::basis::{self, Basis};
use crate::capability::{self, Capabilities, Capability};
use crate::client::{truncate, ScimClient, ScimResponse};
use crate::matrix::exec::{body_of, cleanup, is_2xx, make_baseline, short_uid, Bookkeeping};
use crate::matrix::{Characteristic, Keyword, Method, Outcome, Verdict};
use crate::schema::Resource;

const USER_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const PATCHOP_URN: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// Mirrors `crate::matrix::exec::safe`: turns a transport error into a
/// synthetic status-0 response instead of propagating it, so every check
/// below always has a `ScimResponse` to judge.
async fn safe(
    fut: impl std::future::Future<Output = Result<ScimResponse, crate::client::Error>>,
) -> ScimResponse {
    match fut.await {
        Ok(r) => r,
        Err(e) => ScimResponse {
            status: 0,
            headers: reqwest::header::HeaderMap::new(),
            body: None,
            raw: e.to_string(),
            exchange: crate::client::Exchange {
                method: String::new(),
                url: String::new(),
                status: None,
                elapsed_ms: 0,
                request_body: None,
                response_body: None,
            },
        },
    }
}

/// One row's fixed identity, carrying its own `basis`/`secondary`/`keyword`
/// explicitly (unlike `crate::probes::ProbeKey`, which derives `basis` from
/// a fixed characteristic -> basis table): rows sharing
/// `Characteristic::EtagConditionalWrite` cite different bases depending on
/// method (PUT/PATCH cite §3.14 itself; DELETE cites the weaker Table 8),
/// so there is no single per-characteristic basis to look up.
struct Key {
    attribute: &'static str,
    characteristic: Characteristic,
    method: Method,
    basis: Basis,
    secondary: Vec<Basis>,
    keyword: Keyword,
}

impl Key {
    fn raw(
        &self,
        verdict: Verdict,
        observed: Option<String>,
        detail: impl Into<String>,
    ) -> Outcome {
        Outcome {
            attribute: self.attribute.to_string(),
            schema: USER_URN.to_string(),
            resource: Resource::User,
            characteristic: self.characteristic,
            method: self.method,
            verdict,
            basis: self.basis,
            detail: detail.into(),
            observed,
            secondary: self.secondary.clone(),
            keyword: Some(self.keyword),
        }
    }

    /// Judges a boolean per this row's keyword policy (see module docs):
    /// `ok` -> `Pass`; `!ok` -> `Fail` for `Must`, `Info` for `Should`/`May`.
    fn judge(&self, ok: bool, observed: impl Into<String>, detail: impl Into<String>) -> Outcome {
        if ok {
            self.raw(Verdict::Pass, Some(observed.into()), detail)
        } else {
            let verdict = match self.keyword {
                Keyword::Must => Verdict::Fail,
                Keyword::Should | Keyword::May => Verdict::Info,
            };
            self.raw(verdict, Some(observed.into()), detail)
        }
    }

    /// Records an observation without judging it pass/fail at all -- used
    /// by the `May`-keyworded ETag-form row and the `DELETE x If-Match`
    /// rows, which are informational regardless of what they observe.
    fn info(&self, observed: impl Into<String>, detail: impl Into<String>) -> Outcome {
        self.raw(Verdict::Info, Some(observed.into()), detail)
    }

    fn skip(&self, detail: impl Into<String>) -> Outcome {
        self.raw(Verdict::Skip, None, detail)
    }

    fn error(&self, detail: impl Into<String>) -> Outcome {
        self.raw(Verdict::Error, None, detail)
    }
}

fn etag_header(r: &ScimResponse) -> Option<String> {
    r.headers
        .get("ETag")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

fn meta_version(r: &ScimResponse) -> Option<String> {
    body_of(r)
        .pointer("/meta/version")
        .and_then(Value::as_str)
        .map(String::from)
}

/// `W/"..."` -> weak, `"..."` (no `W/` prefix) -> strong. Per RFC 7232
/// §2.3 (incorporated by reference, not vendored -- see module docs).
fn etag_form(etag: &str) -> &'static str {
    if etag.starts_with("W/") {
        "weak"
    } else {
        "strong"
    }
}

// ------------------------------------------------------------- representation

/// Group 1: one `POST`, read once. See module docs for the four rows.
/// Returns the rows plus `(id, known_current_etag)` for the fixture, if
/// creation succeeded at all.
async fn representation(
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> (Vec<Outcome>, Option<(String, String)>) {
    let header_key = Key {
        attribute: "ETag",
        characteristic: Characteristic::EtagRepresentation,
        method: Method::Post,
        basis: basis::ETAG_REPRESENTATION,
        secondary: Vec::new(),
        keyword: Keyword::Must,
    };
    let version_key = Key {
        attribute: "meta.version",
        keyword: Keyword::Should,
        ..header_key.clone_shape()
    };
    let consistency_key = Key {
        attribute: "ETag==meta.version",
        keyword: Keyword::Must,
        ..header_key.clone_shape()
    };
    let form_key = Key {
        attribute: "ETag.form",
        keyword: Keyword::May,
        ..header_key.clone_shape()
    };

    let r = safe(client.post("/Users", &make_baseline(Resource::User))).await;
    if !is_2xx(r.status) {
        let detail = format!(
            "baseline POST failed: {} {}",
            r.status,
            truncate(&r.raw, 200)
        );
        return (
            vec![
                header_key.error(detail.clone()),
                version_key.error(detail.clone()),
                consistency_key.error(detail.clone()),
                form_key.error(detail),
            ],
            None,
        );
    }
    let Some(id) = r.id() else {
        let detail = "baseline POST succeeded but returned no id";
        return (
            vec![
                header_key.error(detail),
                version_key.error(detail),
                consistency_key.error(detail),
                form_key.error(detail),
            ],
            None,
        );
    };
    bk.note("/Users", id.clone());

    let header = etag_header(&r);
    let version = meta_version(&r);

    let mut outcomes = Vec::new();

    outcomes.push(header_key.judge(
        header.is_some(),
        header.clone().unwrap_or_else(|| "absent".to_string()),
        "RFC 7644 §3.14: \"When supported, SCIM ETags MUST be specified as an HTTP header\" \
         -- an ETag-supporting provider's POST response must carry one.",
    ));

    outcomes.push(version_key.judge(
        version.is_some(),
        version.clone().unwrap_or_else(|| "absent".to_string()),
        "RFC 7644 §3.14: \"... and SHOULD be specified within the 'version' attribute \
         contained in the resource's 'meta' attribute\" -- a SHOULD, so a missing \
         meta.version is recorded as an observation (INFO), never a violation.",
    ));

    match (&header, &version) {
        (Some(h), Some(v)) => outcomes.push(consistency_key.judge(
            h == v,
            format!("ETag={h:?} meta.version={v:?}"),
            "the RFC's own worked example (rfc7644.txt:4003-4037) shows the response ETag \
             header and meta.version as the identical string -- a provider that emits both \
             but disagrees between them cannot be relied on by a client comparing one \
             against the other.",
        )),
        _ => outcomes.push(consistency_key.skip(
            "cannot compare: ETag header and/or meta.version absent (see the two rows above)",
        )),
    }

    match &header {
        Some(h) => outcomes.push(form_key.info(
            etag_form(h),
            format!(
                "ETag {h:?} is a {} ETag; RFC 7644 §3.14 permits either (\"MAY support weak \
                 ETags\")",
                etag_form(h)
            ),
        )),
        None => outcomes.push(form_key.skip("no ETag header to classify (see the ETag row above)")),
    }

    // Prefer the header value as the fixture's known-current ETag (it's
    // the one MUST-guaranteed to exist when supported); fall back to
    // meta.version if the header was somehow missing but the body wasn't.
    let known_etag = header.or(version);
    (outcomes, known_etag.map(|e| (id, e)))
}

impl Key {
    /// Copies every field except `attribute`/`keyword` (the two fields
    /// every caller above overrides via struct-update syntax).
    fn clone_shape(&self) -> Key {
        Key {
            attribute: self.attribute,
            characteristic: self.characteristic,
            method: self.method,
            basis: self.basis,
            secondary: self.secondary.clone(),
            keyword: self.keyword,
        }
    }

    /// Copies every field except `attribute`, which is overridden -- used
    /// to give each `{current,stale,*}` case of one axis a distinct
    /// `Outcome::attribute` (and therefore a distinct `Finding::key`; see
    /// `crate::report::Finding::key`'s doc comment: three rows sharing a
    /// (resource, attribute, characteristic, method) tuple would collide).
    fn with_attribute(&self, attribute: &'static str) -> Key {
        Key {
            attribute,
            ..self.clone_shape()
        }
    }
}

// ------------------------------------------------------------ conditional read

/// Group 2: `GET x If-None-Match`. "Stale" is produced the way §3.14's own
/// scenario implies (another client's write moved the version on): the
/// fixture's ETag as of `representation` (`stale_etag`) is already
/// superseded by the unconditional bump this function issues before
/// testing "current" -- not a fabricated value, an actually-superseded
/// one.
async fn conditional_read(
    client: &ScimClient,
    id: &str,
    stale_etag: &str,
) -> (Vec<Outcome>, Option<String>) {
    let key = Key {
        attribute: "If-None-Match",
        characteristic: Characteristic::EtagConditionalRead,
        method: Method::Get,
        basis: basis::ETAG_CONDITIONAL_READ,
        secondary: Vec::new(),
        keyword: Keyword::Must,
    };
    let path = format!("/Users/{id}");

    // One unconditional write to move the version past `stale_etag`,
    // giving the "current" leg below a genuinely fresh ETag to test.
    let got = safe(client.get(&path)).await;
    let mut body = body_of(&got);
    body["nickName"] = json!(format!("n-{}", short_uid()));
    let bump = safe(client.put(&path, &body)).await;
    let Some(current_etag) = etag_header(&bump).or_else(|| meta_version(&bump)) else {
        let d = "could not establish the fixture's current ETag (unconditional bump PUT \
                 failed or returned no ETag/meta.version) to run conditional-read checks";
        return (
            vec![
                key.with_attribute("If-None-Match=current").error(d),
                key.with_attribute("If-None-Match=stale").error(d),
                key.with_attribute("If-None-Match=*").error(d),
            ],
            None,
        );
    };

    let mut outcomes = Vec::new();

    // current -> 304, empty body
    let r_current = safe(client.get_with_headers(&path, &[("If-None-Match", &current_etag)])).await;
    outcomes.push(key.with_attribute("If-None-Match=current").judge(
        r_current.status == 304 && r_current.raw.is_empty(),
        format!(
            "status={} body_len={}",
            r_current.status,
            r_current.raw.len()
        ),
        format!(
            "If-None-Match: {current_etag:?} (the resource's real current ETag) must yield \
             \"an empty body with a 304 (Not Modified) response code\" (rfc7644.txt:4051-4052)"
        ),
    ));

    // stale -> 200
    let r_stale = safe(client.get_with_headers(&path, &[("If-None-Match", stale_etag)])).await;
    outcomes.push(key.with_attribute("If-None-Match=stale").judge(
        r_stale.status == 200,
        format!("status={}", r_stale.status),
        format!(
            "If-None-Match: {stale_etag:?} (a genuinely superseded ETag, from before this \
             function's unconditional bump changed the resource) does not match the current \
             representation, so the request must proceed normally (200), not 304"
        ),
    ));

    // * -> 304 (the resource exists)
    let r_star = safe(client.get_with_headers(&path, &[("If-None-Match", "*")])).await;
    outcomes.push(key.with_attribute("If-None-Match=*").judge(
        r_star.status == 304 && r_star.raw.is_empty(),
        format!("status={} body_len={}", r_star.status, r_star.raw.len()),
        "If-None-Match: * matches any existing representation, so an existing resource must \
         yield 304 with an empty body, same as the current-ETag case (rfc7644.txt:4051-4052)",
    ));

    (outcomes, Some(current_etag))
}

// ----------------------------------------------------------- conditional write

/// Sends one conditional `PUT`/`PATCH`: `body` is the exact request body
/// (a full mutated representation for PUT, a `PatchOp` for PATCH -- see
/// `put_body`/`patch_body` below), `if_match` is the `If-Match` header
/// value.
async fn send_conditional(
    client: &ScimClient,
    method: Method,
    path: &str,
    body: &Value,
    if_match: &str,
) -> ScimResponse {
    match method {
        Method::Put => safe(client.put_with_headers(path, body, &[("If-Match", if_match)])).await,
        Method::Patch => {
            safe(client.patch_with_headers(path, body, &[("If-Match", if_match)])).await
        }
        other => unreachable!("send_conditional only supports PUT/PATCH, got {other:?}"),
    }
}

fn put_body(current: &Value) -> Value {
    let mut b = current.clone();
    b["nickName"] = json!(format!("n-{}", short_uid()));
    b
}

fn patch_body(_current: &Value) -> Value {
    json!({
        "schemas": [PATCHOP_URN],
        "Operations": [
            {"op": "replace", "path": "nickName", "value": format!("n-{}", short_uid())},
        ],
    })
}

/// One `{PUT,PATCH} x If-Match` triple against `id`, starting from
/// `start_etag` (the resource's known-current ETag at the start of this
/// call). Returns the outcomes plus the resource's ETag after the triple
/// (so a caller can chain another triple, e.g. PATCH after PUT, without
/// re-fetching).
///
/// Sequencing (see module docs): `current` first (bumps the version and
/// asserts it actually advanced -- the "do not inadvertently overwrite
/// each other's changes" mechanism actually firing, not just a 2xx);
/// `stale` reuses `start_etag`, which the `current` step has by now made
/// genuinely stale; `*` runs last and bumps the version again.
async fn conditional_write_triple(
    client: &ScimClient,
    id: &str,
    method: Method,
    start_etag: &str,
    build_body: impl Fn(&Value) -> Value,
) -> (Vec<Outcome>, Option<String>) {
    let key = Key {
        attribute: "If-Match",
        characteristic: Characteristic::EtagConditionalWrite,
        method,
        basis: basis::ETAG_CONDITIONAL_WRITE,
        secondary: Vec::new(),
        keyword: Keyword::Must,
    };
    let path = format!("/Users/{id}");

    let mut outcomes = Vec::new();

    // current -> 2xx, and the version must advance.
    let got = safe(client.get(&path)).await;
    let body = build_body(&body_of(&got));
    let r_current = send_conditional(client, method, &path, &body, start_etag).await;
    let new_etag_current = etag_header(&r_current).or_else(|| meta_version(&r_current));
    let advanced = new_etag_current.as_deref().is_some_and(|e| e != start_etag);
    outcomes.push(key.with_attribute("If-Match=current").judge(
        is_2xx(r_current.status) && advanced,
        format!(
            "status={} new_etag={:?}",
            r_current.status, new_etag_current
        ),
        format!(
            "{method:?} If-Match: {start_etag:?} (the resource's real current ETag) must \
             succeed, and the returned ETag must differ from the one sent -- the version \
             actually advancing is what \"ensuring that clients do not inadvertently \
             overwrite each other's changes\" (rfc7644.txt:3966-3967) means in practice"
        ),
    ));
    let etag_after_current = new_etag_current.unwrap_or_else(|| start_etag.to_string());

    // stale -> 412 (start_etag is now superseded by the write above).
    let got2 = safe(client.get(&path)).await;
    let body2 = build_body(&body_of(&got2));
    let r_stale = send_conditional(client, method, &path, &body2, start_etag).await;
    outcomes.push(key.with_attribute("If-Match=stale").judge(
        r_stale.status == 412,
        format!("status={}", r_stale.status),
        format!(
            "{method:?} If-Match: {start_etag:?} is now stale (the current-ETag row above \
             already advanced the version past it), so this write must fail with 412 \
             (Precondition Failed) rather than applying"
        ),
    ));

    // * -> 2xx (matches any existing representation).
    let got3 = safe(client.get(&path)).await;
    let body3 = build_body(&body_of(&got3));
    let r_star = send_conditional(client, method, &path, &body3, "*").await;
    outcomes.push(key.with_attribute("If-Match=*").judge(
        is_2xx(r_star.status),
        format!("status={}", r_star.status),
        format!("{method:?} If-Match: * matches any existing representation, so it must succeed"),
    ));
    let etag_after_star = etag_header(&r_star)
        .or_else(|| meta_version(&r_star))
        .unwrap_or(etag_after_current);

    (outcomes, Some(etag_after_star))
}

// ------------------------------------------------------ delete x if-match

/// Group 4: `DELETE x If-Match`, not named by §3.14 (see module docs) --
/// always `Verdict::Info`, cited primarily to the weaker Table 8 basis,
/// never judged `Fail`.
async fn delete_conditional(client: &ScimClient) -> Vec<Outcome> {
    let key = Key {
        attribute: "If-Match",
        characteristic: Characteristic::EtagConditionalWrite,
        method: Method::Delete,
        basis: basis::ETAG_TABLE8_PRECONDITION_FAILED,
        secondary: vec![basis::ETAG_CONDITIONAL_WRITE],
        keyword: Keyword::May,
    };

    let mut outcomes = Vec::new();

    // current -> 2xx
    match create_fixture(client).await {
        Ok((id, etag)) => {
            let r =
                safe(client.delete_with_headers(&format!("/Users/{id}"), &[("If-Match", &etag)]))
                    .await;
            let case_key = key.with_attribute("If-Match=current");
            outcomes.push(case_key.info(
                format!("status={}", r.status),
                format!(
                    "DELETE If-Match: {etag:?} (real current ETag) against a server that \
                     implements DELETE preconditions is expected to succeed (2xx), observed \
                     status={}; not §3.14-mandated (it names only PUT/PATCH), so this can \
                     never fail the family -- see Table 8 (rfc7644.txt:3779-3781)",
                    r.status
                ),
            ));
        }
        Err(e) => outcomes.push(key.with_attribute("If-Match=current").error(e)),
    }

    // stale -> 412
    match create_fixture(client).await {
        Ok((id, etag)) => {
            let path = format!("/Users/{id}");
            // Unconditional bump to make `etag` genuinely stale.
            let got = safe(client.get(&path)).await;
            let mut body = body_of(&got);
            body["nickName"] = json!(format!("n-{}", short_uid()));
            let _bump = safe(client.put(&path, &body)).await;

            let r = safe(client.delete_with_headers(&path, &[("If-Match", &etag)])).await;
            let case_key = key.with_attribute("If-Match=stale");
            outcomes.push(case_key.info(
                format!("status={}", r.status),
                format!(
                    "DELETE If-Match: {etag:?} (now stale after an unconditional PUT) against \
                     a server that implements DELETE preconditions is expected to fail (412), \
                     observed status={}; not §3.14-mandated -- see Table 8 (rfc7644.txt:3779-3781)",
                    r.status
                ),
            ));
            // Best-effort cleanup regardless of what the conditional
            // DELETE above did (an unconditional DELETE always applies).
            let _ = safe(client.delete(&path)).await;
        }
        Err(e) => outcomes.push(key.with_attribute("If-Match=stale").error(e)),
    }

    // * -> 2xx
    match create_fixture(client).await {
        Ok((id, _etag)) => {
            let r = safe(client.delete_with_headers(&format!("/Users/{id}"), &[("If-Match", "*")]))
                .await;
            let case_key = key.with_attribute("If-Match=*");
            outcomes.push(case_key.info(
                format!("status={}", r.status),
                format!(
                    "DELETE If-Match: * matches any existing representation; observed \
                     status={}; not §3.14-mandated -- see Table 8 (rfc7644.txt:3779-3781)",
                    r.status
                ),
            ));
        }
        Err(e) => outcomes.push(key.with_attribute("If-Match=*").error(e)),
    }

    outcomes
}

async fn create_fixture(client: &ScimClient) -> Result<(String, String), String> {
    let r = safe(client.post("/Users", &make_baseline(Resource::User))).await;
    if !is_2xx(r.status) {
        return Err(format!(
            "fixture POST failed: {} {}",
            r.status,
            truncate(&r.raw, 200)
        ));
    }
    let Some(id) = r.id() else {
        return Err("fixture POST succeeded but returned no id".to_string());
    };
    let etag = etag_header(&r)
        .or_else(|| meta_version(&r))
        .ok_or_else(|| "fixture POST succeeded but carried no ETag/meta.version".to_string())?;
    Ok((id, etag))
}

// ------------------------------------------------------------------- driver

/// The three `{current,stale,*}` case labels every conditional-read/write
/// axis is built from -- shared by the fallback-error and gate-skip paths
/// below so their row shape matches what a normal run would have produced
/// (see `Key::with_attribute`'s doc comment on why each case needs its own
/// `attribute`).
const CASES: [&str; 3] = ["current", "stale", "*"];

/// Three ERROR rows (one per `{current,stale,*}` case) for one
/// conditional-read/write axis, used when no fixture exists to run that
/// axis's checks against at all.
fn error_triple(
    prefix: &'static str,
    characteristic: Characteristic,
    method: Method,
    detail: &'static str,
) -> Vec<Outcome> {
    let basis_val = match characteristic {
        Characteristic::EtagConditionalRead => basis::ETAG_CONDITIONAL_READ,
        _ => basis::ETAG_CONDITIONAL_WRITE,
    };
    CASES
        .iter()
        .map(|case| {
            let attribute: &'static str = case_attribute(prefix, case);
            Key {
                attribute,
                characteristic,
                method,
                basis: basis_val,
                secondary: Vec::new(),
                keyword: Keyword::Must,
            }
            .error(detail)
        })
        .collect()
}

/// Three SKIP rows (one per case) for the PATCH conditional-write axis,
/// used when `patch.supported=false`.
fn patch_skip_rows() -> Vec<Outcome> {
    CASES
        .iter()
        .map(|case| {
            let attribute: &'static str = case_attribute("If-Match", case);
            Key {
                attribute,
                characteristic: Characteristic::EtagConditionalWrite,
                method: Method::Patch,
                basis: basis::ETAG_CONDITIONAL_WRITE,
                secondary: Vec::new(),
                keyword: Keyword::Must,
            }
            .skip("patch.supported=false")
        })
        .collect()
}

/// `case_attribute("If-Match", "stale")` -> `"If-Match=stale"`, from a
/// small fixed table (kept `&'static str` -- see `Key::attribute`'s own
/// doc comment on why these are static literals, not formatted strings).
fn case_attribute(prefix: &str, case: &str) -> &'static str {
    match (prefix, case) {
        ("If-None-Match", "current") => "If-None-Match=current",
        ("If-None-Match", "stale") => "If-None-Match=stale",
        ("If-None-Match", "*") => "If-None-Match=*",
        ("If-Match", "current") => "If-Match=current",
        ("If-Match", "stale") => "If-Match=stale",
        ("If-Match", "*") => "If-Match=*",
        _ => unreachable!("case_attribute called with an unknown (prefix, case) pair"),
    }
}

/// Every row this family can produce, each SKIPped with `reason` -- used
/// when `Capability::Etag` is advertised unsupported, so `run_all` returns
/// without sending a single conditional request (not even a fixture POST).
fn skip_everything(reason: &str) -> Vec<Outcome> {
    let mut rows: Vec<(&'static str, Characteristic, Method, Basis, Keyword)> = vec![
        (
            "meta.version",
            Characteristic::EtagRepresentation,
            Method::Post,
            basis::ETAG_REPRESENTATION,
            Keyword::Should,
        ),
        (
            "ETag",
            Characteristic::EtagRepresentation,
            Method::Post,
            basis::ETAG_REPRESENTATION,
            Keyword::Must,
        ),
        (
            "ETag==meta.version",
            Characteristic::EtagRepresentation,
            Method::Post,
            basis::ETAG_REPRESENTATION,
            Keyword::Must,
        ),
        (
            "ETag.form",
            Characteristic::EtagRepresentation,
            Method::Post,
            basis::ETAG_REPRESENTATION,
            Keyword::May,
        ),
    ];
    for case in CASES {
        rows.push((
            case_attribute("If-None-Match", case),
            Characteristic::EtagConditionalRead,
            Method::Get,
            basis::ETAG_CONDITIONAL_READ,
            Keyword::Must,
        ));
    }
    for case in CASES {
        rows.push((
            case_attribute("If-Match", case),
            Characteristic::EtagConditionalWrite,
            Method::Put,
            basis::ETAG_CONDITIONAL_WRITE,
            Keyword::Must,
        ));
    }
    for case in CASES {
        rows.push((
            case_attribute("If-Match", case),
            Characteristic::EtagConditionalWrite,
            Method::Patch,
            basis::ETAG_CONDITIONAL_WRITE,
            Keyword::Must,
        ));
    }
    for case in CASES {
        rows.push((
            case_attribute("If-Match", case),
            Characteristic::EtagConditionalWrite,
            Method::Delete,
            basis::ETAG_TABLE8_PRECONDITION_FAILED,
            Keyword::May,
        ));
    }
    rows.into_iter()
        .map(|(attribute, characteristic, method, basis_val, keyword)| {
            Key {
                attribute,
                characteristic,
                method,
                basis: basis_val,
                secondary: Vec::new(),
                keyword,
            }
            .skip(reason.to_string())
        })
        .collect()
}

/// Runs the whole §3.14 family against `client`. Fetches
/// `GET /ServiceProviderConfig` itself (the same pattern `crate::probes::
/// run_all` uses) and gates on `Capability::Etag`: if the provider reports
/// `etag.supported: false`, every row SKIPs with that reason and no
/// conditional request is ever sent (not even the fixture POST) -- see
/// `tests/conformance_etag_capability_gate.rs`. The three PATCH rows are
/// additionally gated on `Capability::Patch` (see module docs).
pub async fn run_all(client: &mut ScimClient) -> Vec<Outcome> {
    let caps: Capabilities = capability::fetch(client).await;
    let caps = &caps;
    if caps.get(Capability::Etag) == Some(false) {
        return skip_everything("etag.supported=false");
    }

    let mut bk = Bookkeeping::new();
    let mut outcomes = Vec::new();

    let (rep_outcomes, fixture) = representation(client, &mut bk).await;
    outcomes.extend(rep_outcomes);

    let Some((id, etag_at_creation)) = fixture else {
        // No usable fixture (the baseline POST itself failed) -- every
        // read/write-conditional row would just re-report the same
        // failure; record one ERROR triple per remaining axis instead of
        // sending doomed requests. `delete_conditional` is unaffected --
        // it creates its own independent fixtures -- so it still runs.
        outcomes.extend(error_triple(
            "If-None-Match",
            Characteristic::EtagConditionalRead,
            Method::Get,
            "no fixture (baseline POST failed above)",
        ));
        outcomes.extend(error_triple(
            "If-Match",
            Characteristic::EtagConditionalWrite,
            Method::Put,
            "no fixture (baseline POST failed above)",
        ));
        if caps.get(Capability::Patch) == Some(false) {
            outcomes.extend(patch_skip_rows());
        } else {
            outcomes.extend(error_triple(
                "If-Match",
                Characteristic::EtagConditionalWrite,
                Method::Patch,
                "no fixture (baseline POST failed above)",
            ));
        }
        outcomes.extend(delete_conditional(client).await);
        cleanup(client, &bk).await;
        return outcomes;
    };

    let (read_outcomes, current_after_read) =
        conditional_read(client, &id, &etag_at_creation).await;
    outcomes.extend(read_outcomes);
    let current_etag = current_after_read.unwrap_or(etag_at_creation);

    let (put_outcomes, current_after_put) =
        conditional_write_triple(client, &id, Method::Put, &current_etag, put_body).await;
    outcomes.extend(put_outcomes);

    if caps.get(Capability::Patch) == Some(false) {
        outcomes.extend(patch_skip_rows());
    } else {
        let current_etag = current_after_put.unwrap_or(current_etag);
        let (patch_outcomes, _) =
            conditional_write_triple(client, &id, Method::Patch, &current_etag, patch_body).await;
        outcomes.extend(patch_outcomes);
    }

    outcomes.extend(delete_conditional(client).await);

    cleanup(client, &bk).await;
    outcomes
}
