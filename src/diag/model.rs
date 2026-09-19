//! Core types for `scim-server diagnose`.
//!
//! These are deliberately data-only: a check is described by a [`CheckDef`]
//! record rather than a trait object, and results are plain values
//! ([`CheckOutcome`], [`Report`]) so that renderers stay pure functions over
//! data instead of re-running probes.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    Compat,
    Rfc7644,
    Spc,
    Etag,
}

impl Tier {
    pub fn slug(&self) -> &'static str {
        match self {
            Tier::Compat => "tier1",
            Tier::Rfc7644 => "tier2",
            Tier::Spc => "tier3",
            Tier::Etag => "tier4",
        }
    }
    pub fn title(&self) -> &'static str {
        match self {
            Tier::Compat => "Tier 1 — Compatibility knobs",
            Tier::Rfc7644 => "Tier 2 — RFC 7644 conformance",
            Tier::Spc => "Tier 3 — ServiceProviderConfig vs observed behaviour",
            Tier::Etag => "Tier 4 — ETag / RFC 7232 conditional requests",
        }
    }
    pub const ALL: [Tier; 4] = [Tier::Compat, Tier::Rfc7644, Tier::Spc, Tier::Etag];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KnobValue {
    Bool(bool),
    Str(String),
}

impl KnobValue {
    /// YAML snippet rendering. Bool prints as true/false, Str is quoted.
    pub fn to_yaml(&self) -> String {
        match self {
            KnobValue::Bool(b) => b.to_string(),
            KnobValue::Str(s) => format!("{:?}", s),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Verdict {
    /// Behaves per spec (i.e. matches scim-server's default). Knob checks
    /// populate `detected` with the observed value.
    Pass { detected: Option<KnobValue> },
    /// Spec violation / unexpected behaviour.
    Fail { detail: String },
    /// Differs from the default but is a known, accepted quirk. `detected`
    /// is always populated.
    Quirk { detected: KnobValue },
    /// Preconditions were not met, so the check did not run. `reason` must
    /// be specific.
    Skip { reason: String },
    /// The probe itself failed (transport error, etc).
    Error { detail: String },
}

impl Verdict {
    pub fn tag(&self) -> &'static str {
        match self {
            Verdict::Pass { .. } => "OK",
            Verdict::Fail { .. } => "FAIL",
            Verdict::Quirk { .. } => "QUIRK",
            Verdict::Skip { .. } => "SKIP",
            Verdict::Error { .. } => "ERROR",
        }
    }
    pub fn detected(&self) -> Option<&KnobValue> {
        match self {
            Verdict::Pass { detected } => detected.as_ref(),
            Verdict::Quirk { detected } => Some(detected),
            _ => None,
        }
    }
}

/// The fixtures / write-mode preconditions a check declares via
/// `&'static [Need]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    Writes,
    U1,
    U2,
    U3,
    G1,
    G2,
    Membership,
}

#[derive(Debug, Clone)]
pub struct Exchange {
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub elapsed_ms: u128,
    /// The client always populates these (§5.5 item 6's final call: keeping
    /// verbosity logic out of the client). Whether a renderer *prints* them
    /// depends on `-v`/`-vv` and on the check's verdict — see
    /// `render::text`, not this struct.
    pub request_body: Option<String>,
    pub response_body: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CheckOutcome {
    pub id: &'static str,
    pub title: &'static str,
    pub tier: Tier,
    pub severity: Severity,
    /// Only `Some` for Tier 1 (the `CompatibilityConfig` field name).
    pub knob: Option<&'static str>,
    pub verdict: Verdict,
    pub note: Option<String>,
    pub transcript: Vec<Exchange>,
}

impl CheckOutcome {
    /// The status word shared by both renderers (`render::text` wraps it in
    /// `[ OK  ]`-style brackets, `render::markdown` uses it bare in a table
    /// cell). `"INFO"` is not a `Verdict` variant — it's a display-only
    /// override for a `Severity::Info` check that `Pass`ed (currently only
    /// `etag.if_none_match_weak_compare`).
    pub fn status_word(&self) -> &'static str {
        if self.severity == Severity::Info && matches!(self.verdict, Verdict::Pass { .. }) {
            "INFO"
        } else {
            self.verdict.tag()
        }
    }
}

pub type CheckResult = (Verdict, Option<String>); // (verdict, note)

pub type CheckFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = CheckResult> + Send + 'a>>;

/// Checks are represented as a table of these descriptors rather than trait
/// objects: a `trait` + `async_trait` per check would mean a struct + 6
/// method impls per check, which is excessive for ~30 checks.
pub struct CheckDef {
    pub id: &'static str,
    pub title: &'static str,
    pub tier: Tier,
    pub severity: Severity,
    pub knob: Option<&'static str>,
    pub needs: &'static [Need],
    pub run: for<'a> fn(&'a mut crate::diag::ctx::DiagContext) -> CheckFuture<'a>,
}

/// One-liner for `catalog()` entries.
///
/// The coercion from a non-capturing closure to an HRTB fn pointer, combined
/// with the `Box::pin` unsizing coercion inside it, *should* both hold at
/// once — but compile exactly one entry with this macro before writing many.
/// If it does not compile, fall back to a named `wrap` function per check:
///   fn wrap<'a>(ctx: &'a mut DiagContext) -> CheckFuture<'a> { Box::pin(impl_fn(ctx)) }
/// and pass `run: wrap`.
#[macro_export]
macro_rules! check_def {
    ($id:expr, $title:expr, $tier:expr, $sev:expr, $knob:expr, $needs:expr, $f:path) => {
        $crate::diag::model::CheckDef {
            id: $id,
            title: $title,
            tier: $tier,
            severity: $sev,
            knob: $knob,
            needs: $needs,
            run: |ctx| Box::pin($f(ctx)),
        }
    };
}

#[derive(Debug, Clone, Default)]
pub struct Counts {
    pub pass: usize,
    pub fail: usize,
    pub quirk: usize,
    pub skip: usize,
    pub error: usize,
}

#[derive(Debug, Clone)]
pub struct ReportHeader {
    pub target: String,
    pub auth: String, // "bearer (token from SCIM_DIAG_TOKEN)"
    pub tls: String,  // "verified (built-in Mozilla roots)" / "DISABLED (--insecure)"
    pub mode: String, // "read-write" / "read-only" / "dry-run"
    pub prefix: String,
    pub probe_email: Option<String>,
    pub probe_attribute: String,
    pub started: String, // RFC3339
    pub duration_ms: u128,
    pub tool_version: &'static str,
    /// Verbosity level requested via `-v`/`-vv`; renderers use this to
    /// decide how much of each Exchange to print.
    pub verbose: u8,
    /// "TLS verification DISABLED (--insecure)" / "WRITE TIER DEGRADED: <reason>" etc.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CleanupReport {
    pub attempted: usize,
    pub deleted: usize,
    /// Things that could not be deleted: `Group 9f21… "…" (DELETE -> 500)`.
    pub failures: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub header: ReportHeader,
    pub outcomes: Vec<CheckOutcome>,
    pub cleanup: Option<CleanupReport>,
}

impl Report {
    pub fn counts(&self) -> Counts {
        let mut c = Counts::default();
        for o in &self.outcomes {
            match &o.verdict {
                Verdict::Pass { .. } => c.pass += 1,
                Verdict::Fail { .. } => c.fail += 1,
                Verdict::Quirk { .. } => c.quirk += 1,
                Verdict::Skip { .. } => c.skip += 1,
                Verdict::Error { .. } => c.error += 1,
            }
        }
        c
    }

    /// Only the knobs that were actually observed. Skip/Fail/Error knobs
    /// are excluded.
    pub fn detected_knobs(&self) -> Vec<(&'static str, KnobValue)> {
        self.outcomes
            .iter()
            .filter_map(|o| Some((o.knob?, o.verdict.detected()?.clone())))
            .collect()
    }

    pub fn exit_code(&self) -> u8 {
        if self
            .cleanup
            .as_ref()
            .is_some_and(|c| !c.failures.is_empty())
        {
            return 3;
        }
        if self.counts().fail > 0 || self.counts().error > 0 {
            1
        } else {
            0
        }
    }
}
