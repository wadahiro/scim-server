//! `scim-server diagnose` argument parsing: the clap [`DiagnoseArgs`] shape
//! and [`into_options`], which validates and normalizes it into a
//! [`DiagOptions`] the rest of `diag::*` consumes.

use std::path::PathBuf;

use crate::diag::DiagError;

#[derive(clap::Args, Debug, Clone)]
pub struct DiagnoseArgs {
    /// Base URL of the SCIM service provider, e.g. https://api.example.com/scim/v2
    pub base_url: String,

    // ---- authentication ----
    /// Authentication scheme
    #[arg(long, value_enum, default_value_t = AuthKind::Bearer)]
    pub auth: AuthKind,
    /// Token for --auth bearer ("Bearer <t>") or --auth token ("token <t>")
    #[arg(long, env = "SCIM_DIAG_TOKEN", hide_env_values = true)]
    pub token: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long, env = "SCIM_DIAG_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,
    /// Extra request header, repeatable: --header "X-Tenant: acme"
    #[arg(long = "header", value_name = "NAME: VALUE")]
    pub headers: Vec<String>,

    // ---- TLS ----
    #[arg(long = "ca-cert", value_name = "PEM_FILE")]
    pub ca_certs: Vec<PathBuf>,
    /// Also trust the OS certificate store (default: built-in Mozilla roots only)
    #[arg(long)]
    pub native_roots: bool,
    /// DANGER: disable TLS certificate and hostname verification
    #[arg(long = "insecure", alias = "tls-no-verify")]
    pub insecure: bool,

    // ---- write mode ----
    #[arg(long)]
    pub read_only: bool,
    #[arg(long)]
    pub dry_run: bool,
    /// Prefix for created resources. Default: scimdiag-<8 hex>
    #[arg(long)]
    pub prefix: Option<String>,
    // NOTE for the exact wording below: clap's help renderer treats the
    // literal 3-character sequence "{n}" (no space) as a forced newline
    // (`StyledStr::replace_newline_var`, `clap_builder::builder::styled_str`)
    // and silently eats it from `--help` output — so the per-probe counter
    // placeholder is spelled with a space here purely for display. The real
    // template value the user types has no space: `{n}`.
    /// REQUIRED for write probes. Must contain the literal tokens {prefix}
    /// and { n } (no space in the real value). Recommended form:
    /// {prefix}+{ n }@corp.example.com
    #[arg(long, value_name = "TEMPLATE")]
    pub probe_email: Option<String>,
    #[arg(long)]
    pub allow_consumer_email: bool,
    /// Multi-valued attribute exercised by the PATCH-clearing probes
    #[arg(long, value_enum, default_value_t = ProbeAttr::PhoneNumbers)]
    pub probe_attribute: ProbeAttr,
    /// Delete leftovers from a previous run with this prefix, then exit
    #[arg(long, requires = "prefix")]
    pub cleanup_only: bool,

    // ---- selection ----
    #[arg(long = "only")]
    pub only: Vec<String>, // check id or tier1..tier4
    #[arg(long = "skip")]
    pub skip: Vec<String>,

    // ---- output ----
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub emit_config_snippet: bool,
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    #[arg(short, long)]
    pub quiet: bool,

    // ---- timing ----
    #[arg(long, default_value_t = 30)]
    pub timeout: u64,
    #[arg(long, default_value_t = 300)]
    pub deadline: u64,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    Bearer,
    Token,
    Basic,
    None,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeAttr {
    PhoneNumbers,
    Emails,
}

impl ProbeAttr {
    /// The SCIM attribute name this probe targets.
    pub fn attr_name(&self) -> &'static str {
        match self {
            ProbeAttr::PhoneNumbers => "phoneNumbers",
            ProbeAttr::Emails => "emails",
        }
    }
}

impl std::fmt::Display for ProbeAttr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.attr_name())
    }
}

/// Output format.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Markdown,
}

/// Normalized, validated options that the rest of `diag::*` consumes.
///
/// Not given verbatim by the spec (only referenced via field accesses on
/// `opts.*` and the `DiagOptions` name); this shape is derived from those
/// usages.
#[derive(Debug, Clone)]
pub struct DiagOptions {
    pub base_url: String,
    pub auth: AuthKind,
    pub token: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub headers: Vec<(String, String)>,

    pub ca_certs: Vec<PathBuf>,
    pub native_roots: bool,
    pub insecure: bool,

    pub read_only: bool,
    pub dry_run: bool,
    pub prefix: String,
    /// Validated in PR3 (`EmailTemplate::parse`); PR2 only threads the raw
    /// value through.
    pub probe_email: Option<String>,
    pub allow_consumer_email: bool,
    pub probe_attribute: ProbeAttr,
    pub cleanup_only: bool,

    pub only: Vec<String>,
    pub skip: Vec<String>,

    pub format: Format,
    pub output: Option<PathBuf>,
    pub emit_config_snippet: bool,
    pub verbose: u8,
    pub quiet: bool,

    pub timeout: u64,
    pub deadline: u64,
}

pub fn into_options(args: DiagnoseArgs) -> Result<DiagOptions, DiagError> {
    let parsed_url = url::Url::parse(&args.base_url)
        .map_err(|e| DiagError::BadUrl(format!("{}: {e}", args.base_url)))?;
    if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
        return Err(DiagError::BadUrl(format!(
            "{} is not an absolute http(s) URL",
            args.base_url
        )));
    }

    match args.auth {
        AuthKind::Bearer | AuthKind::Token if args.token.is_none() => {
            return Err(DiagError::BadArgs(format!(
                "--auth {:?} requires --token (or $SCIM_DIAG_TOKEN)",
                args.auth
            )));
        }
        AuthKind::Basic if args.username.is_none() || args.password.is_none() => {
            return Err(DiagError::BadArgs(
                "--auth basic requires --username and --password (or $SCIM_DIAG_PASSWORD)".into(),
            ));
        }
        _ => {}
    }

    let mut headers = Vec::with_capacity(args.headers.len());
    for h in &args.headers {
        let (name, value) = h.split_once(':').ok_or_else(|| {
            DiagError::BadArgs(format!("--header {h:?} is not in \"Name: Value\" form"))
        })?;
        let (name, value) = (name.trim(), value.trim());
        if name.is_empty() {
            return Err(DiagError::BadArgs(format!(
                "--header {h:?} is not in \"Name: Value\" form"
            )));
        }
        headers.push((name.to_string(), value.to_string()));
    }

    // `--probe-email` validation. Missing is fine (write probes degrade to
    // Skip at runtime with a specific reason, §5.8) — only a *present but
    // malformed/blocked* template is a hard `BadArgs` here.
    if let Some(template_str) = &args.probe_email {
        let template = crate::diag::email::EmailTemplate::parse(template_str)?;
        template.check_domain(args.allow_consumer_email)?;
    }

    let known_ids = crate::diag::checks::catalog_ids();
    for sel in args.only.iter().chain(args.skip.iter()) {
        if !is_known_selector(sel, &known_ids) {
            return Err(DiagError::BadArgs(format!(
                "{sel:?} is not a known check id or tier (tier1..tier4){}",
                suggest(sel, &known_ids)
            )));
        }
    }

    let prefix = args.prefix.clone().unwrap_or_else(default_prefix);

    Ok(DiagOptions {
        base_url: args.base_url,
        auth: args.auth,
        token: args.token,
        username: args.username,
        password: args.password,
        headers,
        ca_certs: args.ca_certs,
        native_roots: args.native_roots,
        insecure: args.insecure,
        read_only: args.read_only,
        dry_run: args.dry_run,
        prefix,
        probe_email: args.probe_email,
        allow_consumer_email: args.allow_consumer_email,
        probe_attribute: args.probe_attribute,
        cleanup_only: args.cleanup_only,
        only: args.only,
        skip: args.skip,
        format: args.format,
        output: args.output,
        emit_config_snippet: args.emit_config_snippet,
        verbose: args.verbose,
        quiet: args.quiet,
        timeout: args.timeout,
        deadline: args.deadline,
    })
}

fn is_known_selector(sel: &str, ids: &[&'static str]) -> bool {
    matches!(sel, "tier1" | "tier2" | "tier3" | "tier4") || ids.contains(&sel)
}

fn suggest(sel: &str, ids: &[&'static str]) -> String {
    let mut candidates: Vec<&'static str> = ids.to_vec();
    candidates.extend(["tier1", "tier2", "tier3", "tier4"]);
    candidates
        .into_iter()
        .map(|id| (levenshtein(sel, id), id))
        .min_by_key(|(d, _)| *d)
        .filter(|(d, _)| *d <= 4)
        .map(|(_, id)| format!("; did you mean {id:?}?"))
        .unwrap_or_default()
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut prev = row[0];
        row[0] = i;
        for j in 1..=b.len() {
            let tmp = row[j];
            row[j] = if a[i - 1] == b[j - 1] {
                prev
            } else {
                1 + prev.min(row[j]).min(row[j - 1])
            };
            prev = tmp;
        }
    }
    row[b.len()]
}

fn default_prefix() -> String {
    let id = uuid::Uuid::new_v4();
    let b = id.as_bytes();
    format!("scimdiag-{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3])
}
