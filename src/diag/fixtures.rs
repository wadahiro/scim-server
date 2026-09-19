//! Fixture bookkeeping and provisioning for write-mode probes.
//!
//! Creation order is U1 (primary) -> U2 (delete-verification) -> U3
//! (If-Match delete verification, PR4) -> G1 (`members: [{value: U1.id}]`)
//! -> G2 (a group whose create request omits the `members` key entirely,
//! not `[]` — so a server that just echoes the request body back can't be
//! mistaken for one that actually tracks empty membership).
//!
//! `--probe-email` is the only address-consuming input: it is expanded
//! once per user slot (`{prefix}+{n}@...`) and used for both `userName`
//! and `emails[0].value`. Every other write-mode probe that needs a
//! multi-valued attribute to mutate uses `--probe-attribute` (default
//! `phoneNumbers`) instead, specifically so it never manufactures another
//! address (see `src/diag/checks/compat.rs`).
//!
//! `POST /Users` bodies never include `password` — an SSO-only SaaS that
//! rejects a `password` field would otherwise degrade the entire write
//! tier for a reason unrelated to what's being diagnosed.

use std::sync::{Arc, Mutex};

use reqwest::Method;
use serde_json::{json, Value};

use crate::diag::cli::DiagOptions;
use crate::diag::client::ScimClient;
use crate::diag::ctx::{CreateProbe, DiagContext};
use crate::diag::email::EmailTemplate;
use crate::diag::model::{CleanupReport, Report, ReportHeader};
use crate::diag::DiagError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    User,
    Group,
}

impl ResourceKind {
    fn word(self) -> &'static str {
        match self {
            ResourceKind::User => "User",
            ResourceKind::Group => "Group",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Fixture {
    pub id: String,
    /// User only (= the expanded probe email).
    pub user_name: String,
    /// Group only.
    pub display_name: String,
    /// User only.
    pub email: String,
}

#[derive(Debug, Default)]
pub struct FixtureSet {
    pub prefix: String,
    /// Pushed the moment a 201 is received (before assertions run), so
    /// cleanup only ever needs to look here.
    pub created: Vec<(ResourceKind, String, String)>, // (kind, id, label)
    pub u1: Option<Fixture>,
    pub u2: Option<Fixture>,
    pub u3: Option<Fixture>,
    pub g1: Option<Fixture>,
    pub g2: Option<Fixture>,
    /// Set by `provision()` if fixture creation failed partway through (or
    /// couldn't start — e.g. no `--probe-email`). `run()` reads this back
    /// out through the `Arc` (the `DiagContext` that set it is moved into
    /// a spawned task and never observed directly) to render the report
    /// header's "WRITE TIER DEGRADED" warning. Never set for `--read-only`
    /// or `--dry-run` — those are requested modes, not degradations.
    pub degraded: Option<String>,
}

impl FixtureSet {
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
            ..Default::default()
        }
    }
}

fn user_body(prefix: &str, n: u8, email: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": email,
        "externalId": format!("{prefix}-u{n}"),
        "name": { "givenName": "Scim", "familyName": "Diag" },
        "displayName": format!("{prefix} probe user {n}"),
        "emails": [{ "value": email, "type": "work", "primary": true }],
        "active": true
    })
}

/// Creates U1..G2 in order, unless writes are already disabled (in which
/// case this is a no-op — every `Need::Writes` check will Skip on its own).
/// Never panics or aborts the run on failure: sets `ctx.writes_disabled`
/// (and mirrors it onto the shared `FixtureSet` as `degraded`) and returns,
/// leaving whatever fixtures *did* get created registered for cleanup.
pub async fn provision(ctx: &mut DiagContext) {
    if ctx.writes_disabled.is_some() {
        return;
    }

    let template = match ctx.opts.probe_email.as_deref() {
        Some(t) => match EmailTemplate::parse(t) {
            Ok(t) => t,
            Err(e) => {
                degrade(ctx, e.to_string());
                return;
            }
        },
        None => {
            degrade(
                ctx,
                "--probe-email not supplied; write probes require an explicit, operator-chosen address"
                    .to_string(),
            );
            return;
        }
    };

    if ctx.opts.dry_run {
        provision_dry_run(ctx, &template).await;
        return;
    }

    print_write_banner(&ctx.opts, &template);

    if let Err(reason) = provision_real(ctx, &template).await {
        degrade(ctx, reason);
    }
}

fn degrade(ctx: &mut DiagContext, reason: String) {
    ctx.writes_disabled = Some(reason.clone());
    ctx.fixtures.lock().unwrap().degraded = Some(reason);
}

fn print_write_banner(opts: &DiagOptions, template: &EmailTemplate) {
    let e1 = template.expand(&opts.prefix, 1);
    let e2 = template.expand(&opts.prefix, 2);
    let e3 = template.expand(&opts.prefix, 3);
    eprintln!(
        "! WRITE MODE. About to create the following resources on {}",
        opts.base_url
    );
    eprintln!("!   users : {e1}   (userName)");
    eprintln!("!           {e2}");
    eprintln!("!           {e3}");
    eprintln!(
        "!   groups: \"{p} probe group 1\", \"{p} probe group 2\"",
        p = opts.prefix
    );
    eprintln!(
        "! User creation will be attempted 4 times (the duplicate-username probe re-POSTs the +1 address)."
    );
    eprintln!("! The target server may send invitation/notification email to these addresses.");
    eprintln!("! To inspect without writing, use --read-only; to see every request that would be sent without sending it, use --dry-run.");
}

async fn provision_real(ctx: &mut DiagContext, template: &EmailTemplate) -> Result<(), String> {
    // ---- U1: the only creation that negotiates Content-Type ----
    let email1 = template.expand(&ctx.opts.prefix, 1);
    let body1 = user_body(&ctx.opts.prefix, 1, &email1);

    ctx.client.content_type = "application/scim+json";
    let mut resp = ctx
        .client
        .request(Method::POST, "/Users", &[], Some(&body1), &[])
        .await
        .map_err(|e| format!("POST /Users failed: {e}"))?;

    let mut retried = false;
    if resp.status == 415 {
        retried = true;
        ctx.client.content_type = "application/json";
        resp = ctx
            .client
            .request(Method::POST, "/Users", &[], Some(&body1), &[])
            .await
            .map_err(|e| format!("POST /Users failed: {e}"))?;
    }
    ctx.content_type = ctx.client.content_type;

    let status = resp.status;
    let detail = resp.detail();
    let location = resp.header("location").map(str::to_string);
    let id = resp.ptr("/id").and_then(Value::as_str).map(str::to_string);
    let resource_type = resp
        .ptr("/meta/resourceType")
        .and_then(Value::as_str)
        .map(str::to_string);

    ctx.state.create_u1 = Some(CreateProbe {
        status,
        retried_with_plain_json: retried,
        location: location.clone(),
        id: id.clone(),
        resource_type,
        detail: detail.clone(),
    });

    if status != 201 || id.is_none() {
        let mut reason = format!("POST /Users returned {status} ({detail}); write probes skipped");
        if status == 400 {
            reason.push_str(
                "; a 400 on create often means the target rejects the --probe-email domain; try a verified domain",
            );
        }
        return Err(reason);
    }
    let id = id.unwrap();
    {
        let mut fx = ctx.fixtures.lock().unwrap();
        fx.created
            .push((ResourceKind::User, id.clone(), email1.clone()));
        fx.u1 = Some(Fixture {
            id: id.clone(),
            user_name: email1.clone(),
            display_name: String::new(),
            email: email1,
        });
    }

    // ---- U2, U3: plain creates, no negotiation ----
    create_plain_user(ctx, template, 2, Slot::U2).await?;
    create_plain_user(ctx, template, 3, Slot::U3).await?;

    // ---- G1: members: [{value: U1.id}] ----
    let u1_id = ctx.fixtures.lock().unwrap().u1.as_ref().unwrap().id.clone();
    create_group(ctx, 1, Some(&u1_id)).await?;

    // ---- G2: no `members` key in the request at all ----
    create_group(ctx, 2, None).await?;

    Ok(())
}

enum Slot {
    U2,
    U3,
}

async fn create_plain_user(
    ctx: &mut DiagContext,
    template: &EmailTemplate,
    n: u8,
    slot: Slot,
) -> Result<(), String> {
    let email = template.expand(&ctx.opts.prefix, n);
    let body = user_body(&ctx.opts.prefix, n, &email);
    let resp = ctx
        .client
        .request(Method::POST, "/Users", &[], Some(&body), &[])
        .await
        .map_err(|e| format!("POST /Users (u{n}) failed: {e}"))?;
    if resp.status != 201 {
        return Err(format!(
            "POST /Users returned {} ({}); write probes skipped",
            resp.status,
            resp.detail()
        ));
    }
    let id = resp
        .ptr("/id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("POST /Users (u{n}) returned 201 with no id"))?;
    let mut fx = ctx.fixtures.lock().unwrap();
    fx.created
        .push((ResourceKind::User, id.clone(), email.clone()));
    let fixture = Fixture {
        id,
        user_name: email.clone(),
        display_name: String::new(),
        email,
    };
    match slot {
        Slot::U2 => fx.u2 = Some(fixture),
        Slot::U3 => fx.u3 = Some(fixture),
    }
    Ok(())
}

async fn create_group(
    ctx: &mut DiagContext,
    n: u8,
    member_user_id: Option<&str>,
) -> Result<(), String> {
    let display_name = format!("{} probe group {n}", ctx.opts.prefix);
    let mut body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": display_name,
    });
    if let Some(uid) = member_user_id {
        body["members"] = json!([{ "value": uid }]);
    }
    let resp = ctx
        .client
        .request(Method::POST, "/Groups", &[], Some(&body), &[])
        .await
        .map_err(|e| format!("POST /Groups failed: {e}"))?;
    if resp.status != 201 {
        return Err(format!(
            "POST /Groups returned {} ({}); write probes skipped",
            resp.status,
            resp.detail()
        ));
    }
    let id = resp
        .ptr("/id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "POST /Groups returned 201 with no id".to_string())?;
    let mut fx = ctx.fixtures.lock().unwrap();
    fx.created
        .push((ResourceKind::Group, id.clone(), display_name.clone()));
    let fixture = Fixture {
        id,
        user_name: String::new(),
        display_name: display_name.clone(),
        email: String::new(),
    };
    if n == 1 {
        fx.g1 = Some(fixture);
    } else {
        fx.g2 = Some(fixture);
    }
    Ok(())
}

/// Under `--dry-run`, `ctx.client` never actually sends anything (it's
/// constructed with `dry_run: true`, so every `request()` call below just
/// builds-and-logs) — but responses therefore always come back with
/// `status: 0`, which would look like total failure to `provision_real`'s
/// status checks. So this is a separate, simpler path: send (don't-send)
/// every fixture-creation request for the transcript, and unconditionally
/// fill every fixture slot with a placeholder id (`{U1}`..`{G2}`) so later
/// checks can build (and print) id-dependent requests against them. Nothing
/// is pushed to `created`: dry-run creates nothing, so cleanup has nothing
/// to do.
async fn provision_dry_run(ctx: &mut DiagContext, template: &EmailTemplate) {
    let email1 = template.expand(&ctx.opts.prefix, 1);
    let body1 = user_body(&ctx.opts.prefix, 1, &email1);
    let _ = ctx
        .client
        .request(Method::POST, "/Users", &[], Some(&body1), &[])
        .await;
    set_fixture(ctx, Placeholder::U1, email1.clone(), String::new(), email1);

    let email2 = template.expand(&ctx.opts.prefix, 2);
    let body2 = user_body(&ctx.opts.prefix, 2, &email2);
    let _ = ctx
        .client
        .request(Method::POST, "/Users", &[], Some(&body2), &[])
        .await;
    set_fixture(ctx, Placeholder::U2, email2.clone(), String::new(), email2);

    let email3 = template.expand(&ctx.opts.prefix, 3);
    let body3 = user_body(&ctx.opts.prefix, 3, &email3);
    let _ = ctx
        .client
        .request(Method::POST, "/Users", &[], Some(&body3), &[])
        .await;
    set_fixture(ctx, Placeholder::U3, email3.clone(), String::new(), email3);

    let g1name = format!("{} probe group 1", ctx.opts.prefix);
    let g1body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": g1name,
        "members": [{ "value": "{U1}" }],
    });
    let _ = ctx
        .client
        .request(Method::POST, "/Groups", &[], Some(&g1body), &[])
        .await;
    set_fixture(ctx, Placeholder::G1, String::new(), g1name, String::new());

    let g2name = format!("{} probe group 2", ctx.opts.prefix);
    let g2body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": g2name,
    });
    let _ = ctx
        .client
        .request(Method::POST, "/Groups", &[], Some(&g2body), &[])
        .await;
    set_fixture(ctx, Placeholder::G2, String::new(), g2name, String::new());
}

enum Placeholder {
    U1,
    U2,
    U3,
    G1,
    G2,
}

fn set_fixture(
    ctx: &mut DiagContext,
    slot: Placeholder,
    user_name: String,
    display_name: String,
    email: String,
) {
    let id = match slot {
        Placeholder::U1 => "{U1}",
        Placeholder::U2 => "{U2}",
        Placeholder::U3 => "{U3}",
        Placeholder::G1 => "{G1}",
        Placeholder::G2 => "{G2}",
    }
    .to_string();
    let fixture = Fixture {
        id,
        user_name,
        display_name,
        email,
    };
    let mut fx = ctx.fixtures.lock().unwrap();
    match slot {
        Placeholder::U1 => fx.u1 = Some(fixture),
        Placeholder::U2 => fx.u2 = Some(fixture),
        Placeholder::U3 => fx.u3 = Some(fixture),
        Placeholder::G1 => fx.g1 = Some(fixture),
        Placeholder::G2 => fx.g2 = Some(fixture),
    }
}

/// The `!! CLEANUP INCOMPLETE ...` stderr block (§5.8), shared by both
/// places a cleanup failure needs to be surfaced: the ordinary completion
/// path (`cli.rs::diag_main`, `report.cleanup.failures` non-empty even
/// though a `Report` was built) and the interrupted/panicked path
/// (`DiagError::CleanupIncomplete`'s `Display`, where no `Report` exists at
/// all).
pub fn cleanup_incomplete_block(report: &CleanupReport, base_url: &str, prefix: &str) -> String {
    let mut out = format!(
        "!! CLEANUP INCOMPLETE. {} resource(s) remain on {base_url}:\n",
        report.failures.len()
    );
    for line in &report.failures {
        out.push_str(&format!("!!   {line}\n"));
    }
    out.push_str(&format!(
        "!! find them:  filter=userName sw \"{prefix}\" (or displayName sw \"{prefix}\")\n"
    ));
    out.push_str(&format!(
        "!! re-run:     scim-server diagnose {base_url} --cleanup-only --prefix {prefix}"
    ));
    out
}

async fn delete_one(client: &mut ScimClient, kind: ResourceKind, id: &str) -> Result<(), String> {
    let path = match kind {
        ResourceKind::User => format!("/Users/{id}"),
        ResourceKind::Group => format!("/Groups/{id}"),
    };
    match client.request(Method::DELETE, &path, &[], None, &[]).await {
        // 404 counts as success: the resource is already gone, which is
        // the desired end state either way.
        Ok(resp) if resp.status == 204 || resp.status == 200 || resp.status == 404 => Ok(()),
        Ok(resp) => Err(resp.status.to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// Deletes everything `FixtureSet::created` knows about: groups before
/// users (a straight reverse of `created` would delete e.g. a 201 that
/// `rfc.duplicate_username` registered — a *user*, appended after G1/G2 —
/// before the groups, if it weren't partitioned first), each partition in
/// reverse creation order. Its own short (10s per request) timeout client,
/// independent of `--timeout`, so a hung cleanup can't run indefinitely.
pub async fn cleanup(fixtures: &Arc<Mutex<FixtureSet>>, opts: &DiagOptions) -> CleanupReport {
    let created = { fixtures.lock().unwrap().created.clone() };
    if created.is_empty() {
        return CleanupReport::default();
    }

    let mut cleanup_opts = opts.clone();
    cleanup_opts.timeout = 10;
    let mut client = match ScimClient::new(&cleanup_opts) {
        Ok(c) => c,
        Err(e) => {
            return CleanupReport {
                attempted: created.len(),
                deleted: 0,
                failures: created
                    .iter()
                    .map(|(k, id, label)| {
                        format!(
                            "{} {id} {label:?} (cleanup client setup failed: {e})",
                            k.word()
                        )
                    })
                    .collect(),
            };
        }
    };

    let (mut groups, mut users): (Vec<_>, Vec<_>) = created
        .into_iter()
        .partition(|(k, _, _)| *k == ResourceKind::Group);
    groups.reverse();
    users.reverse();

    let mut deleted = 0;
    let mut failures = Vec::new();
    for (kind, id, label) in groups.into_iter().chain(users) {
        match delete_one(&mut client, kind, &id).await {
            Ok(()) => deleted += 1,
            Err(status) => failures.push(format!(
                "{} {id} {label:?} (DELETE -> {status})",
                kind.word()
            )),
        }
    }

    CleanupReport {
        attempted: deleted + failures.len(),
        deleted,
        failures,
    }
}

/// `--cleanup-only`: rediscovers leftovers from a previous run by
/// `userName sw "{prefix}"` / `displayName sw "{prefix}"` and deletes them
/// (same groups-before-users, reverse-within-kind, 404-is-success rules as
/// `cleanup()`). Runs no checks at all.
pub async fn run_cleanup_only(opts: &DiagOptions) -> Result<Report, DiagError> {
    let started = std::time::Instant::now();
    let started_at = chrono::Utc::now();

    let mut cleanup_opts = opts.clone();
    cleanup_opts.timeout = 10;
    let mut client = ScimClient::new(&cleanup_opts)?;

    let mut groups = Vec::new();
    let gq = format!("displayName sw \"{}\"", opts.prefix);
    let gresp = client
        .get_query("/Groups", &[("filter", gq.as_str())])
        .await?;
    if let Some(items) = gresp.ptr("/Resources").and_then(Value::as_array) {
        for it in items {
            if let Some(id) = it.get("id").and_then(Value::as_str) {
                let label = it
                    .get("displayName")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                groups.push((ResourceKind::Group, id.to_string(), label));
            }
        }
    }

    let mut users = Vec::new();
    let uq = format!("userName sw \"{}\"", opts.prefix);
    let uresp = client
        .get_query("/Users", &[("filter", uq.as_str())])
        .await?;
    if let Some(items) = uresp.ptr("/Resources").and_then(Value::as_array) {
        for it in items {
            if let Some(id) = it.get("id").and_then(Value::as_str) {
                let label = it
                    .get("userName")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                users.push((ResourceKind::User, id.to_string(), label));
            }
        }
    }

    let mut deleted = 0;
    let mut failures = Vec::new();
    for (kind, id, label) in groups.into_iter().chain(users) {
        match delete_one(&mut client, kind, &id).await {
            Ok(()) => deleted += 1,
            Err(status) => failures.push(format!(
                "{} {id} {label:?} (DELETE -> {status})",
                kind.word()
            )),
        }
    }

    let header = ReportHeader {
        target: opts.base_url.clone(),
        auth: crate::diag::describe_auth(opts),
        tls: crate::diag::describe_tls(opts),
        mode: "cleanup-only".to_string(),
        prefix: opts.prefix.clone(),
        probe_email: opts.probe_email.clone(),
        probe_attribute: opts.probe_attribute.attr_name().to_string(),
        started: started_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        duration_ms: started.elapsed().as_millis(),
        tool_version: env!("CARGO_PKG_VERSION"),
        verbose: opts.verbose,
        warnings: vec![],
    };

    Ok(Report {
        header,
        outcomes: vec![],
        cleanup: Some(CleanupReport {
            attempted: deleted + failures.len(),
            deleted,
            failures,
        }),
    })
}
