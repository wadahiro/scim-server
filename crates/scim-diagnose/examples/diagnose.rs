//! Minimal ad hoc CLI for exercising `scim_diagnose::run` end to end against
//! a live target -- this branch (`feat/scim-diagnose-axes`) doesn't carry a
//! real `diagnose` subcommand (that belongs to a separate, not-yet-merged
//! piece of work; see the older `feat/scim-diagnose` branch for a prior,
//! now-superseded attempt at one). This example exists only so the new
//! nine-axis family's behaviour can be pasted from a real run, per the
//! brief this crate's axes were added under; it takes no auth flags because
//! every use so far is against a `--allow-writes`-eligible, unauthenticated
//! local reference server.
//!
//! Usage: `cargo run -p scim-diagnose --example diagnose -- <base_url> [--allow-writes]`

use scim_diagnose::{render_profile, Auth, DiagOptions};

// `current_thread`: scim-diagnose's `tokio` dependency enables only `rt,
// macros, time` (no `rt-multi-thread`), the same flavor `#[tokio::test]`
// already uses throughout this crate's integration tests -- the default
// `#[tokio::main]` flavor needs a feature this crate deliberately doesn't
// pull in for a library.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let base_url = args
        .next()
        .unwrap_or_else(|| panic!("usage: diagnose <base_url> [--allow-writes]"));
    let allow_writes = args.next().as_deref() == Some("--allow-writes");

    let opts = DiagOptions {
        base_url,
        auth: Auth::None,
        headers: Vec::new(),
        insecure: false,
        ca_certs: Vec::new(),
        native_roots: false,
        timeout_secs: 30,
        allow_writes,
    };

    let profile = scim_diagnose::run(&opts)
        .await
        .unwrap_or_else(|e| panic!("diagnose run failed: {e}"));
    print!("{}", render_profile(&profile));
}
