//! T11: guards against `scim-server diagnose` regressing the container
//! contract the existing (no-subcommand) CLI already has -- `docker run
//! scim-server -c config.yaml`, `--port`/`--host` overrides, and bare
//! `scim-server` with no arguments at all must all still parse to today's
//! exact serve behavior once `Command::Diagnose` exists alongside them.
//!
//! Pure `clap`-parsing assertions: `Args::try_parse_from` in-process, no
//! server, no subprocess, no I/O.

use clap::Parser;
use scim_server::cli::{Args, Command};

#[test]
fn config_port_host_flags_parse_with_no_subcommand() {
    let args = Args::try_parse_from([
        "scim-server",
        "-c",
        "x.yaml",
        "--port",
        "8080",
        "--host",
        "0.0.0.0",
    ])
    .expect("existing serve flags must still parse");

    assert!(
        args.command.is_none(),
        "no diagnose subcommand was given -- command must stay None"
    );
    assert_eq!(args.config.as_deref(), Some("x.yaml"));
    assert_eq!(args.port, Some(8080));
    assert_eq!(args.host.as_deref(), Some("0.0.0.0"));
}

#[test]
fn host_only_flag_parses_with_no_subcommand() {
    let args = Args::try_parse_from(["scim-server", "--host", "0.0.0.0"])
        .expect("--host alone must still parse");

    assert!(args.command.is_none());
    assert_eq!(args.config, None);
    assert_eq!(args.port, None);
    assert_eq!(args.host.as_deref(), Some("0.0.0.0"));
}

#[test]
fn no_arguments_parses_with_no_subcommand_and_all_defaults() {
    let args = Args::try_parse_from(["scim-server"]).expect("no-args invocation must still parse");

    assert!(args.command.is_none());
    assert_eq!(args.config, None);
    assert_eq!(args.port, None);
    assert_eq!(args.host, None);
}

#[test]
fn diagnose_subcommand_parses_and_does_not_leak_into_serve_fields() {
    let args = Args::try_parse_from([
        "scim-server",
        "diagnose",
        "http://127.0.0.1:3000/scim/v2",
        "--read-only",
    ])
    .expect("diagnose subcommand must parse");

    // The subcommand must not disturb the top-level serve flags' defaults.
    assert_eq!(args.config, None);
    assert_eq!(args.port, None);
    assert_eq!(args.host, None);

    match args.command {
        Some(Command::Diagnose(d)) => {
            assert_eq!(d.base_url, "http://127.0.0.1:3000/scim/v2");
            assert!(d.read_only);
        }
        other => panic!("expected Command::Diagnose, got {other:?}"),
    }
}
