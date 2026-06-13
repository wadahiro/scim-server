# Changelog

## [0.4.1](https://github.com/wadahiro/scim-server/compare/v0.4.0...v0.4.1) (2026-06-13)

### Bug Fixes

* Make the container image usable out of the box — `docker run -p 3000:3000 IMAGE` now starts a zero-config demo bound to `0.0.0.0` instead of failing without a mounted config ([#61](https://github.com/wadahiro/scim-server/pull/61))

### Build System

* The published container image now contains the **exact** binary published as a release asset (byte-identical, single source of truth) ([#61](https://github.com/wadahiro/scim-server/pull/61))
* Build the Linux binaries with cargo-zigbuild pinned to a glibc 2.28 floor, so one binary runs on every currently-supported distro (RHEL 8/9, Debian 10–13, Ubuntu 20.04+) and in the container ([#61](https://github.com/wadahiro/scim-server/pull/61))
* Switch the runtime image to distroless/cc-debian13 (glibc) ([#61](https://github.com/wadahiro/scim-server/pull/61))

## [0.4.0](https://github.com/wadahiro/scim-server/compare/v0.3.0...v0.4.0) (2026-06-13)

### Features

* Publish a multi-arch container image (`linux/amd64`, `linux/arm64`) to GitHub Container Registry (`ghcr.io`) on release ([#49](https://github.com/wadahiro/scim-server/pull/49))
* Provide release binaries for macOS (Apple Silicon and Intel) and Windows (x64 and ARM64) in addition to Linux x64/ARM64 ([#49](https://github.com/wadahiro/scim-server/pull/49))
* Build both the binaries and the container image with SQLite **and** PostgreSQL backends enabled ([#49](https://github.com/wadahiro/scim-server/pull/49))

### Bug Fixes

* Report the correct version from `--version` (it had been stuck at a stale `0.2.0`)

### Dependencies

* Bump scim_proto, clap, tokio, regex, serde_json, uuid, async-trait, tracing-subscriber, bcrypt, chrono-tz, and testcontainers; resolve RUSTSEC advisories (rustls-webpki, time, bytes, tokio-tar) and drop the direct `rand` dependency ([d4f878a](https://github.com/wadahiro/scim-server/commit/d4f878ab0f4230a920a2321ecbae625af7f64fca))

### Build System

* Upgrade the Docker runtime image to Alpine 3.24 and modernize the Dockerfile (rust 1.96-alpine builder) ([#59](https://github.com/wadahiro/scim-server/pull/59), [#49](https://github.com/wadahiro/scim-server/pull/49))
* Automate releases with release-please and harden the CI/release workflows (SHA-pinned actions, least-privilege tokens) ([#51](https://github.com/wadahiro/scim-server/pull/51))
