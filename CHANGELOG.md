# Changelog

## [0.5.0](https://github.com/wadahiro/scim-server/compare/v0.4.2...v0.5.0) (2026-09-24)


### Features

* **cli:** add --validate to check a configuration without starting the server ([2165bf9](https://github.com/wadahiro/scim-server/commit/2165bf9e6c4497abba9f45dd5ce75b3304e7fd93))


### Bug Fixes

* align scimType error keywords with RFC 7644 Table 9 ([783baee](https://github.com/wadahiro/scim-server/commit/783baee30785a7b5e58080567eb61664a40c2b86))
* **backend:** report scimType "uniqueness" for duplicate values on PUT and PATCH (RFC 7644 §3.12) ([7fa1061](https://github.com/wadahiro/scim-server/commit/7fa10610152d79545cc89201d1a6046c621d8605))
* **config:** avoid overlapping tenant paths in the sample configuration ([24827af](https://github.com/wadahiro/scim-server/commit/24827af9dae8ca23f70b46ed36ae9c9c5d9c335d))
* **config:** merge tenant compatibility overrides field-by-field instead of replacing the block ([a323192](https://github.com/wadahiro/scim-server/commit/a323192fab0f82839fe0cdcf98b35a1f08652331))
* **config:** reject an unknown meta_datetime_format at load time ([d03d625](https://github.com/wadahiro/scim-server/commit/d03d625f10b4f865bbcd15f09761731678e93dd7))
* **config:** validate auth, tenant paths, proxies, and backend settings at load time ([50d1beb](https://github.com/wadahiro/scim-server/commit/50d1beb67a2be36abbe27689066f4879841ae651))
* **config:** validate configuration at load time and add --validate ([f3a1ddb](https://github.com/wadahiro/scim-server/commit/f3a1ddb56cf8147953be43c277f4b6f0b3882a22))
* **deps:** bump bcrypt, h2 and rustls for RUSTSEC advisories ([fac12a5](https://github.com/wadahiro/scim-server/commit/fac12a569f0eec052aedb04909e78b55246bae9d))
* enforce RFC 7643/7644 mutability, required-field, and type conformance ([971cff4](https://github.com/wadahiro/scim-server/commit/971cff49d3707ae8169135e523b063ce2a752a16))
* **error:** stop emitting an undefined scimType on 412 responses ([5aecdc6](https://github.com/wadahiro/scim-server/commit/5aecdc69716ff8cb54220d7bccc2ef8f2256c060))
* **resource:** enforce attribute type checking for addresses, Group.externalId, and Group.members (RFC 7643 §2.3) ([4a692c5](https://github.com/wadahiro/scim-server/commit/4a692c5a2807b27756e4d7d6274122f12bde342e))
* **resource:** honour attributes/excludedAttributes on POST, PUT, and PATCH (RFC 7644 §3.9) ([73b8b9c](https://github.com/wadahiro/scim-server/commit/73b8b9ca750bd0236686e87d266c35e0191ebdb6))
* **resource:** ignore forged readOnly manager.$ref/displayName on write (RFC 7644 §3.3) ([057133e](https://github.com/wadahiro/scim-server/commit/057133e9d7d33b77caf6980bb85223fc8e2d0d90))
* **resource:** reject PATCH modifications to readOnly/immutable attributes (RFC 7644 §3.5.2) ([3f3d4dc](https://github.com/wadahiro/scim-server/commit/3f3d4dcbc95f5b4681be9fa4d6c1ab4590a8a94a))
* **resource:** reject PUT /Groups/{id} when displayName is missing (RFC 7643 §4.2) ([23a0c52](https://github.com/wadahiro/scim-server/commit/23a0c521c036c234eaa1a4736794c8428a888ff9))
* **resource:** stop echoing client-forged User.groups in the POST response (RFC 7644 §3.3) ([13b9687](https://github.com/wadahiro/scim-server/commit/13b9687a8f9c9cf716f40d6212ec4e8670271639))
* **resource:** use Table 9's defined scimType keywords instead of "unsupported" ([f6e4402](https://github.com/wadahiro/scim-server/commit/f6e440255e9a71e52043776f4058fd317175b93a))
* **scim:** advertise User.groups as never returned when the tenant excludes it ([a4e55f0](https://github.com/wadahiro/scim-server/commit/a4e55f0e3c493e14ff452a01b5a857af5284abbf))
* **scim:** always return id, schemas and meta from attribute projection ([0b12e26](https://github.com/wadahiro/scim-server/commit/0b12e261f5055c316d15fb031f241e7f701e8526))
* **scim:** apply tenant compatibility settings to Group PATCH ([9b702ad](https://github.com/wadahiro/scim-server/commit/9b702ad768231b99473aff120c5e1a0612f2b1ab))
* **scim:** build meta.location as an absolute URL on discovery endpoints ([38846a4](https://github.com/wadahiro/scim-server/commit/38846a42b874c749f600e4008cf883d6ee1a5e2d))
* **scim:** correct PATCH noTarget scimType and extension-URN path parsing ([4b81cde](https://github.com/wadahiro/scim-server/commit/4b81cde29ae49fa713a388dd3249cde1e085ba65))
* **scim:** de-duplicate multi-valued attributes; stop echoing client meta on PUT ([4da5bca](https://github.com/wadahiro/scim-server/commit/4da5bca83edf0f91939be8933bbdebbc11d9b676))
* **scim:** enforce the single-primary constraint on addresses ([71a323f](https://github.com/wadahiro/scim-server/commit/71a323f9929992e8a6317f2c8a4351ab182b31fa))
* **scim:** honour "*" in If-Match and If-None-Match per RFC 7232 ([6df1857](https://github.com/wadahiro/scim-server/commit/6df1857e2c2e8797bdb4451cef5255c5448360fc))
* **scim:** implement POST /.search; enforce filter types and Group member types ([6f5b483](https://github.com/wadahiro/scim-server/commit/6f5b483cbac8f2bcb9f6f244becadcf0763454f7))
* **scim:** include schemas in ServiceProviderConfig and advertise etag support ([c3ec229](https://github.com/wadahiro/scim-server/commit/c3ec22958b861c5a6f90552d9cc6ee738a066fdf))
* **scim:** never advertise an empty specUri in ServiceProviderConfig ([e38be6b](https://github.com/wadahiro/scim-server/commit/e38be6b9644393c786cff56af3c949d46c324390))
* **scim:** preserve addresses[].primary instead of silently dropping it ([3865297](https://github.com/wadahiro/scim-server/commit/38652978baaa34d927b1a351c66bbb1af177d990))
* **scim:** rebuild meta from database columns; reject Group PATCH mutability violations ([e54c0de](https://github.com/wadahiro/scim-server/commit/e54c0de6e26d0c0370a9c54bfbc893b38e74c089))
* **scim:** reject a PATCH operation that sets primary on multiple values ([15cf779](https://github.com/wadahiro/scim-server/commit/15cf77945cbb7522b6ba5134ac63a3e63e34ffdf))
* **scim:** reject PATCH remove of a required User attribute with 400 ([87cc23e](https://github.com/wadahiro/scim-server/commit/87cc23e3b3f9627dd1d0daafabd4a783bbdb6e89))
* **scim:** reject relational filter operators on Boolean/Binary attributes ([4435cc3](https://github.com/wadahiro/scim-server/commit/4435cc3ee89f8c46267c2bcfe32830b8f107c066))
* **scim:** resolve attribute names case-insensitively outside filters ([025486e](https://github.com/wadahiro/scim-server/commit/025486ef674ff7731ec335c9eb83b2c7e1b6c28d))
* **scim:** resolve core-schema-qualified PATCH paths to the plain attribute ([e6e3bd5](https://github.com/wadahiro/scim-server/commit/e6e3bd55003f0f0d8d3c93e8c2ed23c12fe4ef03))
* **scim:** return a SCIM error for unmatched routes; unify router construction ([fcf68d1](https://github.com/wadahiro/scim-server/commit/fcf68d12171f2b793d0a54b13429cf07a948c775))
* **scim:** return SCIM Error resources for every error response ([aea7ef3](https://github.com/wadahiro/scim-server/commit/aea7ef312214b4a75bc84a5afe2644ee9c530563))
* **scim:** RFC 7644/7232 conformance fixes and a startable sample config ([95bd538](https://github.com/wadahiro/scim-server/commit/95bd538662f61da6bc7f25bad8f50f1eccb5b5e5))
* **scim:** schema/resource-type discovery conformance and shared error types ([1cc8168](https://github.com/wadahiro/scim-server/commit/1cc8168cc4eb1f5c5a2c5900d3034838f2aa4ec7))
* **scim:** SCIM 2.0 specification conformance fixes ([24f5bf0](https://github.com/wadahiro/scim-server/commit/24f5bf01b8aa24c133c7e46a9eda0154a88cb890))
* **scim:** serve SCIM responses as application/scim+json ([48e40f9](https://github.com/wadahiro/scim-server/commit/48e40f987f58ace38e89a8ec8e4fe53fffd655a9))

## [0.4.2](https://github.com/wadahiro/scim-server/compare/v0.4.1...v0.4.2) (2026-06-13)


### Bug Fixes

* **sqlite:** create the database file automatically — a file URL like `sqlite:/data/scim.db` no longer needs `?mode=rwc` ([#65](https://github.com/wadahiro/scim-server/pull/65))

### Build System

* Build the published container image from the exact released binary (single source of truth) via one multi-target Dockerfile, and slim the runtime to distroless/base-nossl (~12 MB smaller) ([#64](https://github.com/wadahiro/scim-server/pull/64))

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
