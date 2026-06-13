# One image, two build paths that share a single runtime definition.
#
#   * "source"   (default) — compiles from source. Used for local development,
#     docker-compose, and the CI build check. Plain cargo binaries dynamically
#     link libgcc_s.so.1, so this path uses the distroless/cc base (which ships
#     libgcc).
#   * "prebuilt"           — COPYs a prebuilt release binary, no compilation, so
#     the published image is byte-identical to the released binary (single
#     source of truth). Used by the release pipeline:
#       --target prebuilt \
#       --build-arg RUNTIME=gcr.io/distroless/base-nossl-debian13:nonroot
#     cargo-zigbuild links libgcc statically, so the smaller base-nossl works.
#
# buildkit only builds the stages in the requested target's graph, so the
# release build skips the Rust compile, and `docker build .` never evaluates
# the prebuilt stage's `COPY bin/`.

ARG RUNTIME=gcr.io/distroless/cc-debian13:nonroot

# --- build stage (used by the "source" path) ---
FROM rust:1.96-bookworm AS builder
ARG FEATURES="sqlite,postgresql"
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --locked --features "${FEATURES}"
RUN rm -rf src
COPY src ./src
RUN cargo build --release --locked --features "${FEATURES}"

# --- shared runtime definition (settings declared once, here) ---
FROM ${RUNTIME} AS runtime
EXPOSE 3000
WORKDIR /data
STOPSIGNAL SIGTERM
ENTRYPOINT ["scim-server"]
# Zero-config demo by default (in-memory SQLite, unauthenticated), bound to all
# interfaces so a published port is reachable. For real use, mount a config and
# override the command with `--config /data/config.yaml`.
CMD ["--host", "0.0.0.0"]

# --- release path: package the exact prebuilt binary (no compilation) ---
FROM runtime AS prebuilt
ARG TARGETARCH
COPY bin/scim-server-${TARGETARCH} /usr/local/bin/scim-server

# --- default path: compile from source ---
FROM runtime AS source
COPY --from=builder /app/target/release/scim-server /usr/local/bin/scim-server
