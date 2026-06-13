# Self-contained image used for local development, docker-compose, and the CI
# build check. It compiles from source on a glibc toolchain so it matches the
# released image's runtime (distroless/cc). The published release image is built
# separately from the prebuilt binaries via Dockerfile.release.

# Build stage (glibc, matches the distroless/cc runtime below)
FROM rust:1.96-bookworm AS builder

# Cargo features to enable in the build (image supports both backends by default)
ARG FEATURES="sqlite,postgresql"

WORKDIR /app

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy source to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (cached unless Cargo.toml/Cargo.lock change)
RUN cargo build --release --locked --features "${FEATURES}"

# Remove dummy source and build the real binary
RUN rm -rf src
COPY src ./src
RUN cargo build --release --locked --features "${FEATURES}"

# Runtime stage. This self-contained image is built with plain cargo, whose
# binary dynamically links libgcc_s.so.1, so it needs distroless/cc (which ships
# libgcc). The published release image uses base-nossl instead — see
# Dockerfile.release — because the cargo-zigbuild binaries link libgcc
# statically and don't need it. distroless/cc is glibc-based (debian13, latest).
FROM gcr.io/distroless/cc-debian13:nonroot

COPY --from=builder /app/target/release/scim-server /usr/local/bin/scim-server

EXPOSE 3000
WORKDIR /data
STOPSIGNAL SIGTERM

ENTRYPOINT ["scim-server"]
# Zero-config demo by default (in-memory SQLite, unauthenticated), bound to all
# interfaces so a published port is reachable. For real use, mount a config and
# override the command with `--config /data/config.yaml`.
CMD ["--host", "0.0.0.0"]
