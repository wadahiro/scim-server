# Build stage
FROM rust:1.85-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    postgresql-dev \
    sqlite-dev

# Create app directory
WORKDIR /app

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy source to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (this will be cached if Cargo.toml/Cargo.lock don't change)
RUN cargo build --release --locked

# Remove dummy source
RUN rm -rf src

# Copy real source code
COPY src ./src

# Build release binary with locked dependencies
RUN cargo build --release --locked

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    libpq \
    sqlite-libs \
    && adduser -D -u 1000 scim

# Copy binary from builder
COPY --from=builder /app/target/release/scim-server /usr/local/bin/scim-server

# Create data directory
RUN mkdir -p /data && chown scim:scim /data

# Switch to non-root user
USER scim

# Set working directory
WORKDIR /data

# Expose port
EXPOSE 3000

# Configure signal handling for proper Docker shutdown
STOPSIGNAL SIGTERM

# Set entrypoint
ENTRYPOINT ["scim-server"]

# Default command (can be overridden)
CMD ["--config", "/data/config.yaml"]