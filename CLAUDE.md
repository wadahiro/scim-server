# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Essential Commands

### Build and Run
```bash
cargo build --release               # Build optimized binary
cargo run                          # Run with config.yaml or defaults
cargo run -- --help               # Show command line options
cargo run -- -c /path/to/config.yaml  # Run with custom config file
cargo run -- --port 8080          # Override port from config
cargo run -- --host 0.0.0.0       # Override host from config
```

### Quick Start (No Configuration Required)
```bash
# Run with default settings - perfect for development!
cargo run

# This starts the server with:
# - In-memory SQLite database
# - Anonymous access (no authentication)
# - Single tenant at /scim/v2
# - Listening on 127.0.0.1:3000
```

### Configuration
```bash
# Run with default configuration (no config.yaml needed)
cargo run

# Create configuration file (optional)
cp config.yaml my-config.yaml
ACME_TOKEN=secret123 GLOBEX_USER=admin GLOBEX_PASSWORD=pass cargo run -- -c my-config.yaml

# Custom config file location
cargo run -- -c production.yaml

# Validate configuration without running
cargo run -- -c config.yaml --validate
```

### Testing
```bash
cargo test                         # Run all tests
cargo test --all-features         # Include PostgreSQL tests (requires Docker)
cargo test --test attributes_filter_test  # Run specific test file
cargo test test_user_attributes_parameter  # Run specific test function
cargo test --test etag_version_test       # Run ETag/versioning tests
./run_tests.sh                    # Run automated test suite with summary
```

### Development Tools
```bash
# Format code
cargo fmt

# Lint code (warnings only for now)
cargo clippy --all-targets --all-features -- -W clippy::all

# Check without building
cargo check --all-features

# Security audit
cargo audit

# Generate documentation
cargo doc --open --all-features

# Test GitHub Actions locally (requires act)
act -l                             # List available workflows
act -j test-basic                  # Run basic test suite locally
act -j docker-build                # Test Docker build locally
```

### Local GitHub Actions Testing
```bash
# Install act (GitHub Actions runner)
brew install act

# Run CI workflows locally
act -j test-basic                  # Test basic CI workflow
act -j test-postgres               # Test PostgreSQL integration
act -j docker-build                # Test Docker build
act -j build-check                 # Test cross-compilation
```

### Release Process
```bash
# Create a new release
git tag v1.0.0
git push origin v1.0.0

# GitHub Actions will automatically:
# 1. Create a draft release
# 2. Build Linux binaries (x86_64 and ARM64)
# 3. Upload binaries as tar archives
# 4. Generate and upload license information (THIRD-PARTY-LICENSES)
# 5. Publish the release

# Download released binaries
curl -L https://github.com/{owner}/scim-server/releases/download/v1.0.0/scim-server-x86_64-unknown-linux-gnu.tar.gz | tar xz
./scim-server --version
```

## Modern Architecture Overview

### Production-Ready SCIM 2.0 Server
This is a fully compliant SCIM 2.0 server with enterprise-grade architecture:

- **RFC 7644 Compliance**: Complete SCIM 2.0 specification implementation
- **Multi-tenant architecture**: Path-based tenant isolation with optional host routing and per-tenant auth
- **Dual database support**: PostgreSQL (production) and SQLite (development)
- **Advanced features**: Attribute filtering, complex queries, PATCH operations, ETag/versioning
- **Zero-configuration mode**: Run without config.yaml for development/testing
- **Production ready**: Docker support, CI/CD, comprehensive testing
- **Modern Rust**: Uses Rust 1.85+ with edition2024 support
- **Optimized dependencies**: Latest cryptographic libraries (argon2 v0.5, base64ct v1.8.0)
- **Optimistic concurrency control**: RFC 7232 conditional requests with ETag support

### Clean Architecture Pattern
```
┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│   HTTP Layer    │  Business Logic │  Repository     │   Database      │
│                 │                 │   Abstraction   │ Implementation  │
├─────────────────┼─────────────────┼─────────────────┼─────────────────┤
│ Resource        │ Schema          │ UserRepository  │ PostgreSQL      │
│ Handlers        │ Validation      │ GroupRepository │ Backend         │
│ (Axum Web)      │ & Normalization │ (Traits)        │                 │
├─────────────────┼─────────────────┼─────────────────┼─────────────────┤
│ Attribute       │ Filter Parser   │                 │ SQLite          │
│ Filtering       │ & Query Builder │                 │ Backend         │
├─────────────────┼─────────────────┼─────────────────┼─────────────────┤
│ Multi-Tenant    │ Authentication  │                 │ Shared Schema   │
│ Routing         │ & Authorization │                 │ & Indexing      │
└─────────────────┴─────────────────┴─────────────────┴─────────────────┘
```

## Configuration System

### YAML-First Configuration
The server uses YAML configuration with environment variable embedding for secrets:

**Complete Configuration Example:**
```yaml
server:
  host: "0.0.0.0"
  port: 3000

backend:
  backend_type: "database"
  database:
    db_type: "postgresql"  # or "sqlite"
    url: "postgresql://user:${DB_PASSWORD}@localhost:5432/scim"
    max_connections: 10

tenants:
  # Simple path-only tenant (matches any host) - OAuth 2.0 Bearer Token
  - id: 1
    path: "/scim/v2"
    auth:
      auth_type: "bearer"
      token: "${SCIM_SERVER_TOKEN:-sample-bearer-token}"

  # Host-specific tenant with default Host header resolution
  - id: 2
    path: "/api/scim"
    host: "api.example.com"
    auth:
      auth_type: "basic"
      basic:
        username: "${API_USER:-admin}"
        password: "${API_PASSWORD:-password}"

  # Host-specific tenant with explicit Host header resolution
  - id: 10
    path: "/scim/tenant1"
    host: "tenant1.company.com"
    host_resolution:
      type: "host"
    auth:
      auth_type: "bearer"
      token: "${TENANT1_TOKEN:-tenant1-token}"

  # Host-specific tenant with Forwarded header resolution (behind proxy)
  - id: 20
    path: "/scim/tenant2"
    host: "tenant2.company.com"
    host_resolution:
      type: "forwarded"
      trusted_proxies: ["192.168.1.100", "10.0.0.0/8"]
    auth:
      auth_type: "basic"
      basic:
        username: "${TENANT2_USER:-tenant2user}"
        password: "${TENANT2_PASS:-tenant2pass}"

  # Token authentication tenant
  - id: 25
    path: "/scim/token"
    host: "token.company.com"
    auth:
      auth_type: "token"
      token: "${TOKEN_SCIM_TOKEN:-token_xxxxxxxxxxxxxxxxxxxx}"

  # Host-specific tenant with X-Forwarded headers (behind load balancer)
  - id: 30
    path: "/api/scim"
    host: "api.loadbalancer.com"
    host_resolution:
      type: "xforwarded"
      trusted_proxies: ["172.16.0.0/12"]
    auth:
      auth_type: "bearer"
      token: "${API_TOKEN:-api-token}"

  # Tenant with custom endpoints and override base URL
  - id: 40
    path: "/scim/v2"
    override_base_url: "https://public.example.com"  # Forces response URLs
    auth:
      auth_type: "bearer"
      token: "${CUSTOM_TOKEN:-custom-token}"
    custom_endpoints:
      # Static JSON response endpoint
      - path: "/my/custom/static"
        response: |
          {
            "message": "This is a custom static endpoint",
            "version": "1.0.0",
            "timestamp": "2024-01-01T00:00:00Z"
          }
        status_code: 200
        content_type: "application/json"
      
      # Health check endpoint
      - path: "/health/custom"
        response: |
          {
            "status": "healthy",
            "service": "SCIM Server Custom Endpoint"
          }
        status_code: 200
        content_type: "application/json"
      
      # Plain text response example
      - path: "/info/text"
        response: "This is a plain text custom endpoint response"
        status_code: 200
        content_type: "text/plain"
      
  # Zero-configuration development tenant
  - id: 50
    path: "/dev/scim"
    auth:
      auth_type: "unauthenticated"
      
  # Tenant with custom compatibility settings
  - id: 60
    path: "/legacy/scim"
    auth:
      auth_type: "bearer"
      token: "${LEGACY_TOKEN:-legacy-token}"
    compatibility:
      meta_datetime_format: "epoch"        # Legacy system uses timestamps
      show_empty_groups_members: false     # Don't show empty arrays
      include_user_groups: false           # Doesn't support User.groups
      support_group_members_filter: false  # Can't filter by members

# Global compatibility defaults
compatibility:
  meta_datetime_format: "rfc3339"
  show_empty_groups_members: true
  include_user_groups: true
  support_group_members_filter: true
  support_group_displayname_filter: true
  support_patch_replace_empty_array: true    # Allow [] to clear multi-valued attributes
  support_patch_replace_empty_value: false   # Reject [{"value":""}] pattern
```

### Authentication Types

The server supports multiple authentication methods that can be configured per tenant:

#### Bearer Token (OAuth 2.0)
Standard OAuth 2.0 Bearer token authentication (RFC 6750):
```yaml
auth:
  auth_type: "bearer"
  token: "${BEARER_TOKEN:-default-token}"
```
- **Usage**: `Authorization: Bearer <token>`
- **Case-insensitive**: "Bearer", "bearer", or "BEARER" are all valid
- **Most common for API access**

#### Token Authentication
Alternative token format for systems that don't use Bearer prefix:
```yaml
auth:
  auth_type: "token"
  token: "${API_TOKEN:-token_xxxxxxxxxxxxxxxxxxxx}"
```
- **Usage**: `Authorization: token <token>`
- **Case-insensitive**: "Token" or "token" are valid
- **Used by some API providers like GitHub**

#### HTTP Basic Authentication
Standard HTTP Basic authentication (RFC 7617):
```yaml
auth:
  auth_type: "basic"
  basic:
    username: "${API_USER:-admin}"
    password: "${API_PASSWORD:-password}"
```
- **Usage**: `Authorization: Basic <base64(username:password)>`
- **Case-insensitive**: "Basic" or "basic" are valid
- **Suitable for simple username/password scenarios**

#### Unauthenticated (Development Only)
No authentication required - useful for development and testing:
```yaml
auth:
  auth_type: "unauthenticated"
```
- **Usage**: No Authorization header required
- **WARNING**: Never use in production environments
- **Perfect for local development and testing**

### Host Resolution

The server supports multiple methods for resolving the host in multi-tenant environments:

#### Host Header (Default)
Uses the standard HTTP Host header:
```yaml
host_resolution:
  type: "host"  # or omit host_resolution entirely
```
- **Default behavior** if host_resolution is not specified
- **Direct connection** scenarios
- **Development environments**

#### Forwarded Header (RFC 7239)
For proxies that use the standard Forwarded header:
```yaml
host_resolution:
  type: "forwarded"
  trusted_proxies: ["192.168.1.100", "10.0.0.0/8"]
```
- **Parses**: `Forwarded: for=192.0.2.60;host=example.com;proto=https`
- **Validates proxy IP** against trusted_proxies list
- **Extracts**: host, proto, and for parameters
- **Most standards-compliant option**

#### X-Forwarded Headers
For proxies/load balancers using X-Forwarded-* headers:
```yaml
host_resolution:
  type: "xforwarded"
  trusted_proxies: ["172.16.0.0/12", "10.0.0.0/8"]
```
- **Uses headers**: `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-For`
- **Common with**: AWS ALB, nginx, Apache
- **Validates proxy IP** from X-Forwarded-For
- **Widely supported** by load balancers

**Security Note**: Always configure `trusted_proxies` with actual proxy IP addresses to prevent header spoofing attacks.

### Response URL Control

Control how URLs appear in SCIM responses:

#### Automatic URL Construction (Default)
URLs are automatically constructed based on host resolution:
- **Direct connection** (`host`): `http://resolved-host/path`
- **Behind proxy** (`forwarded`/`xforwarded`): `https://resolved-host/path`
- **Protocol detection**: Assumes HTTPS when behind proxy

#### Override Base URL
Force a specific base URL for all responses:
```yaml
override_base_url: "https://api.public.com"
```

**Use cases**:
- **Internal vs External URLs**: Internal routing differs from public URLs
- **Consistent URLs**: Same URLs regardless of request origin
- **Complex proxy setups**: Multiple layers of proxies/load balancers
- **Custom domains**: CDN or API gateway scenarios

**Example**: If tenant path is `/scim/v2` and override is `https://api.public.com`:
- User resource: `https://api.public.com/scim/v2/Users/123`
- Group resource: `https://api.public.com/scim/v2/Groups/456`

### Custom Endpoints

Define static responses for custom paths within a tenant:

```yaml
custom_endpoints:
  # JSON response
  - path: "/my/custom/static"
    response: |
      {
        "message": "This is a custom static endpoint",
        "version": "1.0.0",
        "timestamp": "2024-01-01T00:00:00Z",
        "data": {
          "custom_field": "custom_value",
          "nested": {
            "array": [1, 2, 3],
            "boolean": true
          }
        }
      }
    status_code: 200
    content_type: "application/json"
  
  # Health check endpoint
  - path: "/health/custom"
    response: |
      {
        "status": "healthy",
        "service": "SCIM Server Custom Endpoint",
        "uptime": "24h"
      }
    status_code: 200
    content_type: "application/json"
  
  # Plain text response
  - path: "/info/text"
    response: "This is a plain text custom endpoint response"
    status_code: 200
    content_type: "text/plain"
  
  # Custom error response
  - path: "/maintenance"
    response: |
      {
        "error": "Service Unavailable",
        "message": "The service is under maintenance"
      }
    status_code: 503
    content_type: "application/json"
```

**Features**:
- **Static responses**: No dynamic processing
- **Any content type**: JSON, text, HTML, XML, etc.
- **Custom status codes**: 200, 404, 503, etc.
- **Tenant isolation**: Each tenant has its own endpoints
- **Authentication**: Inherits tenant's auth configuration

**Common use cases**:
- **Health checks**: `/health`, `/ping`, `/status`
- **Version info**: `/version`, `/info`
- **Service metadata**: `/config`, `/features`
- **Maintenance pages**: `/maintenance`
- **Integration endpoints**: Legacy system compatibility

### Environment Variable Embedding
- Use `${VAR_NAME}` or `${VAR_NAME:-default}` syntax in YAML
- Only for sensitive data: tokens, passwords, database credentials
- Variables expanded at startup with comprehensive error handling

### Compatibility Configuration

The server supports extensive compatibility options to emulate various SCIM implementations with different levels of compliance:

**Global and Tenant-Specific Settings:**
```yaml
# Global defaults (apply to all tenants)
compatibility:
  meta_datetime_format: "rfc3339"       # "rfc3339" or "epoch"
  show_empty_groups_members: true       # Show/hide empty arrays
  include_user_groups: true             # Include/exclude User.groups field
  support_group_members_filter: true    # Allow/reject members filters
  support_group_displayname_filter: true # Allow/reject displayName filters

# Tenant-specific overrides
tenants:
  - id: 1
    path: "/scim/v2"
    compatibility:  # Overrides global settings
      meta_datetime_format: "epoch"  # Legacy system compatibility
      include_user_groups: false     # This tenant doesn't support User.groups
```

**Compatibility Options:**
- **`meta_datetime_format`**: Controls datetime format in responses
  - `"rfc3339"` (default): Standard format like `"2025-06-14T10:03:54.374Z"`
  - `"epoch"`: Unix timestamp in milliseconds like `1749895434374`
  - Applied to meta.created and meta.lastModified fields
  - **Important**: Only affects response format, storage remains RFC3339

- **`support_patch_replace_empty_array`**: Controls PATCH replace with empty array for clearing multi-valued attributes
  - `true` (default): Allow `{"op": "replace", "path": "emails", "value": []}` to clear all emails
  - `false`: Reject PATCH operations that use empty arrays to clear multi-valued attributes
  - Some SCIM servers don't support empty array clearing, so this provides compatibility

- **`support_patch_replace_empty_value`**: Controls special empty value pattern for clearing
  - `false` (default): Reject `{"op": "replace", "path": "emails", "value": [{"value": ""}]}` pattern
  - `true`: Allow this non-standard pattern to clear multi-valued attributes
  - **WARNING**: This is a non-RFC pattern used by some legacy SCIM implementations

- **`show_empty_groups_members`**: Controls empty array display
  - `true` (default): Show empty arrays as `[]`
  - `false`: Omit empty members/groups arrays entirely
  - Applies to Group.members and User.groups

- **`include_user_groups`**: Controls User.groups field inclusion
  - `true` (default): Include groups field in User resources
  - `false`: Completely omit groups field from User resources
  - Useful for servers that don't support User group membership

- **`support_group_members_filter`**: Controls Group members filtering
  - `true` (default): Allow `filter=members[value eq "user-id"]`
  - `false`: Return 400 error for members filters
  - For servers that can't filter groups by member

- **`support_group_displayname_filter`**: Controls Group displayName filtering
  - `true` (default): Allow `filter=displayName eq "Admins"`
  - `false`: Return 400 error for displayName filters
  - For servers with limited filter capabilities

**Implementation Details:**
- Located in `src/config.rs` as `CompatibilityConfig`
- Utility functions in `src/utils.rs` for datetime and array transformations
- Applied in all User and Group handlers (`src/resource/user.rs`, `src/resource/group.rs`)
- Response-time transformations only - database storage format unchanged

### Zero-Configuration Development Mode

When no `config.yaml` is found, the server automatically starts with development-friendly defaults:

**Default Configuration:**
```yaml
server:
  host: "127.0.0.1"
  port: 3000

backend:
  type: "database"
  database:
    type: "sqlite"
    url: ":memory:"
    max_connections: 1

tenants:
  - id: 1
    path: "/scim/v2"
    auth:
      type: "unauthenticated"
```

**Benefits:**
- **Instant startup**: No configuration file needed
- **In-memory database**: No persistence, perfect for testing
- **Anonymous access**: No authentication required
- **Standard SCIM path**: Available at `/scim/v2/*`
- **Development ready**: Perfect for local development and CI/CD

## Core Features Implementation

### 1. RFC 7644 SCIM 2.0 Compliance

**Full SCIM Resource Support:**
- Users with all standard and enterprise attributes
- Groups with nested membership support
- ServiceProviderConfig with server capabilities
- Resource type and schema discovery endpoints

**Advanced Query Support:**
```bash
# Complex filtering (using configured path)
GET /scim/v2/Users?filter=name.givenName eq "John" and emails[type eq "work"]

# Attribute projection (NEW FEATURE)
GET /scim/v2/Users?attributes=userName,emails.value
GET /scim/v2/Users?excludedAttributes=password,phoneNumbers

# Sorting and pagination
GET /scim/v2/Users?sortBy=name.familyName&sortOrder=ascending&startIndex=1&count=10

# Custom tenant paths (example)
GET /my-custom-path/Users?filter=userName eq "alice"
```

### 2. Attribute Filtering Implementation

**RFC 7644 Section 3.4.2.5 Compliance:**
- `attributes` parameter: Return only specified attributes
- `excludedAttributes` parameter: Exclude specified attributes
- Support for nested attributes: `name.givenName`, `emails.value`
- Always includes core attributes: `id`, `schemas`, `meta`
- Mutually exclusive parameters with proper error handling

**Implementation Details:**
- Located in `src/resource/attribute_filter.rs`
- Applied to both individual resources and list responses
- Handles complex nested JSON structures
- Works with both User and Group resources

### 2.5. ETag/Versioning Implementation

**RFC 7232 HTTP Conditional Request Compliance:**
- **ETag Headers**: All resource responses include `ETag: W/"<version>"` headers
- **Version Field**: SCIM resources include `meta.version` field with ETag value
- **Conditional GET**: Support for `If-None-Match` header (returns 304 Not Modified)
- **Conditional UPDATE/PATCH/DELETE**: Support for `If-Match` header (optimistic concurrency control)
- **Version Increment**: Automatic version increment on resource modifications
- **Conflict Detection**: Returns 412 Precondition Failed for version mismatches

**Implementation Details:**
- **Database Schema**: `version` column in User and Group tables (starts at 1, increments on updates)
- **Version Format**: Weak ETag format `W/"<integer>"` (e.g., `W/"1"`, `W/"2"`)
- **Optimistic Locking**: Prevents lost updates in concurrent environments
- **SCIM Error Format**: Proper 412 error responses with SCIM schemas
- **Cross-Database Support**: Works with both PostgreSQL and SQLite
- **Test Coverage**: Comprehensive test suite in `tests/etag_version_test.rs`

**Example Usage:**
```bash
# GET with ETag response
GET /scim/v2/Users/123
→ ETag: W/"1"
→ {"meta": {"version": "W/\"1\""}, ...}

# Conditional GET (304 if not modified)
GET /scim/v2/Users/123
If-None-Match: W/"1"
→ 304 Not Modified

# Conditional UPDATE (prevents conflicts)
PUT /scim/v2/Users/123
If-Match: W/"1"
→ 200 OK, ETag: W/"2" (if successful)
→ 412 Precondition Failed (if version mismatch)
```

### 3. Multi-Tenant Architecture

**Path-Based Tenant Routing with Optional Host Resolution:**
- Each tenant path configured in YAML defines the route prefix
- Example: `path: "/scim/v2"` → routes at `/scim/v2/*`
- Example: `path: "/api/scim"` → routes at `/api/scim/*`
- Optional host-based routing: `host: "api.example.com"` for multi-domain support
- Complete data isolation via per-tenant table architecture
- Tenant resolution from path and optional host matching
- Per-tenant authentication and authorization
- **Flexible routing** - path-only or path+host combinations

**Database Schema Requirements:**
```sql
-- Tenant-specific table architecture (per-tenant tables)
-- PostgreSQL example for tenant ID 1:
CREATE TABLE t1_users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT NOT NULL UNIQUE,        -- Stored in lowercase
    external_id TEXT UNIQUE,              -- Optional client identifier
    data_orig JSONB NOT NULL,             -- Original SCIM data
    data_norm JSONB NOT NULL,             -- Normalized data
    version BIGINT NOT NULL DEFAULT 1,    -- ETag versioning for optimistic concurrency
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE t1_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    display_name TEXT NOT NULL UNIQUE,    -- Case-insensitive searches
    external_id TEXT UNIQUE,              -- Optional client identifier
    data_orig JSONB NOT NULL,             -- Original SCIM data
    data_norm JSONB NOT NULL,             -- Normalized data
    version BIGINT NOT NULL DEFAULT 1,    -- ETag versioning for optimistic concurrency
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Association table for normalized memberships
CREATE TABLE t1_group_memberships (
    id SERIAL PRIMARY KEY,
    group_id UUID NOT NULL,
    member_id UUID NOT NULL,
    member_type TEXT NOT NULL CHECK (member_type IN ('User', 'Group')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(group_id, member_id, member_type),
    FOREIGN KEY (group_id) REFERENCES t1_groups (id) ON DELETE CASCADE
);

-- Performance indexes (created automatically)
CREATE INDEX idx_1_users_username_lower ON t1_users (LOWER(username));
CREATE INDEX idx_1_users_external_id ON t1_users (external_id) WHERE external_id IS NOT NULL;
CREATE INDEX idx_1_groups_display_name_lower ON t1_groups (LOWER(display_name));
CREATE INDEX idx_1_memberships_group_id ON t1_group_memberships (group_id);
```

### 4. Advanced Database Architecture

**Per-Tenant Table Design:**
- Each tenant gets dedicated tables: `t{tenant_id}_users`, `t{tenant_id}_groups`, etc.
- Complete data isolation without shared tenant_id columns
- Automatic schema creation with proper indexes and constraints
- No cross-tenant data contamination possible

**Normalized Group Membership:**
- Group members stored in separate `t{tenant_id}_group_memberships` table
- Supports User-to-Group and Group-to-Group relationships
- Dynamic member display name resolution via JOINs
- No redundant JSON storage of membership data

**Case-Insensitive Implementation:**
- `userName`: Stored lowercase, searched case-insensitively
- `Group displayName`: LOWER() SQL queries for searches
- Original case preserved in SCIM JSON data

**ExternalId Support:**
- Optional client-defined identifiers
- Unique constraints per tenant table
- NULL-safe database constraints
- Seamless SCIM JSON integration

### 5. Enhanced Schema System

**Advanced Validation:**
- Multi-valued attribute primary constraints
- Email, phone number, and URL format validation
- Required attribute enforcement
- Custom attribute support with configurable case sensitivity

**Schema Definitions:**
- Located in `src/schema/definitions.rs`
- Comprehensive SCIM 2.0 schema implementation
- Extensible attribute definition system
- Validation rule engine with detailed error messages

## Testing Architecture

### Comprehensive Test Strategy

**Test Categories:**
1. **Unit Tests**: Individual component testing
2. **Integration Tests**: Full HTTP request/response cycles
3. **Database Tests**: Both SQLite and PostgreSQL via TestContainers
4. **Compliance Tests**: SCIM 2.0 specification validation
5. **Multi-tenant Tests**: Tenant isolation verification

**Critical Test Files:**
- `tests/attributes_filter_test.rs`: RFC 7644 attribute filtering
- `tests/multi_tenant_test.rs`: Tenant isolation validation
- `tests/case_insensitive_*.rs`: SCIM case-insensitive compliance
- `tests/matrix_integration_test.rs`: Cross-database compatibility
- `tests/patch_operations_test.rs`: SCIM PATCH compliance
- `tests/etag_version_test.rs`: RFC 7232 ETag/versioning and conditional requests

### TestContainers Integration

**PostgreSQL Testing:**
- Automatic Docker container management
- Isolated test databases per test
- Full feature parity testing between SQLite and PostgreSQL
- CI/CD integration with GitHub Actions

**Configuration:**
```bash
export TESTCONTAINERS_RYUK_DISABLED=true
export TESTCONTAINERS_COMMAND_TIMEOUT=180
cargo test --all-features
```

## Development Best Practices

### Code Organization

**Module Structure:**
```
src/
├── resource/           # HTTP handlers and business logic
│   ├── user.rs        # User CRUD operations
│   ├── group.rs       # Group CRUD operations
│   └── attribute_filter.rs  # RFC 7644 attribute filtering
├── backend/           # Database abstraction layer
│   └── database/      # Concrete database implementations
├── schema/            # SCIM schema validation and normalization
├── parser/            # Query and filter parsing
└── config.rs          # Configuration management
```

**Key Design Patterns:**
- Repository pattern for database abstraction
- Builder pattern for complex query construction
- Strategy pattern for authentication methods
- Factory pattern for backend creation

### Error Handling

**Comprehensive Error Management:**
- Custom error types with detailed context
- HTTP status code mapping
- SCIM-compliant error responses
- Structured logging with correlation IDs

### Security Considerations

**Authentication & Authorization:**
- No hardcoded credentials (YAML + environment variables only)
- Proper Authorization header parsing
- Per-tenant credential validation
- Secure password hashing with multiple algorithms

**Input Validation:**
- Comprehensive request validation
- SQL injection prevention via prepared statements
- XSS prevention in JSON responses
- Rate limiting considerations for production deployment

## CI/CD and Deployment

### GitHub Actions Integration

**Automated Workflows:**
- **CI**: Linux-based testing with Rust stable and beta
- **Security**: Dependency auditing and vulnerability scanning
- **Release**: Automated Linux binary builds (x86_64 and ARM64)
- **TestContainers**: PostgreSQL integration testing on Linux
- **Build Check**: Cross-compilation verification for Linux targets

**Deployment Artifacts:**
- Linux binaries (x86_64 and ARM64) as tar archives
- Automatically uploaded to GitHub Releases
- Draft release created on tag push, published after builds complete

### Production Deployment

**Binary Distribution:**
- Pre-built Linux binaries available in GitHub Releases
- Supports x86_64 and ARM64 architectures
- Statically linked with musl for maximum portability
- No runtime dependencies required

**Docker Support (Development):**
- Dockerfile available for custom builds
- Uses Rust 1.85 for edition2024 support
- Multi-stage builds for optimized image size
- Security-hardened Alpine Linux base
- Non-root user execution

**CI/CD Optimizations:**
- Linux-only testing for faster CI times
- Clippy warnings allowed (not errors) for development velocity
- Simplified release process with Linux binaries only
- TestContainers for PostgreSQL integration testing
- Automated release on version tag (v*) push

**Monitoring and Observability:**
- Structured logging with configurable levels
- Health check endpoints
- Metrics collection readiness
- Performance monitoring capabilities

## Key Implementation Notes

### Critical Data Flow Patterns

**Group Membership Handling:**
- NEVER store member data in Group JSON
- Always use `group_memberships` table for relationships
- Populate members via JOIN queries in `fetch_members_for_group()`
- Use `.take()` pattern to prevent JSON duplication

**Tenant Resolution Flow:**
1. Extract tenant identifier from URL path
2. Resolve tenant ID using `app_config.resolve_tenant_id_from_path()`
3. Validate tenant exists and is configured
4. Apply tenant-specific authentication
5. Enforce tenant data isolation in all database operations

**Authentication Processing:**
1. Extract `Authorization` header from HTTP request
2. Parse Bearer token or Basic auth credentials
3. Match against tenant-specific auth configuration
4. Validate credentials and establish tenant context
5. Proceed with SCIM operation under tenant isolation

### Performance Optimization

**Database Query Optimization:**
- Per-tenant table design eliminates cross-tenant queries
- Case-insensitive indexes for username/displayName searches
- Optimized JOIN queries for group membership resolution
- Connection pooling for concurrent request handling
- Automatic index creation for all tenant tables

**Memory Management:**
- Streaming JSON parsing for large payloads
- Efficient attribute filtering without full object reconstruction
- Minimal memory allocation in hot paths
- Connection reuse across requests

This architecture provides a robust, scalable, and fully compliant SCIM 2.0 server suitable for enterprise production environments.