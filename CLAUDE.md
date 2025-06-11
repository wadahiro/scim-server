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
cargo test --features sqlite       # SQLite tests only (fast)
cargo test --all-features         # Include PostgreSQL tests (requires Docker)
cargo test --test attributes_filter_test  # Run specific test file
cargo test test_user_attributes_parameter  # Run specific test function
./run_tests.sh                    # Run automated test suite with summary
```

### Development Tools
```bash
# Format code
cargo fmt

# Lint code
cargo clippy --all-targets --all-features

# Check without building
cargo check --all-features

# Security audit
cargo audit

# Generate documentation
cargo doc --open --all-features
```

## Modern Architecture Overview

### Production-Ready SCIM 2.0 Server
This is a fully compliant SCIM 2.0 server with enterprise-grade architecture:

- **RFC 7644 Compliance**: Complete SCIM 2.0 specification implementation
- **Multi-tenant architecture**: URL-based tenant isolation with per-tenant auth
- **Dual database support**: PostgreSQL (production) and SQLite (development)
- **Advanced features**: Attribute filtering, complex queries, PATCH operations
- **Zero-configuration mode**: Run without config.yaml for development/testing
- **Production ready**: Docker support, CI/CD, comprehensive testing

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
  - id: 1
    url: "https://acme.company.com/scim/v2"
    auth:
      auth_type: "bearer"
      token: "${ACME_TOKEN}"
      
  - id: 2
    url: "https://globex.company.com/api/scim/v2"
    auth:
      auth_type: "basic"
      basic:
        username: "${GLOBEX_USER}"
        password: "${GLOBEX_PASSWORD}"
        
  # Zero-configuration development tenant
  - id: 3
    url: "/scim/v2"
    auth:
      auth_type: "unauthenticated"
    host_resolution:
      type: "host"
```

### Environment Variable Embedding
- Use `${VAR_NAME}` or `${VAR_NAME:-default}` syntax in YAML
- Only for sensitive data: tokens, passwords, database credentials
- Variables expanded at startup with comprehensive error handling

### Multi-Tenant Authentication
- **Bearer Tokens**: OAuth 2.0 compliant (RFC 6750)
- **HTTP Basic Auth**: RFC 7617 compliant username/password
- **Unauthenticated**: Anonymous access for development/testing
- **Per-tenant configuration**: Each tenant can use different auth methods
- **Authorization header validation**: Proper parsing and validation

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
    url: "/scim/v2"
    auth:
      type: "unauthenticated"
    host_resolution:
      type: "host"
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
# Complex filtering (using configured URL paths)
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

### 3. Multi-Tenant Architecture

**URL-Based Tenant Routing:**
- Each tenant URL configured in YAML is used exactly as specified
- Example: `url: "/scim/v2"` → routes at `/scim/v2/*`
- Example: `url: "https://acme.com/api/scim/v2"` → routes at `/api/scim/v2/*` 
- Complete data isolation via per-tenant table architecture
- Tenant resolution from URL path with validation
- Per-tenant authentication and authorization
- **No hardcoded `/v2/` paths** - all paths use exact configuration

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
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE t1_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    display_name TEXT NOT NULL UNIQUE,    -- Case-insensitive searches
    external_id TEXT UNIQUE,              -- Optional client identifier
    data_orig JSONB NOT NULL,             -- Original SCIM data
    data_norm JSONB NOT NULL,             -- Normalized data
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
- **CI**: Multi-platform testing (Linux, macOS, Windows)
- **Security**: Dependency auditing and vulnerability scanning
- **Release**: Automated binary and Docker image builds
- **TestContainers**: PostgreSQL integration testing on Linux

**Deployment Artifacts:**
- Multi-platform binaries (Linux, macOS, Windows, ARM64)
- Docker images for containerized deployment
- GitHub Releases with automated changelog generation

### Production Deployment

**Docker Support:**
- Multi-stage builds for optimized image size
- Security-hardened Alpine Linux base
- Non-root user execution
- Configuration mounting and environment variable support

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