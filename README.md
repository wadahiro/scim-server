# SCIM Server

**This repository is heavily under development.**

A SCIM (System for Cross-domain Identity Management) v2.0 server implementation in Rust with **multi-tenant architecture** and dual database support.

[![CI](https://github.com/wadahiro/scim-server/workflows/CI/badge.svg)](https://github.com/wadahiro/scim-server/actions)
[![Release](https://github.com/wadahiro/scim-server/workflows/Release/badge.svg)](https://github.com/wadahiro/scim-server/releases)

## ✨ Features

### 🏢 Multi-Tenant Architecture
- **URL-based tenant routing**: Each tenant has dedicated SCIM endpoints
- **Complete data isolation**: Full separation between tenant data
- **Per-tenant authentication**: Multiple auth methods (Bearer, Token, Basic, Unauthenticated)
- **Flexible configuration**: YAML-based tenant setup with environment variable support
- **Compatibility modes**: Per-tenant SCIM implementation compatibility settings
- **Custom endpoints**: Define static JSON/text responses per tenant
- **Advanced host resolution**: Support for proxies and load balancers

### 🔧 SCIM 2.0 Specification Support

**Implemented Features:**
- ✅ **User Resource**: Basic user management with standard attributes
- ✅ **Group Resource**: Group management with member relationships
- ✅ **Complex filtering**: Advanced logical operators and nested expressions
- ✅ **PATCH operations**: Complete RFC 7396 JSON Patch compliance
- ✅ **Enterprise User Schema**: Extended user attributes
- ✅ **Attribute projection**: `attributes` and `excludedAttributes` parameter support
- ✅ **Case-insensitive attributes**: userName and Group displayName per specification
- ✅ **Sorting and pagination**: Basic SCIM query parameter support
- ✅ **ServiceProviderConfig**: Server capabilities endpoint
- ✅ **Resource Type discovery**: Schema and resource type endpoints
- ✅ **ETag/Versioning**: Full RFC 7232 conditional request support with optimistic concurrency control

**In Development:**
- 🚧 **Schema extensions**: Custom schema definitions

**Not Yet Implemented:**
- ❌ **Bulk operations**: Batch resource operations
- ❌ **Event notifications**: Webhook and event streaming

### 🗄️ Database Support
- **PostgreSQL**
- **SQLite**

### 🔒 Security & Validation
- **Multi-layered validation**: Schema validation, primary constraints, and data integrity
- **Password hashing**: Argon2, bcrypt, and SSHA algorithm support
- **ExternalId support**: Optional client-defined identifiers with uniqueness constraints
- **Input sanitization**: Comprehensive request validation and error handling
- **Optimistic concurrency control**: ETag-based conflict prevention for concurrent updates

## 🚀 Quick Start

### Zero-Configuration Mode (Simplest)

```bash
# Clone and run immediately
git clone https://github.com/wadahiro/scim-server.git
cd scim-server
cargo run

# Server starts with default configuration:
# - SQLite in-memory database
# - SCIM endpoint at http://localhost:3000/scim/v2
# - No authentication required
```

### With Custom Configuration

```bash
# Use the sample configuration directly (no environment variables required)
# See config.yaml for complete configuration options
cargo run -- -c config.yaml

# Optional: Override default values with environment variables
export SCIM_SERVER_TOKEN="your-bearer-token"
export API_USER="admin"
export API_PASSWORD="password"
export TENANT1_TOKEN="tenant1-bearer-token"
# ... other variables as needed
cargo run -- -c config.yaml
```

## ⚙️ Configuration

### YAML Configuration

Sample configuration is available in the repository root: [config.yaml](config.yaml)

```yaml
server:
  host: "127.0.0.1"
  port: 3000

backend:
  type: "database"
  database:
    type: "sqlite"  # or "postgresql"
    url: "scim.db"

tenants:
  # Simple path-only tenant (matches any host) - OAuth 2.0 Bearer Token
  - id: 1
    path: "/scim/v2"
    auth:
      type: "bearer"
      token: "${SCIM_SERVER_TOKEN:-sample-bearer-token}"

  # Host-specific tenant with default Host header resolution
  - id: 2
    path: "/api/scim"
    host: "api.example.com"
    auth:
      type: "basic"
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
      type: "bearer"
      token: "${TENANT1_TOKEN:-tenant1-token}"

  # Host-specific tenant with Forwarded header resolution (behind proxy)
  - id: 20
    path: "/scim/tenant2"
    host: "tenant2.company.com"
    host_resolution:
      type: "forwarded"
      trusted_proxies: ["192.168.1.100", "10.0.0.0/8"]
    auth:
      type: "basic"
      basic:
        username: "${TENANT2_USER:-tenant2user}"
        password: "${TENANT2_PASS:-tenant2pass}"

  # Token authentication tenant
  - id: 25
    path: "/scim/token"
    host: "token.company.com"
    auth:
      type: "token"
      token: "${TOKEN_SCIM_TOKEN:-token_xxxxxxxxxxxxxxxxxxxx}"

  # Host-specific tenant with X-Forwarded headers (behind load balancer)
  - id: 30
    path: "/api/scim"
    host: "api.loadbalancer.com"
    host_resolution:
      type: "xforwarded"
      trusted_proxies: ["172.16.0.0/12"]
    auth:
      type: "bearer"
      token: "${API_TOKEN:-api-token}"

  # Tenant with custom endpoints and override base URL
  - id: 40
    path: "/scim/v2"
    override_base_url: "https://public.example.com"  # Forces response URLs
    auth:
      type: "bearer"
      token: "${CUSTOM_TOKEN:-custom-token}"
    custom_endpoints:
      - path: "/my/custom/static"
        response: |
          {
            "message": "This is a custom static endpoint",
            "version": "1.0.0"
          }
        status_code: 200
        content_type: "application/json"

# Global compatibility settings (can be overridden per tenant)
compatibility:
  meta_datetime_format: "rfc3339"  # or "epoch" for milliseconds
  show_empty_groups_members: true  # false to omit empty arrays
  include_user_groups: true        # false to omit User.groups field
  support_group_members_filter: true     # false to reject members filters
  support_group_displayname_filter: true # false to reject displayName filters
```

### Environment Variables

Environment variables are embedded in YAML using `${VAR_NAME:-default}` syntax:

```bash
export SCIM_SERVER_TOKEN="your-bearer-token"
export API_USER="admin"
export API_PASSWORD="secret"
export TENANT1_TOKEN="tenant1-bearer-token"

cargo run
```

### Compatibility Configuration

The server supports extensive compatibility options to emulate various SCIM implementations:

#### Global vs Tenant-Specific Settings
- **Global settings**: Applied to all tenants by default (defined at top level)
- **Tenant overrides**: Each tenant can override global settings

```yaml
# Global defaults
compatibility:
  meta_datetime_format: "rfc3339"
  show_empty_groups_members: true

# Tenant-specific override
tenants:
  - id: 1
    path: "/scim/v2"
    compatibility:  # Overrides global settings for this tenant
      meta_datetime_format: "epoch"
      show_empty_groups_members: false
```

#### Available Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `meta_datetime_format` | string | `"rfc3339"` | DateTime format: `"rfc3339"` (standard) or `"epoch"` (milliseconds) |
| `show_empty_groups_members` | bool | `true` | Show empty arrays as `[]` or omit them entirely |
| `include_user_groups` | bool | `true` | Include or completely omit the `groups` field in User resources |
| `support_group_members_filter` | bool | `true` | Allow filtering Groups by `members.value` |
| `support_group_displayname_filter` | bool | `true` | Allow filtering Groups by `displayName` |

#### Use Cases

**Legacy System Compatibility**
```yaml
compatibility:
  meta_datetime_format: "epoch"  # Return timestamps as 1749895434374
  show_empty_groups_members: false  # Omit empty arrays
```

**Limited SCIM Implementation**
```yaml
compatibility:
  include_user_groups: false  # Server doesn't support User.groups
  support_group_members_filter: false  # Can't filter by members
```

### Authentication Types

The server supports multiple authentication methods per tenant:

#### Bearer Token (OAuth 2.0)
Standard OAuth 2.0 Bearer token authentication (RFC 6750):
```yaml
auth:
  type: "bearer"
  token: "${BEARER_TOKEN:-default-token}"
```
Usage: `Authorization: Bearer <token>`

#### Token Authentication
Alternative token format for systems that don't use Bearer prefix:
```yaml
auth:
  type: "token"
  token: "${API_TOKEN:-token_xxxxxxxxxxxxxxxxxxxx}"
```
Usage: `Authorization: token <token>`

#### HTTP Basic Authentication
Standard HTTP Basic authentication (RFC 7617):
```yaml
auth:
  type: "basic"
  basic:
    username: "${API_USER:-admin}"
    password: "${API_PASSWORD:-password}"
```
Usage: `Authorization: Basic <base64(username:password)>`

#### Unauthenticated (Development Only)
No authentication required - useful for development and testing:
```yaml
auth:
  type: "unauthenticated"
```

### Host Resolution

The server supports multiple methods for resolving the host in multi-tenant environments:

#### Host Header (Default)
Uses the standard HTTP Host header:
```yaml
host_resolution:
  type: "host"  # or omit host_resolution entirely
```

#### Forwarded Header (RFC 7239)
For proxies that use the standard Forwarded header:
```yaml
host_resolution:
  type: "forwarded"
  trusted_proxies: ["192.168.1.100", "10.0.0.0/8"]
```
The server will parse: `Forwarded: for=192.0.2.60;host=example.com;proto=https`

#### X-Forwarded Headers
For proxies/load balancers using X-Forwarded-* headers:
```yaml
host_resolution:
  type: "xforwarded"
  trusted_proxies: ["172.16.0.0/12"]
```
The server will use: `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-For`

**Important**: Only configure trusted_proxies with actual proxy IP addresses to prevent header spoofing.

### Response URL Control

Control how URLs appear in SCIM responses:

#### Automatic URL Construction (Default)
URLs are automatically constructed based on host resolution:
- With `host` resolution: `http://resolved-host/path`
- With `forwarded`/`xforwarded`: `https://resolved-host/path` (assumes HTTPS)

#### Override Base URL
Force a specific base URL for all responses:
```yaml
override_base_url: "https://api.public.com"
```
This is useful when:
- Internal routing differs from external URLs
- You need consistent URLs regardless of request origin
- Running behind complex proxy setups

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
        "data": { "key": "value" }
      }
    status_code: 200
    content_type: "application/json"
  
  # Plain text response
  - path: "/info/text"
    response: "This is a plain text response"
    status_code: 200
    content_type: "text/plain"
  
  # Health check endpoint
  - path: "/health/custom"
    response: |
      {"status": "healthy", "service": "SCIM Server"}
    status_code: 200
    content_type: "application/json"
```

Custom endpoints are useful for:
- Health checks and monitoring
- Version information
- Service-specific metadata
- Integration with existing systems

## 📡 API Endpoints

### Multi-Tenant Endpoints

Each configured tenant gets dedicated SCIM endpoints using their configured URL path:

```
# For tenant with path: "/scim/v2"
# Routes available at: /scim/v2/*

# Users
GET    /scim/v2/Users              # List users
GET    /scim/v2/Users/{id}         # Get user
POST   /scim/v2/Users              # Create user
PUT    /scim/v2/Users/{id}         # Update user
PATCH  /scim/v2/Users/{id}         # Patch user
DELETE /scim/v2/Users/{id}         # Delete user

# Groups
GET    /scim/v2/Groups             # List groups
GET    /scim/v2/Groups/{id}        # Get group
POST   /scim/v2/Groups             # Create group
PUT    /scim/v2/Groups/{id}        # Update group
PATCH  /scim/v2/Groups/{id}        # Patch group
DELETE /scim/v2/Groups/{id}        # Delete group

# Metadata
GET    /scim/v2/ServiceProviderConfig  # Server capabilities
GET    /scim/v2/Schemas                # SCIM schemas
GET    /scim/v2/ResourceTypes          # Resource types
```

**Note**: The actual endpoint paths depend on your tenant configuration. If a tenant is configured with `path: "/my-custom-path"`, all endpoints will be available under `/my-custom-path/*`.

### Query Parameters

#### Filtering
```bash
# Simple filters
GET /scim/v2/Users?filter=userName eq "alice"

# Complex filters with logical operators
GET /scim/v2/Users?filter=name.givenName eq "John" and emails[type eq "work"]

# Group membership filters
GET /scim/v2/Groups?filter=members[value eq "user-123"]
```

#### Attribute Projection
```bash
# Request specific attributes only
GET /scim/v2/Users?attributes=userName,emails

# Exclude attributes
GET /scim/v2/Users?excludedAttributes=phoneNumbers,addresses

# Complex attribute selection
GET /scim/v2/Users?attributes=name.givenName,emails.value
```

#### Sorting and Pagination
```bash
# Sort by attribute
GET /scim/v2/Users?sortBy=name.familyName&sortOrder=ascending

# Pagination
GET /scim/v2/Users?startIndex=1&count=10
```

### ETag and Versioning Support

The server supports RFC 7232 conditional requests for optimistic concurrency control:

#### ETag Headers
All resource responses include ETag headers with version information:
```bash
# Response includes ETag header
HTTP/1.1 200 OK
ETag: W/"1"
Content-Type: application/scim+json

{
  "id": "user-123",
  "meta": {
    "version": "W/\"1\"",
    "created": "2024-01-01T12:00:00Z",
    "lastModified": "2024-01-01T12:00:00Z"
  },
  ...
}
```

#### Conditional Requests
```bash
# Conditional GET (If-None-Match) - returns 304 if not modified
GET /scim/v2/Users/user-123
If-None-Match: W/"1"

# Conditional UPDATE (If-Match) - prevents conflicts
PUT /scim/v2/Users/user-123
If-Match: W/"1"
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "alice-updated",
  ...
}

# Conditional PATCH with optimistic locking
PATCH /scim/v2/Users/user-123
If-Match: W/"2"
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "replace",
      "path": "emails[type eq \"work\"].value",
      "value": "newemail@example.com"
    }
  ]
}
```

#### Error Responses
```bash
# 304 Not Modified - resource hasn't changed
HTTP/1.1 304 Not Modified
ETag: W/"1"

# 412 Precondition Failed - version conflict
HTTP/1.1 412 Precondition Failed
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "detail": "Resource version mismatch",
  "status": "412",
  "scimType": "preconditionFailed"
}
```

## 🧪 Testing

### Basic Test

```bash
# Create a user (using zero-configuration mode - no auth required)
curl -X POST "http://localhost:3000/scim/v2/Users" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "alice",
    "name": {
      "givenName": "Alice",
      "familyName": "Smith"
    },
    "emails": [{
      "value": "alice@example.com",
      "primary": true
    }]
  }'

# List users with attribute filtering
curl "http://localhost:3000/scim/v2/Users?attributes=userName,emails"

# With Bearer token authentication
curl -X POST "http://localhost:3000/scim/v2/Users" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer your-bearer-token" \
  -d '...'

# With Token authentication
curl -X POST "http://localhost:3000/scim/token/Users" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: token token_xxxxxxxxxxxxxxxxxxxx" \
  -d '...'

# With Basic authentication
curl -X POST "http://localhost:3000/api/scim/Users" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Basic $(echo -n 'admin:password' | base64)" \
  -d '...'

# Testing custom endpoints
curl "http://localhost:3000/scim/v2/my/custom/static" \
  -H "Authorization: Bearer custom-token"

# Behind proxy with X-Forwarded headers
curl "http://localhost:3000/api/scim/Users" \
  -H "X-Forwarded-Host: api.loadbalancer.com" \
  -H "X-Forwarded-Proto: https" \
  -H "X-Forwarded-For: 192.168.1.100" \
  -H "Authorization: Bearer api-token"

# Testing ETag functionality
# GET with If-None-Match (conditional request)
curl "http://localhost:3000/scim/v2/Users/user-123" \
  -H "If-None-Match: W/\"1\"" \
  -H "Authorization: Bearer your-token"

# UPDATE with If-Match (optimistic locking)
curl -X PUT "http://localhost:3000/scim/v2/Users/user-123" \
  -H "Content-Type: application/scim+json" \
  -H "If-Match: W/\"1\"" \
  -H "Authorization: Bearer your-token" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "alice-updated",
    "emails": [{"value": "updated@example.com", "primary": true}]
  }'
```

### Comprehensive Testing

```bash
# Run all tests
cargo test

# Run with specific features
cargo test --features sqlite
cargo test --features postgresql

# Run integration tests
cargo test --test matrix_integration_test

# Run ETag/versioning tests
cargo test --test etag_version_test
```

See [TESTING.md](TESTING.md) for detailed testing instructions including TestContainers setup.


## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

### Third-Party Licenses

This project uses various open-source dependencies. Third-party license information is automatically generated and included with each release as `licenses-{version}.tar.gz`.

To check dependency licenses locally:
```bash
cargo install cargo-license
cargo license
```

## 🙏 Acknowledgments

- [SCIM v2.0 Specification (RFC 7644)](https://tools.ietf.org/html/rfc7644)
- [scim_v2](https://crates.io/crates/scim_v2) crate for SCIM types
- Rust community for excellent async ecosystem