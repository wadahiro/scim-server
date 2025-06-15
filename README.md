# SCIM Server

**This repository is heavily under development.**

A SCIM (System for Cross-domain Identity Management) v2.0 server implementation in Rust with **multi-tenant architecture** and dual database support.

[![CI](https://github.com/wadahiro/scim-server/workflows/CI/badge.svg)](https://github.com/wadahiro/scim-server/actions)
[![Release](https://github.com/wadahiro/scim-server/workflows/Release/badge.svg)](https://github.com/wadahiro/scim-server/releases)

## ✨ Features

### 🏢 Multi-Tenant Architecture
- **URL-based tenant routing**: Each tenant has dedicated SCIM endpoints
- **Complete data isolation**: Full separation between tenant data
- **Per-tenant authentication**: Bearer tokens and HTTP Basic auth per tenant
- **Flexible configuration**: YAML-based tenant setup with environment variable support
- **Compatibility modes**: Per-tenant SCIM implementation compatibility settings

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

**In Development:**
- 🚧 **Schema extensions**: Custom schema definitions
- 🚧 **Resource versioning**: ETags and versioning support

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

  # Tenant with override base URL for public-facing responses
  - id: 20
    path: "/internal/scim"
    override_base_url: "https://api.public.com"  # Forces response URLs
    auth:
      type: "bearer"
      token: "${PUBLIC_API_TOKEN:-public-token}"

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

# For custom tenant configurations with authentication
curl -X POST "http://localhost:3000/my-custom-path/Users" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer your-token" \
  -d '...'
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