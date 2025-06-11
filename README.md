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
- **PostgreSQL**: Production-ready with JSONB support and advanced indexing
- **SQLite**: Development-friendly with identical feature parity

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
export SCIM_SERVER_TOKEN="your-bearer-token-here"
export ACME_USER="admin"
export ACME_PASSWORD="password"
# ... other variables as needed
cargo run -- -c config.yaml
```

## ⚙️ Configuration

### YAML Configuration

Sample configuration is available in the repository root: [config.yaml](config.yaml)

```yaml
server:
  host: "0.0.0.0"
  port: 3000

backend:
  type: "database"
  database:
    type: "postgresql"  # or "sqlite"
    url: "postgresql://user:pass@localhost:5432/scim"
    max_connections: 10

tenants:
  - id: 1
    url: "https://acme.company.com/scim/v2"
    auth:
      type: "bearer"
      token: "${ACME_TOKEN}"
  
  - id: 2
    url: "https://globex.company.com/api/scim/v2"
    auth:
      type: "basic"
      basic:
        username: "${GLOBEX_USER}"
        password: "${GLOBEX_PASSWORD}"
  
  # Development/testing configuration
  - id: 3
    url: "/scim/v2"
    auth:
      type: "unauthenticated"  # No authentication required
    host_resolution:
      type: "host"
```

### Environment Variables

Environment variables are embedded in YAML using `${VAR_NAME}` syntax:

```bash
export ACME_TOKEN="bearer_token_here"
export GLOBEX_USER="admin"
export GLOBEX_PASSWORD="secret"

cargo run
```

## 📡 API Endpoints

### Multi-Tenant Endpoints

Each configured tenant gets dedicated SCIM endpoints using their configured URL path:

```
# For tenant with url: "https://acme.company.com/scim/v2"
# Routes registered at: /scim/v2/*

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

**Note**: The actual endpoint paths depend on your tenant configuration. If a tenant is configured with `url: "/my-custom-path"`, all endpoints will be available under `/my-custom-path/*`.

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

## 🙏 Acknowledgments

- [SCIM v2.0 Specification (RFC 7644)](https://tools.ietf.org/html/rfc7644)
- [scim_v2](https://crates.io/crates/scim_v2) crate for SCIM types
- Rust community for excellent async ecosystem