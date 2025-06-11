# Testing Guide

This document explains how to run tests for the SCIM Server, which includes comprehensive unit tests, integration tests, and cross-database compatibility testing.

## Quick Start

### Zero-Configuration Testing
```bash
# Run all tests with SQLite (fastest)
cargo test

# Run tests quietly to see summary only
cargo test --quiet

# Run specific test categories
cargo test --test attributes_filter_test
cargo test --test multi_tenant_test
```

## Test Configuration

### 1. SQLite Tests (Default)
```bash
# Test with SQLite only (fast, default configuration)
cargo test --features sqlite

# Run specific test files
cargo test --test crud_operations_test --features sqlite
cargo test test_user_crud --features sqlite

# Run with zero-configuration (no config.yaml needed)
cargo test test_attributes_parameter
```

### 2. PostgreSQL Tests (using TestContainers)
```bash
# Run all tests including PostgreSQL
cargo test --all-features

# Matrix integration tests (both SQLite and PostgreSQL)
cargo test --test matrix_integration_test --all-features

# Specific PostgreSQL integration test
cargo test postgres_test --all-features
```

## Test Coverage

### Comprehensive Test Suite

The SCIM server includes **134+ tests** covering all aspects of functionality:

**Core Feature Tests:**
- `attributes_filter_test.rs` - RFC 7644 attribute projection (`attributes`/`excludedAttributes`)
- `crud_operations_test.rs` - Basic CRUD operations for Users and Groups
- `patch_operations_test.rs` - SCIM PATCH operations compliance
- `multi_tenant_test.rs` - Multi-tenant isolation and security
- `matrix_integration_test.rs` - Cross-database compatibility (SQLite/PostgreSQL)

**Advanced Functionality:**
- `case_insensitive_*_test.rs` - SCIM case-insensitive attribute compliance
- `complex_filter_*_test.rs` - Advanced SCIM filter expressions
- `group_user_search_test.rs` - Group membership and user search
- `pagination_test.rs` - SCIM pagination and sorting
- `enterprise_user_test.rs` - Enterprise User schema support

**Quality Assurance:**
- `error_handling_test.rs` - Comprehensive error scenarios
- `data_validation_test.rs` - Input validation and schema compliance
- `password_algorithm_test.rs` - Multiple password hashing algorithms
- `service_provider_test.rs` - SCIM ServiceProviderConfig endpoint

### Test Architecture

**Multi-Database Testing:**
- All tests run on both SQLite and PostgreSQL
- Identical feature parity between database backends
- TestContainers for isolated PostgreSQL testing
- Zero-configuration in-memory SQLite for speed

**Multi-Tenant Testing:**
- Complete tenant isolation validation
- Cross-tenant security verification
- Per-tenant authentication testing
- URL-based routing validation

## About TestContainers

### Prerequisites
- Docker installed and running
- Access permissions to Docker socket

### Environment Variables

```bash
# TestContainers configuration
export TESTCONTAINERS_RYUK_DISABLED=true          # Disable Ryuk container
export TESTCONTAINERS_COMMAND_TIMEOUT=180         # Timeout setting
export RUST_LOG=info                              # Log level

# Run tests
cargo test --all-features
```

### Troubleshooting

#### Docker Connection Errors
```bash
# Check Docker daemon
docker info

# Check permissions
sudo usermod -aG docker $USER
newgrp docker
```

#### Manual Container Cleanup
```bash
# Remove remaining containers
docker ps -aq | xargs docker rm -f

# System cleanup
docker system prune -f
```

#### Timeout Errors
```bash
# Set longer timeout
export TESTCONTAINERS_COMMAND_TIMEOUT=300
```

## GitHub Actions CI

### Test Separation

1. **Basic Tests**: SQLite only (all OS)
   - Fast execution
   - Basic functionality tests

2. **PostgreSQL Tests**: Using TestContainers (Linux only)
   - Integration tests
   - Requires Docker environment

### CI Environment Notes

- **Linux only**: TestContainers works only on Linux
- **Docker pre-pull**: Pre-fetch PostgreSQL images
- **Cleanup**: Container cleanup after tests
- **Timeout**: Long-running execution countermeasures

## Local Development

### Recommended Development Workflow

```bash
# 1. Fast tests (SQLite)
cargo test --features sqlite

# 2. Complete tests (including PostgreSQL)
cargo test --all-features

# 3. Specific integration tests
cargo test matrix_integration_test --all-features
```

### Development with Docker Compose
```bash
# Start PostgreSQL
docker compose up -d postgres

# Set environment variables (use actual PostgreSQL)
export DATABASE_URL="postgresql://scim:scim_password@localhost:5432/scim"

# Run tests
cargo test --all-features
```

## Performance

### Execution Time Guidelines
- SQLite tests: 30-60 seconds
- PostgreSQL tests: 2-5 minutes (including container startup)

### Performance Tips
```bash
# Limit parallel execution (reduce memory usage)
cargo test --all-features -- --test-threads=2

# Specific test files only
cargo test --test attributes_filter_test --all-features

# Cache Docker images
docker pull postgres:15-alpine
```

## Debugging

### Enable Log Output
```bash
# Run tests with detailed logs
RUST_LOG=debug cargo test --all-features -- --nocapture

# TestContainers logs
TESTCONTAINERS_LOG_LEVEL=DEBUG cargo test --all-features
```

### Monitor Containers During Tests
```bash
# Monitor containers in another terminal
watch docker ps

# Check container logs
docker logs <container_id>
```

## Best Practices

1. **Prioritize SQLite during development**: Fast feedback with zero-configuration
2. **Complete tests before CI**: `cargo test --all-features`
3. **Docker cleanup**: Regular container removal
4. **Limit parallel execution**: Resource usage adjustment

## Recent Improvements

### URL-Based Routing Testing
- **No hardcoded paths**: All tests use configured tenant URLs exactly as specified
- **Dynamic routing**: Routes are registered using exact tenant URL paths from configuration
- **Cross-tenant isolation**: Fixed tests validate proper tenant data isolation
- **Zero-configuration testing**: Tests work without any config.yaml file

### Test Reliability Improvements
- **Fixed attribute filtering**: All 5 attribute filter tests now pass consistently
- **Cross-tenant security**: Improved tenant isolation validation in tests
- **URL generation**: Fixed inconsistencies in tenant URL reference generation
- **Route registration**: Eliminated hardcoded `/v2/` paths throughout test infrastructure

### Current Status
- **134+ tests passing**: Comprehensive test coverage with zero failures
- **Multi-database support**: Full feature parity between SQLite and PostgreSQL
- **CI/CD ready**: All tests pass in automated environments
- **Development-friendly**: Instant test execution with in-memory SQLite