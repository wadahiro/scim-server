use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub backend: BackendConfig,
    pub tenants: Vec<TenantConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BackendConfig {
    #[serde(rename = "type")]
    pub backend_type: String,
    pub database: Option<DatabaseConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DatabaseConfig {
    #[serde(rename = "type")]
    pub db_type: String,
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

fn default_max_connections() -> u32 {
    10
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TenantConfig {
    pub id: u32,
    pub url: String,
    pub auth: AuthConfig,
    #[serde(default)]
    pub host_resolution: Option<HostResolutionConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HostResolutionConfig {
    #[serde(rename = "type")]
    pub resolution_type: HostResolutionType,
    #[serde(default)]
    pub trusted_proxies: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HostResolutionType {
    Host,
    Forwarded,
    XForwarded,
}

#[derive(Debug, Clone)]
pub struct ResolvedUrl {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
}

#[derive(Debug)]
pub struct RequestInfo<'a> {
    pub path: &'a str,
    pub host_header: Option<&'a str>,
    pub forwarded_header: Option<&'a str>,
    pub x_forwarded_proto: Option<&'a str>,
    pub x_forwarded_host: Option<&'a str>,
    pub x_forwarded_port: Option<&'a str>,
    pub client_ip: Option<IpAddr>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthConfig {
    #[serde(rename = "type")]
    pub auth_type: String,
    pub token: Option<String>,
    pub basic: Option<BasicAuthConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BasicAuthConfig {
    pub username: String,
    pub password: String,
}

impl TenantConfig {
    /// Check if this tenant configuration matches the given request
    pub fn matches_request(&self, request_info: &RequestInfo) -> Option<ResolvedUrl> {
        // First check if URL is absolute (has scheme)
        if self.url.starts_with("http://") || self.url.starts_with("https://") {
            // Absolute URL - parse and compare directly
            if let Ok(parsed_url) = url::Url::parse(&self.url) {
                let resolved = self.resolve_url_from_request(request_info)?;

                // Compare host and path
                if parsed_url.host_str() == Some(&resolved.host)
                    && parsed_url.port() == resolved.port
                    && parsed_url.path() == resolved.path
                {
                    return Some(ResolvedUrl {
                        scheme: parsed_url.scheme().to_string(),
                        host: parsed_url.host_str().unwrap().to_string(),
                        port: parsed_url.port(),
                        path: parsed_url.path().to_string(),
                    });
                }
            }
        } else {
            // Relative URL - resolve using host resolution method
            let resolved = self.resolve_url_from_request(request_info)?;

            // Check if path matches
            if request_info.path.starts_with(&self.url) {
                return Some(resolved);
            }
        }

        None
    }

    /// Resolve URL from request using configured host resolution method
    fn resolve_url_from_request(&self, request_info: &RequestInfo) -> Option<ResolvedUrl> {
        let host_resolution = self.host_resolution.as_ref()?;

        match host_resolution.resolution_type {
            HostResolutionType::Host => self.resolve_from_host_header(request_info),
            HostResolutionType::Forwarded => self.resolve_from_forwarded_header(request_info),
            HostResolutionType::XForwarded => self.resolve_from_x_forwarded_headers(request_info),
        }
    }

    /// Resolve URL from Host header
    fn resolve_from_host_header(&self, request_info: &RequestInfo) -> Option<ResolvedUrl> {
        let host_header = request_info.host_header?;

        let (host, port) = if let Some(colon_pos) = host_header.rfind(':') {
            let host_part = &host_header[..colon_pos];
            let port_part = &host_header[colon_pos + 1..];

            if let Ok(port) = port_part.parse::<u16>() {
                (host_part.to_string(), Some(port))
            } else {
                (host_header.to_string(), None)
            }
        } else {
            (host_header.to_string(), None)
        };

        Some(ResolvedUrl {
            scheme: "https".to_string(), // Default to HTTPS
            host,
            port,
            path: request_info.path.to_string(),
        })
    }

    /// Resolve URL from RFC 7239 Forwarded header
    fn resolve_from_forwarded_header(&self, request_info: &RequestInfo) -> Option<ResolvedUrl> {
        let forwarded_header = request_info.forwarded_header?;

        // Parse Forwarded header (simplified implementation)
        // Format: Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43;host=example.com
        let mut scheme = "https".to_string();
        let mut host = String::new();
        let mut port = None;

        for part in forwarded_header.split(';') {
            let part = part.trim();
            if let Some(eq_pos) = part.find('=') {
                let key = &part[..eq_pos];
                let value = &part[eq_pos + 1..].trim_matches('"');

                match key {
                    "proto" => scheme = value.to_string(),
                    "host" => {
                        if let Some(colon_pos) = value.rfind(':') {
                            host = value[..colon_pos].to_string();
                            if let Ok(p) = value[colon_pos + 1..].parse::<u16>() {
                                port = Some(p);
                            }
                        } else {
                            host = value.to_string();
                        }
                    }
                    _ => {}
                }
            }
        }

        if host.is_empty() {
            return None;
        }

        Some(ResolvedUrl {
            scheme,
            host,
            port,
            path: request_info.path.to_string(),
        })
    }

    /// Resolve URL from X-Forwarded-* headers
    fn resolve_from_x_forwarded_headers(&self, request_info: &RequestInfo) -> Option<ResolvedUrl> {
        let scheme = request_info
            .x_forwarded_proto
            .unwrap_or("https")
            .to_string();

        let host_header = request_info.x_forwarded_host?;

        let (host, port) = if let Some(colon_pos) = host_header.rfind(':') {
            let host_part = &host_header[..colon_pos];
            let port_part = &host_header[colon_pos + 1..];

            if let Ok(port) = port_part.parse::<u16>() {
                (host_part.to_string(), Some(port))
            } else {
                (host_header.to_string(), None)
            }
        } else {
            let port = if let Some(port_header) = request_info.x_forwarded_port {
                port_header.parse::<u16>().ok()
            } else {
                None
            };
            (host_header.to_string(), port)
        };

        Some(ResolvedUrl {
            scheme,
            host,
            port,
            path: request_info.path.to_string(),
        })
    }
}

impl AppConfig {
    /// Load configuration from YAML file
    pub fn load_from_file<P: AsRef<Path>>(config_path: P) -> Result<Self, String> {
        let path = config_path.as_ref();

        if !path.exists() {
            return Err(format!("Configuration file not found: {}", path.display()));
        }

        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file {}: {}", path.display(), e))?;

        // Expand environment variables in YAML content
        let expanded_content = Self::expand_env_vars(&content)?;

        let app_config: AppConfig = serde_yaml::from_str(&expanded_content)
            .map_err(|e| format!("Failed to parse config file {}: {}", path.display(), e))?;

        if app_config.tenants.is_empty() {
            return Err("Configuration must contain at least one tenant".to_string());
        }

        Ok(app_config)
    }

    /// Create default configuration for in-memory SQLite with anonymous access
    pub fn default_config() -> Self {
        AppConfig {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 3000,
            },
            backend: BackendConfig {
                backend_type: "database".to_string(),
                database: Some(DatabaseConfig {
                    db_type: "sqlite".to_string(),
                    url: ":memory:".to_string(),
                    max_connections: 1,
                }),
            },
            tenants: vec![TenantConfig {
                id: 1,
                url: "/scim/v2".to_string(),
                auth: AuthConfig {
                    auth_type: "unauthenticated".to_string(),
                    token: None,
                    basic: None,
                },
                host_resolution: None, // Simple path-based routing for zero-config mode
            }],
        }
    }

    /// Expand environment variables in format ${VAR_NAME} or ${VAR_NAME:-default}
    fn expand_env_vars(content: &str) -> Result<String, String> {
        // Simple regex-like replacement for ${VAR} or ${VAR:-default}
        let chars: Vec<char> = content.chars().collect();
        let mut expanded = String::new();
        let mut i = 0;

        while i < chars.len() {
            if i + 1 < chars.len() && chars[i] == '$' && chars[i + 1] == '{' {
                // Find the closing brace
                let mut j = i + 2;
                while j < chars.len() && chars[j] != '}' {
                    j += 1;
                }

                if j < chars.len() {
                    // Extract variable expression
                    let var_expr: String = chars[i + 2..j].iter().collect();

                    // Parse VAR_NAME and default value
                    let (var_name, default_value) = if let Some(pos) = var_expr.find(":-") {
                        (
                            var_expr[..pos].to_string(),
                            Some(var_expr[pos + 2..].to_string()),
                        )
                    } else {
                        (var_expr, None)
                    };

                    // Get environment variable value
                    let value = match std::env::var(&var_name) {
                        Ok(val) => val,
                        Err(_) => {
                            if let Some(default) = default_value {
                                default
                            } else {
                                return Err(format!(
                                    "Environment variable {} not found and no default provided",
                                    var_name
                                ));
                            }
                        }
                    };

                    expanded.push_str(&value);
                    i = j + 1;
                } else {
                    expanded.push(chars[i]);
                    i += 1;
                }
            } else {
                expanded.push(chars[i]);
                i += 1;
            }
        }

        Ok(expanded)
    }

    /// Get all tenants
    pub fn get_all_tenants(&self) -> Vec<&TenantConfig> {
        self.tenants.iter().collect()
    }

    /// Resolve tenant ID from URL path segment
    /// This should be used in handlers to convert URL path tenant identifier to actual tenant ID
    pub fn resolve_tenant_id_from_path(&self, path_tenant: &str) -> Option<u32> {
        // Try to find tenant by exact ID match only
        if let Ok(numeric_id) = path_tenant.parse::<u32>() {
            if self.tenants.iter().any(|t| t.id == numeric_id) {
                return Some(numeric_id);
            }
        }

        None
    }

    /// Find tenant that matches the given request info
    pub fn find_tenant_by_request(
        &self,
        request_info: &RequestInfo,
    ) -> Option<(&TenantConfig, ResolvedUrl)> {
        for tenant in &self.tenants {
            if let Some(resolved_url) = tenant.matches_request(request_info) {
                return Some((tenant, resolved_url));
            }
        }
        None
    }
}

impl DatabaseConfig {
    // Implementation removed - using new storage abstraction
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_var_expansion() {
        // Test environment variable expansion
        std::env::set_var("TEST_TOKEN", "secret_token_123");
        std::env::set_var("TEST_PORT", "8080");

        let yaml_content = "port: ${TEST_PORT:-3000}\ntoken: \"${TEST_TOKEN:-default_token}\"";

        let expanded = AppConfig::expand_env_vars(yaml_content).unwrap();
        println!("Original: {}", yaml_content);
        println!("Expanded: {}", expanded);
        assert!(expanded.contains("secret_token_123"));
        assert!(expanded.contains("8080"));

        // Test with missing env var and default
        let yaml_with_default = "host: \"${MISSING_VAR:-localhost}\"";

        let expanded_default = AppConfig::expand_env_vars(yaml_with_default).unwrap();
        assert!(expanded_default.contains("localhost"));

        // Clean up
        std::env::remove_var("TEST_TOKEN");
        std::env::remove_var("TEST_PORT");
    }

    #[test]
    fn test_tenant_url_lookup() {
        let config = AppConfig {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 3000,
            },
            backend: BackendConfig {
                backend_type: "database".to_string(),
                database: Some(DatabaseConfig {
                    db_type: "sqlite".to_string(),
                    url: "test.db".to_string(),
                    max_connections: 10,
                }),
            },
            tenants: vec![
                TenantConfig {
                    id: 1,
                    url: "https://scim.example.com".to_string(),
                    auth: AuthConfig {
                        auth_type: "bearer".to_string(),
                        token: Some("example_token_123".to_string()),
                        basic: None,
                    },
                    host_resolution: None,
                },
                TenantConfig {
                    id: 2,
                    url: "https://acme.yourcompany.com/scim".to_string(),
                    auth: AuthConfig {
                        auth_type: "bearer".to_string(),
                        token: Some("acme_scim_token_456".to_string()),
                        basic: None,
                    },
                    host_resolution: None,
                },
            ],
        };

        assert_eq!(config.get_all_tenants().len(), 2);
    }

    #[test]
    fn test_config_file_loading() {
        // Create a temporary config file
        let config_content = r#"
server:
  host: "0.0.0.0"
  port: 8080

backend:
  type: "database"
  database:
    type: "postgresql"
    url: "${DB_URL:-postgres://localhost/test}"

tenants:
  - id: 1
    url: "https://test.example.com"
    auth:
      type: "bearer"
      token: "${TEST_TOKEN:-secret_token_123}"
"#;

        std::env::set_var("DB_URL", "postgres://test:pass@localhost/scim");
        std::env::set_var("TEST_TOKEN", "secret_token_123");

        let temp_file = "/tmp/test_config.yaml";
        std::fs::write(temp_file, config_content).unwrap();

        let config = AppConfig::load_from_file(temp_file).unwrap();

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.backend.backend_type, "database");
        assert!(config.backend.database.is_some());
        let db_config = config.backend.database.as_ref().unwrap();
        assert_eq!(db_config.db_type, "postgresql");
        assert_eq!(db_config.url, "postgres://test:pass@localhost/scim");
        assert_eq!(config.tenants.len(), 1);
        assert_eq!(config.tenants[0].url, "https://test.example.com");
        assert_eq!(config.tenants[0].auth.auth_type, "bearer");
        assert_eq!(
            config.tenants[0].auth.token,
            Some("secret_token_123".to_string())
        );

        // Clean up
        std::fs::remove_file(temp_file).unwrap();
        std::env::remove_var("DB_URL");
        std::env::remove_var("TEST_TOKEN");
    }

    #[test]
    fn test_basic_auth_validation() {
        let config = AppConfig {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 3000,
            },
            backend: BackendConfig {
                backend_type: "database".to_string(),
                database: Some(DatabaseConfig {
                    db_type: "sqlite".to_string(),
                    url: "test.db".to_string(),
                    max_connections: 10,
                }),
            },
            tenants: vec![TenantConfig {
                id: 3,
                url: "https://basic.example.com".to_string(),
                auth: AuthConfig {
                    auth_type: "basic".to_string(),
                    token: None,
                    basic: Some(BasicAuthConfig {
                        username: "testuser".to_string(),
                        password: "testpass".to_string(),
                    }),
                },
                host_resolution: None,
            }],
        };

        // Test basic auth config structure
        assert_eq!(config.tenants[0].auth.auth_type, "basic");
        assert!(config.tenants[0].auth.basic.is_some());
        let basic_config = config.tenants[0].auth.basic.as_ref().unwrap();
        assert_eq!(basic_config.username, "testuser");
        assert_eq!(basic_config.password, "testpass");
    }

    #[test]
    fn test_missing_config_file() {
        let result = AppConfig::load_from_file("/nonexistent/path/config.yaml");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Configuration file not found"));
    }

    #[test]
    fn test_default_config() {
        let config = AppConfig::default_config();

        // Check server settings
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 3000);

        // Check backend settings
        assert_eq!(config.backend.backend_type, "database");
        assert!(config.backend.database.is_some());
        let db_config = config.backend.database.as_ref().unwrap();
        assert_eq!(db_config.db_type, "sqlite");
        assert_eq!(db_config.url, ":memory:");
        assert_eq!(db_config.max_connections, 1);

        // Check tenant settings
        assert_eq!(config.tenants.len(), 1);
        let tenant = &config.tenants[0];
        assert_eq!(tenant.id, 1);
        assert_eq!(tenant.url, "/scim/v2");
        assert_eq!(tenant.auth.auth_type, "unauthenticated");
        assert!(tenant.auth.token.is_none());
        assert!(tenant.auth.basic.is_none());

        // Check host resolution settings (should be None for zero-config mode)
        assert!(tenant.host_resolution.is_none());
    }

    #[test]
    fn test_unauthenticated_auth_validation() {
        let config = AppConfig::default_config();

        // Test unauthenticated auth type structure
        assert_eq!(config.tenants[0].auth.auth_type, "unauthenticated");

        // Test resolve_tenant_id_from_path
        assert_eq!(config.resolve_tenant_id_from_path("1"), Some(1));
        assert_eq!(config.resolve_tenant_id_from_path("invalid"), None);
    }

    #[test]
    fn test_invalid_yaml() {
        let invalid_yaml = "invalid: yaml: content: [";
        let temp_file = "/tmp/invalid_config.yaml";
        std::fs::write(temp_file, invalid_yaml).unwrap();

        let result = AppConfig::load_from_file(temp_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse config file"));

        std::fs::remove_file(temp_file).unwrap();
    }

    #[test]
    fn test_empty_tenants() {
        let config_content = r#"
server:
  host: "127.0.0.1"
  port: 3000

backend:
  type: "database"
  database:
    type: "sqlite"
    url: "test.db"

tenants: []
"#;

        let temp_file = "/tmp/empty_tenants_config.yaml";
        std::fs::write(temp_file, config_content).unwrap();

        let result = AppConfig::load_from_file(temp_file);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("must contain at least one tenant"));

        std::fs::remove_file(temp_file).unwrap();
    }

    #[test]
    fn test_relative_url_with_host_resolution() {
        let config_content = r#"
server:
  host: "127.0.0.1"
  port: 3000

backend:
  type: "database"
  database:
    type: "sqlite"
    url: "test.db"

tenants:
  - id: 1
    url: "/scim/tenant1"
    host_resolution:
      type: "host"
    auth:
      type: "bearer"
      token: "test_token_123"
"#;

        let temp_file = "/tmp/relative_url_config.yaml";
        std::fs::write(temp_file, config_content).unwrap();

        let config = AppConfig::load_from_file(temp_file).unwrap();

        assert_eq!(config.tenants.len(), 1);
        assert_eq!(config.tenants[0].url, "/scim/tenant1");
        assert!(config.tenants[0].host_resolution.is_some());

        let host_resolution = config.tenants[0].host_resolution.as_ref().unwrap();
        assert_eq!(host_resolution.resolution_type, HostResolutionType::Host);

        // Test request matching
        let request_info = RequestInfo {
            path: "/scim/tenant1/v2/Users",
            host_header: Some("example.com"),
            forwarded_header: None,
            x_forwarded_proto: None,
            x_forwarded_host: None,
            x_forwarded_port: None,
            client_ip: None,
        };

        let resolved = config.tenants[0].matches_request(&request_info);
        assert!(resolved.is_some());

        let resolved_url = resolved.unwrap();
        assert_eq!(resolved_url.scheme, "https");
        assert_eq!(resolved_url.host, "example.com");
        assert_eq!(resolved_url.path, "/scim/tenant1/v2/Users");

        std::fs::remove_file(temp_file).unwrap();
    }

    #[test]
    fn test_forwarded_header_resolution() {
        let config = AppConfig {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 3000,
            },
            backend: BackendConfig {
                backend_type: "database".to_string(),
                database: Some(DatabaseConfig {
                    db_type: "sqlite".to_string(),
                    url: "test.db".to_string(),
                    max_connections: 10,
                }),
            },
            tenants: vec![TenantConfig {
                id: 4,
                url: "/api/scim".to_string(),
                auth: AuthConfig {
                    auth_type: "bearer".to_string(),
                    token: Some("forwarded_token".to_string()),
                    basic: None,
                },
                host_resolution: Some(HostResolutionConfig {
                    resolution_type: HostResolutionType::Forwarded,
                    trusted_proxies: Some(vec!["192.168.1.100".to_string()]),
                }),
            }],
        };

        let request_info = RequestInfo {
            path: "/api/scim/v2/Users",
            host_header: Some("localhost:3000"),
            forwarded_header: Some("for=192.0.2.60;proto=https;host=api.example.com:443"),
            x_forwarded_proto: None,
            x_forwarded_host: None,
            x_forwarded_port: None,
            client_ip: None,
        };

        let (tenant, resolved_url) = config.find_tenant_by_request(&request_info).unwrap();

        assert_eq!(tenant.url, "/api/scim");
        assert_eq!(resolved_url.scheme, "https");
        assert_eq!(resolved_url.host, "api.example.com");
        assert_eq!(resolved_url.port, Some(443));
        assert_eq!(resolved_url.path, "/api/scim/v2/Users");
    }

    #[test]
    fn test_x_forwarded_headers_resolution() {
        let config = AppConfig {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 3000,
            },
            backend: BackendConfig {
                backend_type: "database".to_string(),
                database: Some(DatabaseConfig {
                    db_type: "sqlite".to_string(),
                    url: "test.db".to_string(),
                    max_connections: 10,
                }),
            },
            tenants: vec![TenantConfig {
                id: 5,
                url: "/scim".to_string(),
                auth: AuthConfig {
                    auth_type: "basic".to_string(),
                    token: None,
                    basic: Some(BasicAuthConfig {
                        username: "xfwd_user".to_string(),
                        password: "xfwd_pass".to_string(),
                    }),
                },
                host_resolution: Some(HostResolutionConfig {
                    resolution_type: HostResolutionType::XForwarded,
                    trusted_proxies: Some(vec!["172.16.0.0/12".to_string()]),
                }),
            }],
        };

        let request_info = RequestInfo {
            path: "/scim/v2/Groups",
            host_header: Some("localhost:3000"),
            forwarded_header: None,
            x_forwarded_proto: Some("https"),
            x_forwarded_host: Some("secure.example.com"),
            x_forwarded_port: Some("443"),
            client_ip: None,
        };

        let (tenant, resolved_url) = config.find_tenant_by_request(&request_info).unwrap();

        assert_eq!(tenant.url, "/scim");
        assert_eq!(resolved_url.scheme, "https");
        assert_eq!(resolved_url.host, "secure.example.com");
        assert_eq!(resolved_url.port, Some(443));
        assert_eq!(resolved_url.path, "/scim/v2/Groups");
    }
}
