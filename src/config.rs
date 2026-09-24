use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub backend: BackendConfig,
    pub tenants: Vec<TenantConfig>,
    #[serde(default)]
    pub compatibility: CompatibilityConfig,
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
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub host_resolution: Option<HostResolutionConfig>,
    pub auth: AuthConfig,
    #[serde(default)]
    pub override_base_url: Option<String>,
    #[serde(default)]
    pub custom_endpoints: Vec<CustomEndpoint>,
    #[serde(default)]
    pub compatibility: Option<CompatibilityOverride>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HostResolutionConfig {
    #[serde(rename = "type")]
    pub resolution_type: HostResolutionType,
    #[serde(default)]
    pub trusted_proxies: Option<Vec<String>>,
}

impl HostResolutionConfig {
    /// Check if a client IP is trusted for proxy headers
    pub fn is_trusted_proxy(&self, client_ip: IpAddr) -> bool {
        match &self.trusted_proxies {
            // If no trusted_proxies configured, trust all (for backward compatibility)
            None => true,
            Some(trusted_ranges) => {
                // Check if client IP matches any configured CIDR range
                for range_str in trusted_ranges {
                    if let Ok(range) = IpNet::from_str(range_str) {
                        if range.contains(&client_ip) {
                            return true;
                        }
                    } else if let Ok(ip) = IpAddr::from_str(range_str) {
                        // Handle single IP addresses (without CIDR notation)
                        if ip == client_ip {
                            return true;
                        }
                    }
                }
                false
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HostResolutionType {
    Host,
    Forwarded,
    #[serde(rename = "xforwarded")]
    XForwarded,
}

#[derive(Debug, Clone)]
pub struct ResolvedUrl {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    #[allow(dead_code)]
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

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityConfig {
    #[serde(default = "default_meta_datetime_format")]
    pub meta_datetime_format: String,
    #[serde(default = "default_show_empty_groups_members")]
    pub show_empty_groups_members: bool,
    #[serde(default = "default_include_user_groups")]
    pub include_user_groups: bool,
    #[serde(default = "default_support_group_members_filter")]
    pub support_group_members_filter: bool,
    #[serde(default = "default_support_group_displayname_filter")]
    pub support_group_displayname_filter: bool,
    #[serde(default = "default_support_patch_replace_empty_array")]
    pub support_patch_replace_empty_array: bool,
    #[serde(default = "default_support_patch_replace_empty_value")]
    pub support_patch_replace_empty_value: bool,
}

fn default_meta_datetime_format() -> String {
    "rfc3339".to_string()
}

fn default_show_empty_groups_members() -> bool {
    true // true: show empty arrays as [], false: omit empty arrays from response
}

fn default_include_user_groups() -> bool {
    true // true: include groups field in User responses, false: omit groups field entirely
}

fn default_support_group_members_filter() -> bool {
    true // true: support filtering Groups by members.value, false: reject such filters
}

fn default_support_group_displayname_filter() -> bool {
    true // true: support filtering Groups by displayName, false: reject such filters
}

fn default_support_patch_replace_empty_array() -> bool {
    true // true: support op=replace with value=[] to clear multi-valued attributes, false: reject such operations
}

fn default_support_patch_replace_empty_value() -> bool {
    false // false: reject op=replace with value=[{"value":""}] pattern, true: allow this non-standard clearing method
}

impl Default for CompatibilityConfig {
    fn default() -> Self {
        Self {
            meta_datetime_format: default_meta_datetime_format(),
            show_empty_groups_members: default_show_empty_groups_members(),
            include_user_groups: default_include_user_groups(),
            support_group_members_filter: default_support_group_members_filter(),
            support_group_displayname_filter: default_support_group_displayname_filter(),
            support_patch_replace_empty_array: default_support_patch_replace_empty_array(),
            support_patch_replace_empty_value: default_support_patch_replace_empty_value(),
        }
    }
}

/// Tenant-level partial override of the global `compatibility:` block.
///
/// Every field is optional: an absent field inherits the global value
/// rather than reverting to this struct's own default. This is the whole
/// point of having a distinct type from `CompatibilityConfig` -- see
/// `AppConfig::get_effective_compatibility`, which merges a tenant's
/// override field-by-field over the global `CompatibilityConfig` instead
/// of replacing it wholesale.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_datetime_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_empty_groups_members: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_user_groups: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_group_members_filter: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_group_displayname_filter: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_patch_replace_empty_array: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_patch_replace_empty_value: Option<bool>,
}

impl CompatibilityOverride {
    /// Field-level merge: every `Some` in `self` wins, every `None`
    /// inherits the corresponding value from `base`.
    pub fn apply_to(&self, base: &CompatibilityConfig) -> CompatibilityConfig {
        CompatibilityConfig {
            meta_datetime_format: self
                .meta_datetime_format
                .clone()
                .unwrap_or_else(|| base.meta_datetime_format.clone()),
            show_empty_groups_members: self
                .show_empty_groups_members
                .unwrap_or(base.show_empty_groups_members),
            include_user_groups: self.include_user_groups.unwrap_or(base.include_user_groups),
            support_group_members_filter: self
                .support_group_members_filter
                .unwrap_or(base.support_group_members_filter),
            support_group_displayname_filter: self
                .support_group_displayname_filter
                .unwrap_or(base.support_group_displayname_filter),
            support_patch_replace_empty_array: self
                .support_patch_replace_empty_array
                .unwrap_or(base.support_patch_replace_empty_array),
            support_patch_replace_empty_value: self
                .support_patch_replace_empty_value
                .unwrap_or(base.support_patch_replace_empty_value),
        }
    }
}

/// Lets a caller (e.g. a test) express "override every field" from a full
/// `CompatibilityConfig`, by wrapping each field in `Some`.
impl From<CompatibilityConfig> for CompatibilityOverride {
    fn from(config: CompatibilityConfig) -> Self {
        Self {
            meta_datetime_format: Some(config.meta_datetime_format),
            show_empty_groups_members: Some(config.show_empty_groups_members),
            include_user_groups: Some(config.include_user_groups),
            support_group_members_filter: Some(config.support_group_members_filter),
            support_group_displayname_filter: Some(config.support_group_displayname_filter),
            support_patch_replace_empty_array: Some(config.support_patch_replace_empty_array),
            support_patch_replace_empty_value: Some(config.support_patch_replace_empty_value),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CustomEndpoint {
    pub path: String,
    pub response: String,
    #[serde(default = "default_status_code")]
    pub status_code: u16,
    #[serde(default = "default_content_type")]
    pub content_type: String,
    /// Optional authentication override for this specific endpoint
    /// If not specified, inherits tenant's authentication settings
    pub auth: Option<AuthConfig>,
}

fn default_status_code() -> u16 {
    200
}

fn default_content_type() -> String {
    "application/json".to_string()
}

impl CustomEndpoint {
    /// Get the effective authentication config for this endpoint
    /// Returns the endpoint's auth config if specified, otherwise the tenant's auth config
    pub fn effective_auth_config<'a>(&'a self, tenant_auth: &'a AuthConfig) -> &'a AuthConfig {
        self.auth.as_ref().unwrap_or(tenant_auth)
    }
}

impl TenantConfig {
    /// Compute the route path prefix this tenant registers its SCIM routes
    /// under (`{base}/Users`, `{base}/Groups`, ...).
    ///
    /// This MUST mirror `app::build_scim_router` exactly -- that function
    /// calls this method instead of re-deriving the prefix itself, so the
    /// two can never drift. When `path` is an absolute `http(s)://` URL,
    /// only the URL's path component is used as the route prefix (matching
    /// historical configs that wrote a full origin in `path`); otherwise
    /// `path` is used verbatim with any trailing slash trimmed.
    pub fn route_base_path(&self) -> String {
        if self.path.starts_with("http://") || self.path.starts_with("https://") {
            if let Ok(url) = url::Url::parse(&self.path) {
                url.path().trim_end_matches('/').to_string()
            } else {
                "/scim".to_string() // fallback, matches build_scim_router's historical behavior
            }
        } else {
            self.path.trim_end_matches('/').to_string()
        }
    }

    /// Build the base URL for this tenant based on configuration and request
    /// - If override_base_url is set: use override_base_url + path (forced override)
    /// - If override_base_url is unset: use host resolution result + path (auto-constructed)
    pub fn build_base_url(&self, request_info: &RequestInfo) -> String {
        if let Some(override_url) = &self.override_base_url {
            // Use configured override_base_url + path (forced override)
            format!("{}{}", override_url.trim_end_matches('/'), &self.path)
        } else {
            // Auto-build from host resolution + path
            if let Some(host) = &self.host {
                // Host-specific tenant: use host resolution
                let resolved = if let Some(host_resolution) = &self.host_resolution {
                    self.resolve_url_from_request_with_resolution(request_info, host_resolution)
                } else {
                    // Default to Host header resolution
                    self.resolve_from_host_header(request_info)
                };

                if let Some(resolved_url) = resolved {
                    let port_suffix = if let Some(port) = resolved_url.port {
                        if (resolved_url.scheme == "https" && port != 443)
                            || (resolved_url.scheme == "http" && port != 80)
                        {
                            format!(":{}", port)
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };

                    format!(
                        "{}://{}{}{}",
                        resolved_url.scheme, resolved_url.host, port_suffix, &self.path
                    )
                } else {
                    // Fallback to http + host + path
                    format!("http://{}{}", host, &self.path)
                }
            } else {
                // Path-only tenant: use http + host header + path
                let host = request_info.host_header.unwrap_or("localhost");
                format!("http://{}{}", host, &self.path)
            }
        }
    }

    /// Build the base URL without path for this tenant - returns just protocol://host:port
    /// Used for constructing individual resource URLs where path is added separately
    #[allow(dead_code)]
    pub fn build_base_url_no_path(&self, request_info: &RequestInfo) -> String {
        if let Some(override_url) = &self.override_base_url {
            // Use configured override_base_url without path
            override_url.trim_end_matches('/').to_string()
        } else {
            // Auto-build from host resolution without path
            if let Some(host) = &self.host {
                // Host-specific tenant: use host resolution
                let resolved = if let Some(host_resolution) = &self.host_resolution {
                    self.resolve_url_from_request_with_resolution(request_info, host_resolution)
                } else {
                    // Default to Host header resolution
                    self.resolve_from_host_header(request_info)
                };

                if let Some(resolved_url) = resolved {
                    let port_suffix = if let Some(port) = resolved_url.port {
                        if (resolved_url.scheme == "https" && port != 443)
                            || (resolved_url.scheme == "http" && port != 80)
                        {
                            format!(":{}", port)
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };

                    format!(
                        "{}://{}{}",
                        resolved_url.scheme, resolved_url.host, port_suffix
                    )
                } else {
                    // Fallback to http + host
                    format!("http://{}", host)
                }
            } else {
                // Path-only tenant: use http + host header
                let host = request_info.host_header.unwrap_or("localhost");
                format!("http://{}", host)
            }
        }
    }
    /// Check if this tenant configuration matches the given request for SCIM endpoints
    pub fn matches_request(&self, request_info: &RequestInfo) -> Option<ResolvedUrl> {
        // First check if path matches
        if !request_info.path.starts_with(&self.path) {
            return None;
        }

        // If host is configured, check host matching
        if let Some(expected_host) = &self.host {
            // Determine how to resolve the host based on host_resolution config
            let resolved = if let Some(host_resolution) = &self.host_resolution {
                self.resolve_url_from_request_with_resolution(request_info, host_resolution)?
            } else {
                // Default to Host header resolution if host is specified but no resolution config
                self.resolve_from_host_header(request_info)?
            };

            // Check if the resolved host matches the expected host
            if &resolved.host != expected_host {
                return None;
            }

            Some(resolved)
        } else {
            // No host config - path matching is sufficient
            Some(ResolvedUrl {
                scheme: "http".to_string(),
                host: request_info.host_header.unwrap_or("localhost").to_string(),
                port: None,
                path: request_info.path.to_string(),
            })
        }
    }

    /// Check if this tenant has a custom endpoint matching the given path
    pub fn matches_custom_endpoint(
        &self,
        request_info: &RequestInfo,
    ) -> Option<(&CustomEndpoint, ResolvedUrl)> {
        for endpoint in &self.custom_endpoints {
            if endpoint.path == request_info.path {
                // If this tenant has host config, verify the host matches
                if let Some(expected_host) = &self.host {
                    // Determine how to resolve the host based on host_resolution config
                    let resolved = if let Some(host_resolution) = &self.host_resolution {
                        self.resolve_url_from_request_with_resolution(request_info, host_resolution)
                    } else {
                        // Default to Host header resolution if host is specified but no resolution config
                        self.resolve_from_host_header(request_info)
                    };

                    if let Some(resolved) = resolved {
                        // Check if the resolved host matches the expected host
                        if &resolved.host == expected_host {
                            return Some((
                                endpoint,
                                ResolvedUrl {
                                    scheme: resolved.scheme,
                                    host: resolved.host,
                                    port: resolved.port,
                                    path: endpoint.path.clone(),
                                },
                            ));
                        }
                    }
                } else {
                    // No host config - custom endpoint matches
                    return Some((
                        endpoint,
                        ResolvedUrl {
                            scheme: "http".to_string(), // Default for non-host tenants
                            host: request_info.host_header.unwrap_or("localhost").to_string(),
                            port: None,
                            path: endpoint.path.clone(),
                        },
                    ));
                }
            }
        }
        None
    }

    /// Resolve URL from request using configured host resolution method
    fn resolve_url_from_request_with_resolution(
        &self,
        request_info: &RequestInfo,
        host_resolution: &HostResolutionConfig,
    ) -> Option<ResolvedUrl> {
        match host_resolution.resolution_type {
            HostResolutionType::Host => self.resolve_from_host_header(request_info),
            HostResolutionType::Forwarded => {
                self.resolve_from_forwarded_header(request_info, host_resolution)
            }
            HostResolutionType::XForwarded => {
                self.resolve_from_x_forwarded_headers(request_info, host_resolution)
            }
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
            scheme: "http".to_string(), // Host mode: HTTP for development/testing
            host,
            port,
            path: request_info.path.to_string(),
        })
    }

    /// Resolve URL from RFC 7239 Forwarded header
    fn resolve_from_forwarded_header(
        &self,
        request_info: &RequestInfo,
        host_resolution: &HostResolutionConfig,
    ) -> Option<ResolvedUrl> {
        let forwarded_header = request_info.forwarded_header?;

        // Check trusted_proxies if configured
        if let Some(client_ip) = request_info.client_ip {
            if !host_resolution.is_trusted_proxy(client_ip) {
                // Client IP is not in trusted_proxies list, reject the request
                tracing::warn!(
                    "Rejecting Forwarded header from untrusted proxy: {}",
                    client_ip
                );
                return None;
            }
        }

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
    fn resolve_from_x_forwarded_headers(
        &self,
        request_info: &RequestInfo,
        host_resolution: &HostResolutionConfig,
    ) -> Option<ResolvedUrl> {
        // Check trusted_proxies if configured
        if let Some(client_ip) = request_info.client_ip {
            if !host_resolution.is_trusted_proxy(client_ip) {
                // Client IP is not in trusted_proxies list, reject the request
                tracing::warn!(
                    "Rejecting X-Forwarded headers from untrusted proxy: {}",
                    client_ip
                );
                return None;
            }
        }

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

        app_config.validate().map_err(|e| e.to_string())?;

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
            compatibility: CompatibilityConfig::default(),
            tenants: vec![TenantConfig {
                id: 1,
                path: "/scim/v2".to_string(),
                host: None,            // No host requirement for zero-config mode
                host_resolution: None, // No host resolution for zero-config mode
                auth: AuthConfig {
                    auth_type: "unauthenticated".to_string(),
                    token: None,
                    basic: None,
                },
                override_base_url: None, // Use auto-constructed URL for zero-config mode
                custom_endpoints: vec![],
                compatibility: None, // Use global compatibility settings
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
    #[allow(dead_code)]
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
        // First try to find a custom endpoint match
        for tenant in &self.tenants {
            if let Some((_, resolved_url)) = tenant.matches_custom_endpoint(request_info) {
                return Some((tenant, resolved_url));
            }
        }

        // If no custom endpoint matches, try regular SCIM endpoints
        for tenant in &self.tenants {
            if let Some(resolved_url) = tenant.matches_request(request_info) {
                return Some((tenant, resolved_url));
            }
        }

        None
    }

    /// Find custom endpoint that matches the given path
    /// Note: This method is deprecated in favor of find_tenant_by_request which handles both SCIM and custom endpoints.
    pub fn find_custom_endpoint(&self, path: &str) -> Option<(&TenantConfig, &CustomEndpoint)> {
        for tenant in &self.tenants {
            for endpoint in &tenant.custom_endpoints {
                if path == endpoint.path {
                    return Some((tenant, endpoint));
                }
            }
        }
        None
    }

    /// Get effective compatibility configuration for a tenant
    ///
    /// The tenant's `compatibility` block (if present) is merged
    /// field-by-field over the global `compatibility` block: a field the
    /// tenant left unspecified inherits the global value, and only fields
    /// the tenant explicitly set are overridden. If the tenant has no
    /// `compatibility` block at all, the global config applies unchanged.
    pub fn get_effective_compatibility(&self, tenant_id: u32) -> CompatibilityConfig {
        if let Some(tenant) = self.tenants.iter().find(|t| t.id == tenant_id) {
            if let Some(ref tenant_override) = tenant.compatibility {
                return tenant_override.apply_to(&self.compatibility);
            }
        }
        self.compatibility.clone()
    }
}

/// Every `auth.type` value `src/auth.rs`'s `validate_authentication` matches
/// on. Kept as the single source of truth for "what auth types exist" so
/// validation can never drift from what the middleware actually accepts.
const VALID_AUTH_TYPES: [&str; 4] = ["unauthenticated", "bearer", "token", "basic"];

/// Every `meta_datetime_format` value `src/utils.rs` recognizes.
const VALID_META_DATETIME_FORMATS: [&str; 2] = ["rfc3339", "epoch"];

/// The fixed set of GET routes `app::build_scim_router` registers under
/// every tenant's `route_base_path()`. A `custom_endpoints` entry (which is
/// also always a GET route, and -- critically -- is registered in a single
/// router shared by *every* tenant, not scoped to its own tenant) that
/// collides with one of these literal paths panics the server at startup
/// exactly like a duplicate tenant path does.
const SCIM_GET_ROUTE_SUFFIXES: [&str; 7] = [
    "/ServiceProviderConfig",
    "/Schemas",
    "/ResourceTypes",
    "/Users",
    "/Users/.search",
    "/Groups",
    "/Groups/.search",
];

/// All problems found by [`AppConfig::validate`] in one pass. `Display`
/// renders one message per line.
#[derive(Debug)]
pub struct ConfigValidationErrors(pub Vec<String>);

impl std::fmt::Display for ConfigValidationErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, e) in self.0.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{}", e)?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigValidationErrors {}

/// Validate a single `auth:` block, appending every problem found to
/// `errors`. `context` names where this auth block lives (e.g. `"tenant id
/// 1"` or `"tenant id 1's custom endpoint \"/health\""`) so each message is
/// self-locating.
fn validate_auth_config(auth: &AuthConfig, context: &str, errors: &mut Vec<String>) {
    if !VALID_AUTH_TYPES.contains(&auth.auth_type.as_str()) {
        errors.push(format!(
            "{}: auth.type {:?} is invalid; must be one of {:?}",
            context, auth.auth_type, VALID_AUTH_TYPES
        ));
        return;
    }

    match auth.auth_type.as_str() {
        "bearer" | "token" => match &auth.token {
            Some(t) if !t.is_empty() => {}
            Some(_) => errors.push(format!(
                "{}: auth.type \"{}\" has an empty token, which can never authenticate a request; set a non-empty token",
                context, auth.auth_type
            )),
            None => errors.push(format!(
                "{}: auth.type \"{}\" requires a token",
                context, auth.auth_type
            )),
        },
        "basic" => match &auth.basic {
            Some(_) => {}
            None => errors.push(format!(
                "{}: auth.type \"basic\" requires a basic: block with username and password",
                context
            )),
        },
        _ => {}
    }
}

impl AppConfig {
    /// Validate this configuration, collecting every problem found rather
    /// than stopping at the first. Called from `load_from_file` so normal
    /// startup benefits, and also exposed for the `--validate` CLI flag.
    pub fn validate(&self) -> Result<(), ConfigValidationErrors> {
        let mut errors = Vec::new();

        self.validate_backend(&mut errors);
        self.validate_tenant_ids(&mut errors);
        self.validate_tenant_paths(&mut errors);

        for tenant in &self.tenants {
            validate_auth_config(
                &tenant.auth,
                &format!("tenant id {}", tenant.id),
                &mut errors,
            );
            self.validate_tenant_host_resolution(tenant, &mut errors);
            self.validate_tenant_override_base_url(tenant, &mut errors);
            self.validate_tenant_custom_endpoints(tenant, &mut errors);
        }

        self.validate_custom_endpoints_global(&mut errors);
        self.validate_meta_datetime_formats(&mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigValidationErrors(errors))
        }
    }

    /// Rule: `backend.type` must be `"database"`, `backend.database` must be
    /// present, and `backend.database.type` must be `"postgresql"` or
    /// `"sqlite"`. `setup_backend` (in `main.rs`) checks the same things
    /// today, but only *after* `load_from_file` returns -- and only for the
    /// value it happens to hit first. Validating here catches every problem
    /// up front; `setup_backend`'s own check is left in place as a
    /// defensive fallback for callers that construct `AppConfig` without
    /// going through `load_from_file`/`validate`.
    fn validate_backend(&self, errors: &mut Vec<String>) {
        if self.backend.backend_type != "database" {
            errors.push(format!(
                "backend.type {:?} is unsupported; must be \"database\"",
                self.backend.backend_type
            ));
            return;
        }

        match &self.backend.database {
            None => errors.push(
                "backend.database block is required when backend.type is \"database\"".to_string(),
            ),
            Some(db) => {
                if db.db_type != "postgresql" && db.db_type != "sqlite" {
                    errors.push(format!(
                        "backend.database.type {:?} is unsupported; must be \"postgresql\" or \"sqlite\"",
                        db.db_type
                    ));
                }
            }
        }
    }

    /// Rule: tenant `id` values must be unique.
    ///
    /// `resolve_tenant_id_from_path` itself only uses `.any(|t| t.id ==
    /// ..)`, so it isn't directly broken by a duplicate id. The actual
    /// damage happens one layer up: `AppConfig::find_tenant_by_request`
    /// (used by `auth.rs`'s `resolve_tenant_id_from_request`) matches a
    /// request by *path*, so it correctly returns the *second* tenant's
    /// struct and thus its id -- but `auth.rs`'s own tenant lookup right
    /// after that, and `get_effective_compatibility`, both do `.find(|t|
    /// t.id == id)`, which returns the *first* tenant with that id. The
    /// result isn't "unreachable" -- it's worse: requests that match the
    /// second tenant's path get authenticated with the first tenant's
    /// `auth` config, resolved with the first tenant's base URL and
    /// compatibility settings, and (since `setup_backend` calls
    /// `init_tenant(id)` once per tenant *entry*, not per unique id)
    /// written into the first tenant's already-initialized tables --
    /// silent cross-tenant data leakage, not a dead/unreachable tenant.
    fn validate_tenant_ids(&self, errors: &mut Vec<String>) {
        let mut seen = std::collections::HashSet::new();
        for tenant in &self.tenants {
            if !seen.insert(tenant.id) {
                errors.push(format!(
                    "duplicate tenant id {}: tenant ids must be unique (requests matching the later tenant's path are authenticated and served using the first tenant's auth, base URL, compatibility settings, and database tables -- silent cross-tenant leakage, not just an unreachable tenant)",
                    tenant.id
                ));
            }
        }
    }

    /// Rule: tenants must not resolve to the same route path.
    /// `app::build_scim_router` registers `{base}/Users`, `{base}/Groups`,
    /// etc. for every tenant's `TenantConfig::route_base_path()`; two
    /// tenants resolving to the same base panics the server at startup
    /// with axum's "Overlapping method route", *after* `setup_backend` has
    /// already created that tenant's database file and tables.
    fn validate_tenant_paths(&self, errors: &mut Vec<String>) {
        let mut seen: std::collections::HashMap<String, (u32, String)> =
            std::collections::HashMap::new();
        for tenant in &self.tenants {
            let normalized = tenant.route_base_path();
            if let Some((first_id, first_path)) = seen.get(&normalized) {
                errors.push(format!(
                    "tenant id {} (path {:?}) and tenant id {} (path {:?}) both resolve to route path {:?}; this panics the server at startup with axum's \"Overlapping method route\" (after tables for both tenants have already been created)",
                    first_id, first_path, tenant.id, tenant.path, normalized
                ));
            } else {
                seen.insert(normalized, (tenant.id, tenant.path.clone()));
            }
        }
    }

    /// Rule: `host_resolution.trusted_proxies` entries must parse as either
    /// an `IpAddr` or an `IpNet`, using the exact same parsing
    /// `HostResolutionConfig::is_trusted_proxy` performs at request time.
    /// Today, an unparsable entry is silently skipped by `is_trusted_proxy`
    /// (it just never matches), so that proxy is quietly never trusted and
    /// nothing is ever logged -- this turns that into a load-time error.
    fn validate_tenant_host_resolution(&self, tenant: &TenantConfig, errors: &mut Vec<String>) {
        if let Some(host_resolution) = &tenant.host_resolution {
            if let Some(trusted_proxies) = &host_resolution.trusted_proxies {
                for entry in trusted_proxies {
                    let valid = IpNet::from_str(entry).is_ok() || IpAddr::from_str(entry).is_ok();
                    if !valid {
                        errors.push(format!(
                            "tenant id {}: host_resolution.trusted_proxies entry {:?} is not a valid IP address or CIDR range",
                            tenant.id, entry
                        ));
                    }
                }
            }
        }
    }

    /// Rule: `override_base_url`, when present, must parse as an absolute
    /// http/https URL (reusing the `url` crate already used elsewhere in
    /// this codebase, rather than hand-rolling URL validation).
    fn validate_tenant_override_base_url(&self, tenant: &TenantConfig, errors: &mut Vec<String>) {
        if let Some(url_str) = &tenant.override_base_url {
            match url::Url::parse(url_str) {
                Ok(parsed) if parsed.scheme() == "http" || parsed.scheme() == "https" => {}
                Ok(parsed) => errors.push(format!(
                    "tenant id {}: override_base_url {:?} has unsupported scheme {:?}; must be \"http\" or \"https\"",
                    tenant.id, url_str, parsed.scheme()
                )),
                Err(e) => errors.push(format!(
                    "tenant id {}: override_base_url {:?} is not a valid absolute URL: {}",
                    tenant.id, url_str, e
                )),
            }
        }
    }

    /// Rule (tenant-local half): a tenant's own `custom_endpoints` must not
    /// contain duplicate `path` values, and each endpoint's optional `auth:`
    /// override (see `CustomEndpoint::effective_auth_config`) is validated
    /// the same way tenant-level auth is.
    fn validate_tenant_custom_endpoints(&self, tenant: &TenantConfig, errors: &mut Vec<String>) {
        let mut seen = std::collections::HashSet::new();
        for endpoint in &tenant.custom_endpoints {
            if !seen.insert(endpoint.path.clone()) {
                errors.push(format!(
                    "tenant id {}: duplicate custom_endpoints path {:?}",
                    tenant.id, endpoint.path
                ));
            }
            if let Some(auth) = &endpoint.auth {
                validate_auth_config(
                    auth,
                    &format!(
                        "tenant id {}'s custom endpoint {:?}",
                        tenant.id, endpoint.path
                    ),
                    errors,
                );
            }
        }
    }

    /// Rule (global half): `app::build_custom_router` registers every
    /// tenant's `custom_endpoints` into a *single, shared* router keyed only
    /// by `endpoint.path` -- it is NOT scoped per tenant. That means a
    /// `custom_endpoints` path colliding with another tenant's
    /// `custom_endpoints` path, or with any tenant's built-in SCIM GET
    /// route (`{base}/Users`, `{base}/ServiceProviderConfig`, ...), panics
    /// the server at startup with axum's "Overlapping method route" --
    /// verified empirically against this build, not just inferred from
    /// reading the router code.
    fn validate_custom_endpoints_global(&self, errors: &mut Vec<String>) {
        let mut reserved_scim_routes: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for tenant in &self.tenants {
            let base = tenant.route_base_path();
            for suffix in SCIM_GET_ROUTE_SUFFIXES {
                reserved_scim_routes.insert(format!("{}{}", base, suffix), tenant.id);
            }
        }

        let mut seen_custom_paths: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for tenant in &self.tenants {
            for endpoint in &tenant.custom_endpoints {
                if let Some(&owner_id) = reserved_scim_routes.get(&endpoint.path) {
                    errors.push(format!(
                        "tenant id {}: custom_endpoints path {:?} collides with tenant id {}'s built-in SCIM GET route at the same path; this panics the server at startup with axum's \"Overlapping method route\"",
                        tenant.id, endpoint.path, owner_id
                    ));
                }

                match seen_custom_paths.get(&endpoint.path) {
                    Some(&first_owner) if first_owner != tenant.id => {
                        errors.push(format!(
                            "tenant id {} and tenant id {} both register custom_endpoints path {:?}; custom endpoint routes are shared across all tenants (not scoped per tenant), so this panics the server at startup with axum's \"Overlapping method route\"",
                            first_owner, tenant.id, endpoint.path
                        ));
                    }
                    Some(_) => {
                        // Same-tenant duplicate, already reported by
                        // `validate_tenant_custom_endpoints`.
                    }
                    None => {
                        seen_custom_paths.insert(endpoint.path.clone(), tenant.id);
                    }
                }
            }
        }
    }

    /// Reject any `meta_datetime_format` value other than the two
    /// recognized spellings ("rfc3339", "epoch"). The comparison is
    /// exact/case-sensitive, matching the consumer in `utils.rs`
    /// (`if format_type == "epoch"`), so config authors get an
    /// unambiguous, single accepted spelling for each value instead of a
    /// value silently falling through to rfc3339.
    ///
    /// Validates both the global `compatibility:` block and every tenant's
    /// `compatibility:` override (when present).
    fn validate_meta_datetime_formats(&self, errors: &mut Vec<String>) {
        fn check(value: &str, where_: &str, errors: &mut Vec<String>) {
            if !VALID_META_DATETIME_FORMATS.contains(&value) {
                errors.push(format!(
                    "Invalid meta_datetime_format {:?} in {}: must be one of {:?}",
                    value, where_, VALID_META_DATETIME_FORMATS
                ));
            }
        }

        check(
            &self.compatibility.meta_datetime_format,
            "the global compatibility block",
            errors,
        );

        for tenant in &self.tenants {
            if let Some(ref tenant_override) = tenant.compatibility {
                if let Some(ref value) = tenant_override.meta_datetime_format {
                    check(
                        value,
                        &format!("tenant id {}'s compatibility block", tenant.id),
                        errors,
                    );
                }
            }
        }
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
            compatibility: CompatibilityConfig::default(),
            tenants: vec![
                TenantConfig {
                    id: 1,
                    path: "https://scim.example.com".to_string(),
                    host: None,
                    host_resolution: None,
                    auth: AuthConfig {
                        auth_type: "bearer".to_string(),
                        token: Some("example_token_123".to_string()),
                        basic: None,
                    },
                    override_base_url: None,
                    custom_endpoints: vec![],
                    compatibility: None,
                },
                TenantConfig {
                    id: 2,
                    path: "https://acme.yourcompany.com/scim".to_string(),
                    host: None,
                    host_resolution: None,
                    auth: AuthConfig {
                        auth_type: "bearer".to_string(),
                        token: Some("acme_scim_token_456".to_string()),
                        basic: None,
                    },
                    override_base_url: None,
                    custom_endpoints: vec![],
                    compatibility: None,
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
    path: "https://test.example.com"
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
        assert_eq!(config.tenants[0].path, "https://test.example.com");
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
            compatibility: CompatibilityConfig::default(),
            tenants: vec![TenantConfig {
                id: 3,
                path: "https://basic.example.com".to_string(),
                host: None,
                host_resolution: None,
                auth: AuthConfig {
                    auth_type: "basic".to_string(),
                    token: None,
                    basic: Some(BasicAuthConfig {
                        username: "testuser".to_string(),
                        password: "testpass".to_string(),
                    }),
                },
                override_base_url: None,
                custom_endpoints: vec![],
                compatibility: None,
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
        assert_eq!(tenant.path, "/scim/v2");
        assert_eq!(tenant.auth.auth_type, "unauthenticated");
        assert!(tenant.auth.token.is_none());
        assert!(tenant.auth.basic.is_none());

        // Check host resolution settings (should be None for zero-config mode)
        assert!(tenant.host.is_none());
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
    fn test_relative_path_with_host() {
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
    path: "/scim/tenant1"
    host: "example.com"
    host_resolution:
      type: "host"
    auth:
      type: "bearer"
      token: "test_token_123"
"#;

        let temp_file = "/tmp/relative_path_config.yaml";
        std::fs::write(temp_file, config_content).unwrap();

        let config = AppConfig::load_from_file(temp_file).unwrap();

        assert_eq!(config.tenants.len(), 1);
        assert_eq!(config.tenants[0].path, "/scim/tenant1");
        assert_eq!(config.tenants[0].host, Some("example.com".to_string()));
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
        assert_eq!(resolved_url.scheme, "http"); // Host mode uses HTTP for development/testing
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
            compatibility: CompatibilityConfig::default(),
            tenants: vec![TenantConfig {
                id: 4,
                path: "/api/scim".to_string(),
                host: Some("api.example.com".to_string()),
                host_resolution: Some(HostResolutionConfig {
                    resolution_type: HostResolutionType::Forwarded,
                    trusted_proxies: Some(vec!["192.168.1.100".to_string()]),
                }),
                auth: AuthConfig {
                    auth_type: "bearer".to_string(),
                    token: Some("forwarded_token".to_string()),
                    basic: None,
                },
                override_base_url: None,
                custom_endpoints: vec![],
                compatibility: None,
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

        assert_eq!(tenant.path, "/api/scim");
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
            compatibility: CompatibilityConfig::default(),
            tenants: vec![TenantConfig {
                id: 5,
                path: "/scim".to_string(),
                host: Some("secure.example.com".to_string()),
                host_resolution: Some(HostResolutionConfig {
                    resolution_type: HostResolutionType::XForwarded,
                    trusted_proxies: Some(vec!["172.16.0.0/12".to_string()]),
                }),
                auth: AuthConfig {
                    auth_type: "basic".to_string(),
                    token: None,
                    basic: Some(BasicAuthConfig {
                        username: "xfwd_user".to_string(),
                        password: "xfwd_pass".to_string(),
                    }),
                },
                override_base_url: None,
                custom_endpoints: vec![],
                compatibility: None,
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

        assert_eq!(tenant.path, "/scim");
        assert_eq!(resolved_url.scheme, "https");
        assert_eq!(resolved_url.host, "secure.example.com");
        assert_eq!(resolved_url.port, Some(443));
        assert_eq!(resolved_url.path, "/scim/v2/Groups");
    }

    #[test]
    fn test_new_config_design_functionality() {
        // Test the new config.yaml design with path field and optional host/host_resolution
        let config_content = r#"
server:
  host: "127.0.0.1"
  port: 3000

backend:
  type: "database"
  database:
    type: "sqlite"
    url: ":memory:"

tenants:
  # Path-only tenant (no host requirements) 
  - id: 1
    path: "/scim/v2"
    auth:
      type: "unauthenticated"

  # Host-specific tenant with default host resolution (Host header)
  - id: 2
    path: "/api/scim"
    host: "api.example.com"
    auth:
      type: "bearer"
      token: "secret123"
"#;

        let temp_file = "/tmp/new_config_test.yaml";
        std::fs::write(temp_file, config_content).unwrap();

        let config = AppConfig::load_from_file(temp_file).unwrap();

        // Verify tenant structure
        assert_eq!(config.tenants.len(), 2);

        // Test tenant 1: path-only matching
        let tenant1 = &config.tenants[0];
        assert_eq!(tenant1.path, "/scim/v2");
        assert!(tenant1.host.is_none());
        assert!(tenant1.host_resolution.is_none());

        // Test tenant 2: host with default resolution
        let tenant2 = &config.tenants[1];
        assert_eq!(tenant2.path, "/api/scim");
        assert_eq!(tenant2.host, Some("api.example.com".to_string()));
        assert!(tenant2.host_resolution.is_none()); // Default resolution

        // Test request matching scenarios

        // Scenario 1: Path-only tenant (should match any host)
        let request_info1 = RequestInfo {
            path: "/scim/v2/Users",
            host_header: Some("any.host.com"),
            forwarded_header: None,
            x_forwarded_proto: None,
            x_forwarded_host: None,
            x_forwarded_port: None,
            client_ip: None,
        };

        let (matched_tenant, _) = config.find_tenant_by_request(&request_info1).unwrap();
        assert_eq!(matched_tenant.id, 1);

        // Scenario 2: Host-specific tenant with matching host
        let request_info2 = RequestInfo {
            path: "/api/scim/Users",
            host_header: Some("api.example.com"),
            forwarded_header: None,
            x_forwarded_proto: None,
            x_forwarded_host: None,
            x_forwarded_port: None,
            client_ip: None,
        };

        let (matched_tenant, _) = config.find_tenant_by_request(&request_info2).unwrap();
        assert_eq!(matched_tenant.id, 2);

        // Scenario 3: Host-specific tenant with non-matching host (should not match)
        let request_info3 = RequestInfo {
            path: "/api/scim/Users",
            host_header: Some("wrong.host.com"),
            forwarded_header: None,
            x_forwarded_proto: None,
            x_forwarded_host: None,
            x_forwarded_port: None,
            client_ip: None,
        };

        let result3 = config.find_tenant_by_request(&request_info3);
        assert!(result3.is_none(), "Should not match tenant with wrong host");

        // Clean up
        std::fs::remove_file(temp_file).unwrap();
    }

    #[test]
    fn test_build_base_url_functionality() {
        // Test the new build_base_url method with different configurations

        // Test case 1: override_base_url is set (forced override)
        let tenant_with_override = TenantConfig {
            id: 1,
            path: "/scim/v2".to_string(),
            host: None,
            host_resolution: None,
            auth: AuthConfig {
                auth_type: "unauthenticated".to_string(),
                token: None,
                basic: None,
            },
            override_base_url: Some("https://custom.example.com".to_string()),
            custom_endpoints: vec![],
            compatibility: None,
        };

        let request_info = RequestInfo {
            path: "/scim/v2/Users",
            host_header: Some("localhost:3000"),
            forwarded_header: None,
            x_forwarded_proto: None,
            x_forwarded_host: None,
            x_forwarded_port: None,
            client_ip: None,
        };

        let result = tenant_with_override.build_base_url(&request_info);
        assert_eq!(result, "https://custom.example.com/scim/v2");

        // Test case 2: No override_base_url, path-only tenant (auto-constructed)
        let tenant_path_only = TenantConfig {
            id: 2,
            path: "/api/scim".to_string(),
            host: None,
            host_resolution: None,
            auth: AuthConfig {
                auth_type: "bearer".to_string(),
                token: Some("token123".to_string()),
                basic: None,
            },
            override_base_url: None,
            custom_endpoints: vec![],
            compatibility: None,
        };

        let result = tenant_path_only.build_base_url(&request_info);
        assert_eq!(result, "http://localhost:3000/api/scim");

        // Test case 3: No override_base_url, host-specific tenant with default resolution
        let tenant_with_host = TenantConfig {
            id: 3,
            path: "/tenant/scim".to_string(),
            host: Some("tenant.example.com".to_string()),
            host_resolution: None, // Default to Host header resolution
            auth: AuthConfig {
                auth_type: "basic".to_string(),
                token: None,
                basic: Some(BasicAuthConfig {
                    username: "admin".to_string(),
                    password: "pass".to_string(),
                }),
            },
            override_base_url: None,
            custom_endpoints: vec![],
            compatibility: None,
        };

        let request_info_with_matching_host = RequestInfo {
            path: "/tenant/scim/Users",
            host_header: Some("tenant.example.com"),
            forwarded_header: None,
            x_forwarded_proto: None,
            x_forwarded_host: None,
            x_forwarded_port: None,
            client_ip: None,
        };

        let result = tenant_with_host.build_base_url(&request_info_with_matching_host);
        assert_eq!(result, "http://tenant.example.com/tenant/scim");

        // Test case 4: No override_base_url, host-specific tenant with forwarded resolution
        let tenant_with_forwarded = TenantConfig {
            id: 4,
            path: "/secure/scim".to_string(),
            host: Some("secure.example.com".to_string()),
            host_resolution: Some(HostResolutionConfig {
                resolution_type: HostResolutionType::Forwarded,
                trusted_proxies: None,
            }),
            auth: AuthConfig {
                auth_type: "bearer".to_string(),
                token: Some("secure_token".to_string()),
                basic: None,
            },
            override_base_url: None,
            custom_endpoints: vec![],
            compatibility: None,
        };

        let request_info_forwarded = RequestInfo {
            path: "/secure/scim/Groups",
            host_header: Some("localhost:3000"),
            forwarded_header: Some("for=192.0.2.60;proto=https;host=secure.example.com:443"),
            x_forwarded_proto: None,
            x_forwarded_host: None,
            x_forwarded_port: None,
            client_ip: None,
        };

        let result = tenant_with_forwarded.build_base_url(&request_info_forwarded);
        assert_eq!(result, "https://secure.example.com/secure/scim");
    }
}
