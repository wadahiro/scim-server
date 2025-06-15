use scim_server::config::{HostResolutionConfig, HostResolutionType};
use std::net::IpAddr;
use std::str::FromStr;

#[test]
fn test_trusted_proxies_none() {
    let config = HostResolutionConfig {
        resolution_type: HostResolutionType::Forwarded,
        trusted_proxies: None,
    };

    let client_ip = IpAddr::from_str("192.168.1.100").unwrap();
    assert!(config.is_trusted_proxy(client_ip)); // Should trust all when None
}

#[test]
fn test_trusted_proxies_single_ip() {
    let config = HostResolutionConfig {
        resolution_type: HostResolutionType::Forwarded,
        trusted_proxies: Some(vec!["192.168.1.100".to_string()]),
    };

    let trusted_ip = IpAddr::from_str("192.168.1.100").unwrap();
    let untrusted_ip = IpAddr::from_str("192.168.1.101").unwrap();

    assert!(config.is_trusted_proxy(trusted_ip));
    assert!(!config.is_trusted_proxy(untrusted_ip));
}

#[test]
fn test_trusted_proxies_cidr() {
    let config = HostResolutionConfig {
        resolution_type: HostResolutionType::Forwarded,
        trusted_proxies: Some(vec!["192.168.1.0/24".to_string()]),
    };

    let trusted_ip = IpAddr::from_str("192.168.1.150").unwrap();
    let untrusted_ip = IpAddr::from_str("192.168.2.100").unwrap();

    assert!(config.is_trusted_proxy(trusted_ip));
    assert!(!config.is_trusted_proxy(untrusted_ip));
}

#[test]
fn test_trusted_proxies_multiple_ranges() {
    let config = HostResolutionConfig {
        resolution_type: HostResolutionType::XForwarded,
        trusted_proxies: Some(vec![
            "192.168.1.0/24".to_string(),
            "10.0.0.0/8".to_string(),
            "172.16.0.100".to_string(),
        ]),
    };

    let ip1 = IpAddr::from_str("192.168.1.50").unwrap(); // In 192.168.1.0/24
    let ip2 = IpAddr::from_str("10.5.5.5").unwrap(); // In 10.0.0.0/8
    let ip3 = IpAddr::from_str("172.16.0.100").unwrap(); // Exact match
    let ip4 = IpAddr::from_str("172.16.0.101").unwrap(); // Not trusted

    assert!(config.is_trusted_proxy(ip1));
    assert!(config.is_trusted_proxy(ip2));
    assert!(config.is_trusted_proxy(ip3));
    assert!(!config.is_trusted_proxy(ip4));
}
