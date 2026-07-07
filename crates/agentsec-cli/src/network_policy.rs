//! SSRF-style network policy checks for scan targets (spec 23.4).
//!
//! Extracted from `main.rs` so it can be unit tested in isolation from the
//! CLI/pipeline wiring.

/// Checks whether an IPv4 address falls in a private, loopback, unspecified,
/// or link-local range. Link-local (169.254.0.0/16) specifically covers the
/// AWS/GCP/Azure cloud-metadata endpoint (169.254.169.254), which this check
/// previously missed entirely.
pub fn is_private_ipv4(ipv4: std::net::Ipv4Addr) -> bool {
    ipv4.is_loopback() || ipv4.is_private() || ipv4.is_unspecified() || ipv4.is_link_local()
}

/// Checks whether an IPv6 address is private/loopback/unspecified/unique-local,
/// or an IPv4-mapped address (`::ffff:a.b.c.d`) whose embedded IPv4 address is
/// itself private. Without the mapped-address check, a hostname resolving to
/// `::ffff:169.254.169.254` or `::ffff:127.0.0.1` would bypass the gate.
pub fn is_private_ipv6(ipv6: std::net::Ipv6Addr) -> bool {
    if ipv6.is_loopback() || ipv6.is_unspecified() || ((ipv6.segments()[0] & 0xfe00) == 0xfc00) {
        return true;
    }
    if let Some(mapped_v4) = ipv6.to_ipv4_mapped() {
        return is_private_ipv4(mapped_v4);
    }
    false
}

pub fn is_private_ip_addr(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        std::net::IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
    }
}

pub fn is_private_ip(host: &str) -> bool {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        is_private_ip_addr(ip)
    } else {
        false
    }
}

/// Resolves `host` via DNS (if it isn't already a literal IP) and reports
/// whether any resolved address is private/loopback/link-local.
pub async fn is_host_private(host: &str) -> bool {
    if is_private_ip(host) {
        return true;
    }
    if let Ok(addrs) = tokio::net::lookup_host(format!("{}:80", host)).await {
        for addr in addrs {
            if is_private_ip_addr(addr.ip()) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_standard_private_ipv4_ranges() {
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("10.0.0.5"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("0.0.0.0"));
    }

    #[test]
    fn detects_cloud_metadata_link_local_ipv4() {
        // The AWS/GCP/Azure metadata endpoint. This is the exact SSRF case
        // the network policy check is meant to stop.
        assert!(is_private_ip("169.254.169.254"));
        assert!(is_private_ip("169.254.0.1"));
    }

    #[test]
    fn allows_public_ipv4() {
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
    }

    #[test]
    fn detects_standard_private_ipv6_ranges() {
        assert!(is_private_ip("::1")); // loopback
        assert!(is_private_ip("::")); // unspecified
        assert!(is_private_ip("fd00::1")); // unique local (fc00::/7)
        assert!(is_private_ip("fc00::1"));
    }

    #[test]
    fn detects_ipv4_mapped_private_addresses() {
        // ::ffff:127.0.0.1 and ::ffff:169.254.169.254 must not bypass the
        // gate just because they're written in IPv6 form.
        assert!(is_private_ip("::ffff:127.0.0.1"));
        assert!(is_private_ip("::ffff:169.254.169.254"));
        assert!(is_private_ip("::ffff:10.0.0.1"));
        assert!(is_private_ip("::ffff:192.168.1.1"));
    }

    #[test]
    fn allows_ipv4_mapped_public_addresses() {
        assert!(!is_private_ip("::ffff:8.8.8.8"));
    }

    #[test]
    fn allows_public_ipv6() {
        assert!(!is_private_ip("2001:4860:4860::8888")); // Google public DNS
    }

    #[test]
    fn non_ip_hostname_is_not_flagged_by_is_private_ip() {
        // is_private_ip only handles literal IPs; DNS resolution is handled
        // separately by is_host_private.
        assert!(!is_private_ip("example.com"));
        assert!(!is_private_ip("metadata.google.internal"));
    }

    #[tokio::test]
    async fn is_host_private_detects_literal_private_ip_without_dns() {
        assert!(is_host_private("169.254.169.254").await);
        assert!(is_host_private("127.0.0.1").await);
        assert!(is_host_private("::ffff:169.254.169.254").await);
    }
}
