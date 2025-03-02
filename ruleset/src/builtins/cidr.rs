use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::str::FromStr;

pub fn is_ip_in_cidr(ip: &str, cidr: &str) -> bool {
    // Parse the IP address
    if let Ok(ip_addr) = IpAddr::from_str(ip) {
        if let Ok(cidr_network) = IpNetwork::from_str(cidr) {
            return cidr_network.contains(ip_addr);
        }
    }
    false
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_is_ip_in_cidr() {
        assert_eq!(is_ip_in_cidr("192.168.1.1", "192.168.0.0/16"), true);
    }
}
