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
