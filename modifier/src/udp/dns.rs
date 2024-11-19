//! This module provides a DNS modifier for UDP packets. It includes the `DNSModifier` struct which
//! implements the `Modifier` trait, and the `DNSModifierInstance` struct which implements the `Instance`
//! and `UDPModifierInstance` traits. The DNS modifier can modify DNS responses based on provided
//! IPv4 and IPv6 addresses.

use crate::{udp::dns, Instance, Modifier, UDPModifierInstance};
use pnet::packet::dns::{DnsClasses, DnsResponse, DnsTypes, MutableDnsPacket, Retcode};
use pnet::packet::Packet;
use std::sync::Arc;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use tracing::{self, error, warn};

/// A DNS modifier that implements the `Modifier` trait.
pub struct DNSModifier;

impl DNSModifier {
    /// Construct a empty DNSModifier.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DNSModifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Modifier for DNSModifier {
    fn name(&self) -> &str {
        "dns"
    }
    fn new_instance(
        &self,
        args: std::collections::HashMap<String, String>,
    ) -> Option<Arc<dyn Instance>> {
        // Create a new instance.
        let mut ip = DNSModifierInstance::new();

        // Find the value of the key "a" in args.
        match args.get("a") {
            Some(value) => {
                let a_str = value;

                match Ipv4Addr::from_str(a_str) {
                    Ok(a) => {
                        ip.a = a;
                    }
                    Err(e) => {
                        error!("Invalid args: invalid ip. {}", e);
                        return None;
                    }
                };
            }
            None => {
                warn!("Failing to find key 'a' in the args");
            }
        };

        // Find the value of the key "aaaa" in args.
        match args.get("aaaa") {
            Some(value) => {
                let aaaa_str = value;

                match Ipv6Addr::from_str(aaaa_str) {
                    Ok(aaaa) => {
                        ip.aaaa = aaaa;
                    }
                    Err(e) => {
                        error!("Invalid args: invalid ip. {}", e);
                        return None;
                    }
                }
            }
            None => {
                warn!("Failing to find key 'aaaa' in the args");
            }
        }

        Some(Arc::new(ip))
    }
}

/// An instance of the DNS modifier containing the IPv4 and IPv6 addresses.
struct DNSModifierInstance {
    a: Ipv4Addr,
    aaaa: Ipv6Addr,
}

/// Creates a new `DNSModifierInstance` with unspecified IPv4 and IPv6 addresses.
impl DNSModifierInstance {
    fn new() -> Self {
        Self {
            a: Ipv4Addr::UNSPECIFIED,
            aaaa: Ipv6Addr::UNSPECIFIED,
        }
    }
}

impl Instance for DNSModifierInstance {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl UDPModifierInstance for DNSModifierInstance {
    fn process(&self, data: &mut [u8]) -> Option<Vec<u8>> {
        // Create a mutable dns packet from the bytes.
        let mut dns_packet = match dns::MutableDnsPacket::new(data) {
            Some(packet) => packet,
            None => {
                error!("Invalid dns packet.");
                return None;
            }
        };

        // The packet is not a response or some error occurred.
        if dns_packet.get_is_response() == 0 || dns_packet.get_rcode() != Retcode::NoError {
            error!("Not a valid dns response");
            return None;
        }

        // No querys.
        if dns_packet.get_query_count() == 0 {
            error!("Empty dns question");
            return None;
        }

        if dns_packet.get_response_count() == 0 {
            error!("Empty dns answers");
            return None;
        }

        // In practice, most if not all DNS clients only send one question
        // per packet, so we don't care about the rest for now.
        let query = dns_packet.get_queries_iter().next().unwrap();

        // Get the qtype and modify the response record in the dns packet.
        match query.get_qtype() {
            DnsTypes::A => {
                if !self.a.is_unspecified() {
                    let rr = DnsResponse {
                        name_tag: 0xc00c,
                        rtype: DnsTypes::A,
                        rclass: DnsClasses::IN,
                        ttl: 100,
                        data_len: 4u16,
                        data: self.a.octets().to_vec(),
                        payload: vec![],
                    };

                    dns_packet.set_response_count(1);

                    dns_packet.set_responses(&[rr]);
                }
            }
            DnsTypes::AAAA => {
                if !self.aaaa.is_unspecified() {
                    let rr = DnsResponse {
                        name_tag: 0xc00c,
                        rtype: DnsTypes::AAAA,
                        rclass: DnsClasses::IN,
                        ttl: 100,
                        data_len: 16u16,
                        data: self.aaaa.octets().to_vec(),
                        payload: vec![],
                    };

                    dns_packet.set_response_count(1);

                    dns_packet.set_responses(&[rr]);
                }
            }
            _ => {}
        }

        // Modifiers must be safe for concurrent use, so we can't reuse the buffer
        Some(dns_packet.packet().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_dns_modifier_new() {
        let modifier = DNSModifier;
        let mut args = HashMap::new();
        args.insert("a".to_string(), "192.168.0.1".to_string());
        args.insert("aaaa".to_string(), "::1".to_string());

        let instance = modifier.new_instance(args).unwrap();
        let dns_instance = instance
            .as_any()
            .downcast_ref::<DNSModifierInstance>()
            .unwrap();

        assert_eq!(dns_instance.a, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(dns_instance.aaaa, Ipv6Addr::from_str("::1").unwrap());
    }

    #[test]
    fn test_dns_modifier_process_a() {
        let instance = DNSModifierInstance {
            a: Ipv4Addr::new(192, 168, 0, 1),
            aaaa: Ipv6Addr::UNSPECIFIED,
        };

        let mut packet_data = vec![
            0x75, 0xc0, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x3, 0x77, 0x77, 0x77,
            0x6, 0x6e, 0x65, 0x74, 0x62, 0x73, 0x64, 0x3, 0x6f, 0x72, 0x67, 0x0, 0x0, 0x1, 0x0,
            0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1, 0x40, 0xef, 0x0, 0x4, 0xcc, 0x98, 0xbe,
            0xc,
        ];

        let _ = instance.process(&mut packet_data).unwrap();
    }

    #[test]
    fn test_dns_modifier_process_aaaa() {
        let instance = DNSModifierInstance::new();

        let mut packet_data = vec![
            0x8d, 0xb3, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x3, 0x77, 0x77, 0x77,
            0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1c, 0x0,
            0x1, 0xc0, 0xc, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x2, 0x79, 0x0, 0x8, 0x3, 0x77, 0x77,
            0x77, 0x1, 0x6c, 0xc0, 0x10,
        ];

        let _ = instance.process(&mut packet_data).unwrap();
    }
}
