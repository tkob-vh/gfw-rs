//! The analyzer crate which is usd in the gfw project.
#![warn(missing_docs)]

pub mod tcp;
pub mod tls;
pub mod udp;
pub mod utils;

use std::{any::Any, fmt::Debug, net::IpAddr, sync::Arc};

/// The `Analyzer` trait defines the basic interface for all analyzers.
pub trait Analyzer: Any + Send + Sync + Debug {
    /// Get the name of the analyzer.
    ///
    /// # Returns
    ///
    /// $str: the name returned
    fn name(&self) -> &str;
    /// Get the byte limit for this analyzer.

    /// For example, an analyzer can return 1000 to indicate that it only ever needs
    /// the first 1000 bytes of a stream to do its job. If the stream is still not
    /// done after 1000 bytes, the engine will stop feeding it data and close it.
    /// an analyzer can return 0 or a negative number to indicate that it does not
    /// have a hard limit.
    ///
    /// Note: for udp streams, the engine always feeds entire packets, even if
    /// the packet is larger than the remaining quota or the limit itself.
    ///
    /// # Returns
    ///
    /// i32: the byte limit for this analyzer.
    fn limit(&self) -> i32;

    /// Enable downcast_ref method.
    fn as_any(&self) -> &dyn Any;
}

/// The `TCPAnalyzer` trait extends the `Analyzer` trait for TCP-specific analysis.
pub trait TCPAnalyzer: Analyzer {
    /// Create a new TCPStream.
    ///
    /// # Returns
    ///
    /// A struct which implemented trait `TCPStream`
    fn new_tcp(&self, info: TCPInfo) -> Box<dyn TCPStream>;
}

/// The `TCPInfo` struct holds information about a TCP connection.
pub struct TCPInfo {
    /// SrcIP is the source IP address.
    pub src_ip: IpAddr,
    /// DstIP is the destination IP address.
    pub dst_ip: IpAddr,
    /// SrcPort is the source port.
    pub src_port: u16,
    /// DstPort is the destination port.
    pub dst_port: u16,
}

/// The `TCPStream` trait defines the interface for handling TCP stream data.
pub trait TCPStream: Send + Sync {
    /// Feed a chunk of reassembled data to the stream.
    ///
    /// # Arguments
    ///
    /// * `rev`: A boolean indicating if the data is request or response.
    ///    If set true, it's a response, otherwise is a request.
    /// * `start`: A boolean indicating if this is the start of the stream.
    /// * `end`: A boolean indicating if this is the end of the stream.
    /// * `skip`: The number of bytes to skip from the start of the data.
    /// * `data`: A slice of bytes representing the data to be fed to the stream.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * An optional `PropUpdate` with the information extracted from the stream (can be `None`).
    /// * A boolean indicating whether the analyzer is "done" with this stream (i.e., no more data should be fed).
    fn feed(
        &mut self,
        rev: bool,
        start: bool,
        end: bool,
        skip: usize,
        data: &[u8],
    ) -> (Option<PropUpdate>, bool);

    /// Close the stream.
    /// Either the connection is closed, or the stream has reached its byte limit.
    ///
    /// # Arguments
    ///
    /// * `limited`: A boolean indicating if the stream is being closed due to reaching its byte limit.
    ///
    /// # Returns
    ///
    /// An optional `PropUpdate` with the final information extracted from the stream (can be `None`).
    fn close(&mut self, limited: bool) -> Option<PropUpdate>;
}

/// The `UDPAnalyzer` trait extends the `Analyzer` trait for UDP-specific analysis.
pub trait UDPAnalyzer: Analyzer {
    /// Create a new UDPStream.
    ///
    /// # Returns
    ///
    /// a struct which implemented the `UDPStream` trait.
    fn new_udp(&self, info: UDPInfo) -> Box<dyn UDPStream>;
}

/// The `UDPInfo` struct holds information about a UDP connection.
pub struct UDPInfo {
    /// SrcIP is the source IP address.
    pub src_ip: IpAddr,
    /// DstIP is the destination IP address.
    pub dst_ip: IpAddr,
    /// SrcPort is the source port.
    pub src_port: u16,
    /// DstPort is the destination port.
    pub dst_port: u16,
}

/// The `UDPStream` trait defines the interface for handling UDP stream data.
pub trait UDPStream: Send + Sync {
    /// Feed a chunk of reassembled data to the stream.
    ///
    /// # Arguments
    ///
    /// * `rev`: A boolean indicating if the data is sent to the current host.
    /// * `data`: A slice of bytes representing the data to be fed to the stream.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * An optional `PropUpdate` with the information extracted from the stream (can be `None`).
    /// * A boolean indicating whether the analyzer is "done" with this stream (i.e., no more data should be fed).
    fn feed(&mut self, rev: bool, data: &[u8]) -> (Option<PropUpdate>, bool);

    /// Close the stream.
    /// Either the connection is closed, or the stream has reached its byte limit.
    ///
    /// # Arguments
    ///
    /// * `limited`: A boolean indicating if the stream is being closed due to reaching its byte limit.
    ///
    /// # Returns
    ///
    /// An optional `PropUpdate` with the final information extracted from the stream (can be `None`).
    fn close(&mut self, limited: bool) -> Option<PropUpdate>;
}

/// Property Map for different kinds of packets. From String to the property.
pub type PropMap = std::collections::HashMap<String, Arc<dyn std::any::Any + Send + Sync>>;

/// Combined Property Map.
/// analyzer -> PropMap
pub type CombinedPropMap = std::collections::HashMap<String, PropMap>;

/// Function to extract (String, String) pairs from CombinedPropMap
pub fn extract_pairs_from_combinedpropmap(combined_map: CombinedPropMap) -> Vec<(String, String)> {
    let mut result = Vec::new();

    for (analyzer_key, prop_map) in combined_map {
        flatten_prop_map(&analyzer_key, &prop_map, &mut result);
    }

    result
}

fn flatten_prop_map(prefix: &str, prop_map: &PropMap, result: &mut Vec<(String, String)>) {
    for (key, value) in prop_map {
        let new_key = format!("{}_{}", prefix, key);

        if let Some(string_value) = value.downcast_ref::<String>() {
            result.push((new_key, string_value.clone()));
        } else if let Some(nested_map) = value.downcast_ref::<PropMap>() {
            flatten_prop_map(&new_key, nested_map, result);
        } else if let Some(nested_map) =
            value.downcast_ref::<std::collections::HashMap<String, String>>()
        {
            for (nested_key, nested_value) in nested_map {
                let nested_new_key = format!("{}_{}", new_key, nested_key);
                result.push((nested_new_key, nested_value.clone()));
            }
        }
    }
}

/// The `PropUpdateType` enum defines the types of property updates that can occur.
#[derive(PartialEq, Debug)]
pub enum PropUpdateType {
    /// None
    None,
    /// Merge the maps
    Merge,
    /// Replace the map
    Replace,
    /// Delete the map
    Delete,
}

/// The `PropUpdate` struct holds information about a property update.
#[derive(Debug)]
pub struct PropUpdate {
    /// The PropUpdateType
    pub update_type: PropUpdateType,
    /// The current map
    pub map: PropMap,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[derive(Debug)]
    struct DummyAnalyzer;

    impl Analyzer for DummyAnalyzer {
        fn name(&self) -> &str {
            "DummyAnalyzer"
        }

        fn limit(&self) -> i32 {
            1000
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct DummyTCPStream;

    impl TCPStream for DummyTCPStream {
        fn feed(
            &mut self,
            _rev: bool,
            _start: bool,
            _end: bool,
            _skip: usize,
            _data: &[u8],
        ) -> (Option<PropUpdate>, bool) {
            (None, true)
        }

        fn close(&mut self, _limited: bool) -> Option<PropUpdate> {
            None
        }
    }

    #[derive(Debug)]
    struct DummyTCPAnalyzer;

    impl Analyzer for DummyTCPAnalyzer {
        fn name(&self) -> &str {
            "DummyTCPAnalyzer"
        }

        fn limit(&self) -> i32 {
            1000
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl TCPAnalyzer for DummyTCPAnalyzer {
        fn new_tcp(&self, _info: TCPInfo) -> Box<dyn TCPStream> {
            Box::new(DummyTCPStream)
        }
    }

    struct DummyUDPStream;

    impl UDPStream for DummyUDPStream {
        fn feed(&mut self, _rev: bool, _data: &[u8]) -> (Option<PropUpdate>, bool) {
            (None, true)
        }

        fn close(&mut self, _limited: bool) -> Option<PropUpdate> {
            None
        }
    }

    #[derive(Debug)]
    struct DummyUDPAnalyzer;

    impl Analyzer for DummyUDPAnalyzer {
        fn name(&self) -> &str {
            "DummyUDPAnalyzer"
        }

        fn limit(&self) -> i32 {
            1000
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl UDPAnalyzer for DummyUDPAnalyzer {
        fn new_udp(&self, _info: UDPInfo) -> Box<dyn UDPStream> {
            Box::new(DummyUDPStream)
        }
    }

    #[test]
    fn test_analyzer_name() {
        let analyzer = DummyAnalyzer;
        assert_eq!(analyzer.name(), "DummyAnalyzer");
    }

    #[test]
    fn test_analyzer_limit() {
        let analyzer = DummyAnalyzer;
        assert_eq!(analyzer.limit(), 1000);
    }

    #[test]
    fn test_tcp_info() {
        let info = TCPInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };
        assert_eq!(info.src_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(
            info.dst_ip,
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(info.src_port, 12345);
        assert_eq!(info.dst_port, 80);
    }

    #[test]
    fn test_udp_info() {
        let info = UDPInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };
        assert_eq!(info.src_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(
            info.dst_ip,
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(info.src_port, 12345);
        assert_eq!(info.dst_port, 80);
    }

    #[test]
    fn test_prop_update() {
        let mut map = PropMap::new();
        map.insert("key".to_string(), Arc::new("value".to_string()));
        let update = PropUpdate {
            update_type: PropUpdateType::Merge,
            map: map.clone(),
        };
        assert_eq!(update.update_type, PropUpdateType::Merge);
        assert_eq!(
            update
                .map
                .get("key")
                .unwrap()
                .downcast_ref::<String>()
                .unwrap(),
            "value"
        );
    }

    #[test]
    fn test_tcp_analyzer() {
        let analyzer = DummyTCPAnalyzer;
        let info = TCPInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };
        let mut stream = analyzer.new_tcp(info);
        let (update, done) = stream.feed(false, true, false, 0, &[]);
        assert!(update.is_none());
        assert!(done);
        let close_update = stream.close(false);
        assert!(close_update.is_none());
    }

    #[test]
    fn test_udp_analyzer() {
        let analyzer = DummyUDPAnalyzer;
        let info = UDPInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };
        let mut stream = analyzer.new_udp(info);
        let (update, done) = stream.feed(false, &[]);
        assert!(update.is_none());
        assert!(done);
        let close_update = stream.close(false);
        assert!(close_update.is_none());
    }
}
