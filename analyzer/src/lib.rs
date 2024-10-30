//! The analyzer crate which is usd in the gfw project.
#![warn(missing_docs)]

pub mod udp;
pub mod utils;

/// The `analyzer` module provides traits and structures for analyzing TCP and UDP streams.
/// The Get method for PropMap and CombinedPropMap is not defined temporarily.
use std::{net::IpAddr, rc::Rc};

/// The `Analyzer` trait defines the basic interface for all analyzers.
pub trait Analyzer {
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
    /// u32: the byte limit for this analyzer.
    fn limit(&self) -> u32;
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
///
/// # Example
///
/// ```
/// use analyzer::TCPInfo;
/// use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
///
/// let info = TCPInfo {
///     src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
///     dst_ip: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
///     src_port: 12345,
///     dst_port: 80,
/// };
/// ```
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
pub trait TCPStream {
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
/// # Example
///
/// ```
/// use analyzer::UDPInfo;
/// use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// let info = UDPInfo {
///     src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
///     dst_ip: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
///     src_port: 12345,
///     dst_port: 80,
/// };
/// ```
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
pub trait UDPStream {
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
pub type PropMap = std::collections::HashMap<String, Rc<dyn std::any::Any>>;

/// Combined Property Map.
pub type CombinePropMap = std::collections::HashMap<String, PropMap>;

/// The `PropUpdateType` enum defines the types of property updates that can occur.
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
/// # Example
///
/// ```
/// use analyzer::{PropMap, PropUpdate, PropUpdateType};
/// use std::rc::Rc;
///
/// let mut map = PropMap::new();
/// map.insert("key".to_string(), Rc::new("value".to_string()));
/// let update = PropUpdate {
///     update_type: PropUpdateType::Merge,
///     map,
/// };
/// ```
pub struct PropUpdate {
    /// The PropUpdateType
    pub update_type: PropUpdateType,
    /// The current map
    pub map: PropMap,
}
