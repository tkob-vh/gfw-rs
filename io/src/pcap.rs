//! This module provides functionality for reading and processing packets from a pcap file.
//! It includes the `PcapPacketIO` struct which implements the `PacketIO` trait for handling
//! packet input/output operations using pcap files.
//!
//! In pcap mode, none of the actions in the rules have any effect. This mode is mainly for debugging.
//!
//! For info about pcap file format, refer to:
//! <https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html>
//! <https://wiki.wireshark.org/Development/LibpcapFileFormat>
//! <https://www.slideshare.net/slideshow/pcap-headers-description/62718981#5>

use crate::{Packet, PacketCallback, PacketIO, Verdict};

use async_trait::async_trait;
use crc32fast::hash;
use pcap::Capture;

use std::any::Any;
use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::net::TcpStream;
use tokio::sync::Mutex;

type CancelFunc = Arc<Mutex<Option<Box<dyn Fn() + Send + Sync>>>>;

/// Struct representing the pcap packet input/output operations.
pub struct PcapPacketIO {
    /// Used in real-time mode.
    time_offset: Arc<Mutex<Option<Duration>>>,

    /// Can be called to stop the packet processing.
    cancel_func: CancelFunc,

    /// Store the configuration for the `PcapPacketIO` instance.
    config: PcapPacketIOConfig,
}

/// It can be merged into the `PcapPacketIO` struct.
#[derive(Debug, Clone)]
pub struct PcapPacketIOConfig {
    /// Path to the pcap file.
    pub pcap_file: String,

    /// Flag indicating whether to replay packets in real-time.
    pub real_time: bool,
}

impl PcapPacketIO {
    /// Creates a new `PcapPacketIO` instance using the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - A `PcapPacketIOConfig` instance containing the configuration for the pcap IO.
    ///
    /// # Returns
    ///
    /// * `Option<Self>` - An optional `PcapPacketIO` instance.
    pub fn new(config: PcapPacketIOConfig) -> Option<Self> {
        Some(Self {
            time_offset: Arc::new(Mutex::new(None)),
            cancel_func: Arc::new(Mutex::new(None)),
            config,
        })
    }

    /// Extracts source and destination IP addresses from the given packet data.
    ///
    /// # Arguments
    ///
    /// * `packet` - A byte slice representing the packet data.
    ///
    /// # Returns
    ///
    /// * `Option<(String, String)>` - An optional tuple containing the source and destination IP addresses.
    fn extract_ip_addresses(packet: &[u8]) -> Option<(String, String)> {
        if packet.len() < 34 {
            // Minimum length for IPv4 header + some data
            return None;
        }

        // Skip Ethernet header (14 bytes) to get to IP header
        let ip_header = &packet[14..];

        // Check if it's IPv4 (version 4 in first 4 bits)
        if (ip_header[0] >> 4) != 4 {
            return None;
        }

        // Source IP: bytes 12-15
        let src_ip = format!(
            "{}.{}.{}.{}",
            ip_header[12], ip_header[13], ip_header[14], ip_header[15]
        );

        // Destination IP: bytes 16-19
        let dst_ip = format!(
            "{}.{}.{}.{}",
            ip_header[16], ip_header[17], ip_header[18], ip_header[19]
        );

        Some((src_ip, dst_ip))
    }
}

#[async_trait]
impl PacketIO for PcapPacketIO {
    async fn register(&self, callback: PacketCallback) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut capture = Capture::from_file(&self.config.pcap_file).unwrap();
        let time_offset = self.time_offset.clone();
        let config = self.config.clone();
        let cancel_func = self.cancel_func.clone();

        let _ = tokio::spawn(async move {
            // Iterate through all the packets in the pcap file.
            while let Ok(packet) = capture.next_packet() {
                let packet_timestamp = SystemTime::UNIX_EPOCH
                    + Duration::new(
                        packet.header.ts.tv_sec as u64,
                        packet.header.ts.tv_usec as u32 * 1000,
                    );

                // Intentionally slow down the replay.
                // In realtime mode, this is to match the timestamps in the capture
                if config.real_time {
                    // Handle timing for realtime replay
                    let mut offset = time_offset.lock().await;
                    if offset.is_none() {
                        *offset = Some(
                            SystemTime::now()
                                .duration_since(packet_timestamp)
                                .unwrap_or(Duration::from_secs(0)),
                        );
                    } else {
                        tokio::time::sleep(
                            packet_timestamp
                                .checked_add(offset.unwrap())
                                .unwrap_or(SystemTime::now())
                                .duration_since(SystemTime::now())
                                .unwrap_or(Duration::from_secs(0)),
                        )
                        .await;
                    }
                }

                // Get the src ip and dst ip.
                if let Some((src, dst)) = Self::extract_ip_addresses(packet.data) {
                    let mut endpoints = [src, dst];
                    endpoints.sort();

                    let id = hash(endpoints.join(",").as_bytes());

                    let pcap_packet = PcapPacket {
                        stream_id: id,
                        timestamp: packet_timestamp,
                        data: packet.data[14..].to_vec(),
                    };

                    if !callback(Box::new(pcap_packet), None) {
                        break;
                    }
                }
            }

            // Give workers a chance to finish (similar to Go's time.Sleep(time.Second))
            tokio::time::sleep(Duration::from_secs(1)).await;

            // Stop the engine when all packets are finished
            if let Some(cancel) = cancel_func.lock().await.as_ref() {
                cancel();
            }
        })
        .await;

        Ok(())
    }

    #[allow(unused_variables)]
    async fn set_verdict(
        &self,
        packet: Box<dyn Packet>,
        verdict: Verdict,
        data: Vec<u8>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // PCAP is read-only, so we don't need to implement verdict handling
        Ok(())
    }

    async fn protected_conn(&self, addr: &str) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
        // Simple TCP connection as PCAP doesn't interfere with networking
        Ok(TcpStream::connect(addr).await.unwrap())
    }

    //async fn close(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
    //    // File will be closed when the Arc/Mutex is dropped
    //    Ok(())
    //}

    async fn set_cancel_func(
        &self,
        cancel_func: Box<dyn Fn() + Send + Sync>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut func = self.cancel_func.blocking_lock();
        *func = Some(cancel_func);
        Ok(())
    }
}

/// Struct representing a pcap packet.
///
///```text
///                          1                   2                   3
///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    0 |                      Timestamp (Seconds)                      |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    4 |            Timestamp (Microseconds or nanoseconds)            |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    8 |                    Captured Packet Length                     |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   12 |                    Original Packet Length                     |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   16 /                                                               /
///      /                          Packet Data                          /
///      /                        variable length                        /
///      /                                                               /
///      +---------------------------------------------------------------+
///```
struct PcapPacket {
    stream_id: u32,
    timestamp: SystemTime,
    data: Vec<u8>,
}

impl Packet for PcapPacket {
    fn stream_id(&self) -> u32 {
        self.stream_id
    }

    fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let config = PcapPacketIOConfig {
            pcap_file: String::from("test.pcap"),
            real_time: false,
        };
        let pcap_io = PcapPacketIO::new(config.clone());
        assert!(pcap_io.is_some());
        let pcap_io = pcap_io.unwrap();
        assert_eq!(pcap_io.config.pcap_file, config.pcap_file);
        assert_eq!(pcap_io.config.real_time, config.real_time);
    }

    #[test]
    fn test_extract_ip_addresses() {
        let packet = [
            0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, // Ethernet header
            0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0xa8, 0x00, 0x01, // IP header
            0xc0, 0xa8, 0x00, 0x02, // IP header
        ];
        let result = PcapPacketIO::extract_ip_addresses(&packet);
        assert!(result.is_some());
        let (src_ip, dst_ip) = result.unwrap();
        assert_eq!(src_ip, "192.168.0.1");
        assert_eq!(dst_ip, "192.168.0.2");
    }

    #[test]
    fn test_extract_ip_addresses_invalid_packet() {
        let packet = [0u8; 10]; // Too short to be a valid packet
        let result = PcapPacketIO::extract_ip_addresses(&packet);
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_register() {
        let config = PcapPacketIOConfig {
            pcap_file: String::from("../assets/pcaps/ipv4frags.pcap"),
            real_time: false,
        };
        let pcap_io = PcapPacketIO::new(config).unwrap();

        let result = pcap_io
            .register(Box::new(move |_, err| {
                //let mut err_chan = err_chan_clone.blocking_lock();
                if let Some(_) = err {
                    //*err_chan = Some(e);
                    return false;
                }
                // Simulate dispatching the packet
                // e.dispatch(p)
                true
            }))
            .await;

        assert!(result.is_ok());
    }
}
