//! This module provides functionality for handling network packets, including
//! registering callbacks for packet processing, setting verdicts for packets,
//! and managing packet I/O operations.

pub mod nfqueue;
pub mod pcap;

use std::{error::Error, net::TcpStream, time::SystemTime};

/// Verdict represents the possible actions that can be taken on a packet.
#[derive(Debug)]
pub enum Verdict {
    /// Accept accepts the packet, but continues to process the stream.
    Accept,
    /// AcceptModify is like Accept, but replaces the packet with a new one.
    AcceptModify,
    /// AcceptStream accepts the packet and stops processing the stream.
    AcceptStream,
    /// Drop drops the packet, but does not block the stream.
    Drop,
    /// DropStream drops the packet and blocks the stream.
    DropStream,
}

/// Packet represents an IP packet.
pub trait Packet: Send + Sync {
    /// stream_id is the ID of the stream the packet belongs to.
    fn stream_id(&self) -> u32;

    /// timestamp is the time the packet was received.
    fn timestamp(&self) -> SystemTime;

    /// data is the raw packet data, starting with the IP header.
    fn data(&self) -> &[u8];
}

pub type PacketCallback =
    Box<dyn Fn(Box<dyn Packet>, Option<Box<dyn Error>>) -> bool + Send + Sync>;

#[async_trait::async_trait]
pub trait PacketIO {
    /// Register registers a callback to be called for each packet received.
    /// The callback should be called in one or more separate routines,
    /// and stop when the context is cancelled.
    async fn register(&self, callback: PacketCallback) -> Result<(), Box<dyn Error>>;

    /// Set the verdict for a packet.
    async fn set_verdict(
        &self,
        packet: Box<dyn Packet>,
        verdict: Verdict,
        data: Vec<u8>,
    ) -> Result<(), Box<dyn Error>>;

    ///
    async fn protect_dial(&self, address: &str) -> Result<TcpStream, Box<dyn Error>>;

    /// Close the packet io.
    async fn close(&self) -> Result<(), Box<dyn Error>>;

    /// Give packet io access to context cancel function, enabling it to trigger a shutdown.
    async fn set_cancel_func(
        &self,
        cancel_func: Box<dyn Fn() + Send + Sync>,
    ) -> Result<(), Box<dyn Error>>;
}
