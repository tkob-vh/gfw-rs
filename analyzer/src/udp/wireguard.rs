//! WireGuard Analyzer Module
//!
//! This module provides functionality to analyze WireGuard UDP packets. It includes
//! structures and methods to parse different types of WireGuard messages such as
//! handshake initiation, handshake response, data packets, and cookie replies.
//!
//! The main components of this module are:
//! - `WireGuardAnalyzer`: Implements the `UDPAnalyzer` trait for analyzing WireGuard packets.
//! - `WireGuardUDPStream`: Implements the `UDPStream` trait for handling the stream of WireGuard packets.
//! - `WireGuardIdx`: A structure to store the index information of WireGuard packets.

use crate::analyzer::{self, Analyzer, UDPAnalyzer, UDPStream};
use byteorder::{self, BigEndian, ByteOrder};
use bytes::BytesMut;
use ringbuf::{
    traits::{Consumer, Producer},
    HeapRb,
};
use std::rc::Rc;

const WIREGUARD_UDP_INVALID_COUNT_THRESHOLD: u32 = 4;
const WIREGUARD_REMEMBERED_INDEX_COUNT: u32 = 6;
const WIREGUARD_PROPKEY_MESSAGE_TYPE: &str = "message_type";

// Message Type
const WIREGUARD_TYPE_HANDSHAKE_INITIATION: u8 = 1;
const WIREGUARD_TYPE_HANDSHAKE_RESPONSE: u8 = 2;
const WIREGUARD_TYPE_DATA: u8 = 4;
const WIREGUARD_TYPE_COOKIE_REPLY: u8 = 3;

// Size of the message
// msg = handshake_initiation {
//    u8 message_type
//    u8 reserved_zero[3]
//    u32 sender_index
//    u8 unencrypted_ephemeral[32]
//    u8 encrypted_static[AEAD_LEN(32)]
//    u8 encrypted_timestamp[AEAD_LEN(12)]
//    u8 mac1[16]
//    u8 mac2[16]
// }
//
// msg = handshake_response {
//    u8 message_type
//    u8 reserved_zero[3]
//    u32 sender_index
//    u32 receiver_index
//    u8 unencrypted_ephemeral[32]
//    u8 encrypted_nothing[AEAD_LEN(0)]
//    u8 mac1[16]
//    u8 mac2[16]
// }
const WIREGUARD_SIZE_HANDSHAKE_INITIATION: u32 = 148;
const WIREGUARD_SIZE_HANDSHAKE_RESPONSE: u32 = 92;
const WIREGUARD_MIN_SIZE_PACKET_DATA: u32 = 32;
const WIREGUARD_SIZE_PACKET_COOKIE_REPLY: u32 = 64;

/// `WireGuardAnalyzer` implements `UDPAnalyzer`.
/// This structure is responsible for creating new instances of `WireGuardUDPStream`
/// and providing basic information about the analyzer.

pub struct WireGuardAnalyzer {}

impl Analyzer for WireGuardAnalyzer {
    fn name(&self) -> &str {
        "wireguard"
    }

    fn limit(&self) -> u32 {
        0
    }
}

impl UDPAnalyzer for WireGuardAnalyzer {
    /// The argument `info` is not used here.
    #[allow(unused_variables)]
    fn new_udp(&self, info: crate::analyzer::UDPInfo) -> Box<dyn UDPStream> {
        Box::new(WireGuardUDPStream::new())
    }
}

/// The index about the wireguard packet.
/// This structure stores the sender index and a boolean indicating the direction
struct WireGuardIdx {
    sender_idx: u32,
    reverse: bool,
}

/// `WireGuardUDPStream` implements `UDPStream`.
pub struct WireGuardUDPStream {
    /// The number of current invalid count of wireguard messages.
    invalid_count: u32,
    /// Store the indexes in the ring buffer.
    remembered_indexes: HeapRb<WireGuardIdx>,
}

impl WireGuardUDPStream {
    /// Initialize the `WireGuardUDPStream`
    fn new() -> Self {
        Self {
            invalid_count: 0,
            remembered_indexes: HeapRb::<WireGuardIdx>::new(
                WIREGUARD_REMEMBERED_INDEX_COUNT as usize,
            ),
        }
    }

    /// Parse the wireguard packet.
    ///
    /// This function parses the given data buffer to extract properties of the
    /// WireGuard packet based on its type (handshake initiation, handshake response,
    /// data packet, or cookie reply).
    ///
    /// # Arguments
    ///
    /// * `rev`: Whether it's a request or response.
    /// * `data`: The data buffer we read from.
    ///
    /// # Returns
    /// The properties map or None
    fn parse_wireguard_packet(&mut self, rev: bool, data: &BytesMut) -> Option<analyzer::PropMap> {
        // Check the first four bytes (1 byte for type and 3 bytes for reserved).
        if data.len() < 4 {
            return None;
        }

        // Check if the reserved field is all 0.
        if *data.get(1..4).unwrap().iter().max().unwrap() != 0_u8 {
            return None;
        }

        let mut prop_key = String::new();
        let mut prop_value: Option<analyzer::PropMap> = None;

        // Get the message_type
        let message_type = data.first().unwrap().to_owned();

        // Parse the message according to the type
        match message_type {
            WIREGUARD_TYPE_HANDSHAKE_INITIATION => {
                prop_key = "handshake_initiation".to_string();
                prop_value = self.parse_wireguard_handshake_initiation(rev, data);
            }
            WIREGUARD_TYPE_HANDSHAKE_RESPONSE => {
                prop_key = "handshake_response".to_string();
                prop_value = self.parse_wireguard_handshake_response(rev, data);
            }
            WIREGUARD_TYPE_DATA => {
                prop_key = "packet_data".to_string();
                prop_value = self.parse_wireguard_packet_data(rev, data);
            }
            WIREGUARD_TYPE_COOKIE_REPLY => {
                prop_key = "pakcet_cookie_reply".to_string();
                prop_value = self.parse_wireguard_packet_cookie_reply(rev, data);
            }
            _ => {}
        };

        // Return the prop map.
        match prop_value {
            None => None,
            Some(prop_value) => {
                let mut prop_map = analyzer::PropMap::new();

                // String to Message type.
                prop_map.insert(
                    WIREGUARD_PROPKEY_MESSAGE_TYPE.to_string(),
                    Rc::new(message_type),
                );
                // Message type to prop_map.
                prop_map.insert(prop_key, Rc::new(prop_value));

                Some(prop_map)
            }
        }
    }

    /// Parse the WIREGUARD_TYPE_HANDSHAKE_INITIATION message.
    ///
    /// # Arguments
    /// * `rev`: Whether it's a request or response.
    /// * `data`: The data buffer we read from.
    ///
    /// # Returns
    ///
    /// The properties map or None
    fn parse_wireguard_handshake_initiation(
        &mut self,
        rev: bool,
        data: &BytesMut,
    ) -> Option<analyzer::PropMap> {
        // Check the message length
        if data.len() != WIREGUARD_SIZE_HANDSHAKE_INITIATION as usize {
            return None;
        }

        let mut prop_map = analyzer::PropMap::new();

        // Get the sender_idx field.
        let sender_idx = BigEndian::read_u32(data.get(4..8).unwrap());

        // String to sender_idx.
        prop_map.insert("sender_index".to_string(), Rc::new(sender_idx));

        // Store the index to the ring buffer.
        self.put_sender_idx(rev, sender_idx);

        Some(prop_map)
    }

    /// Parse the WIREGUARD_TYPE_HANDSHAKE_RESPONSE message.
    ///
    /// # Arguments
    /// * `rev`: Whether it's a request or response.
    /// * `data`: The data buffer we read from.
    ///
    /// # Returns
    ///
    /// The properties map or None
    fn parse_wireguard_handshake_response(
        &mut self,
        rev: bool,
        data: &BytesMut,
    ) -> Option<analyzer::PropMap> {
        // Check the message length
        if data.len() != WIREGUARD_SIZE_HANDSHAKE_RESPONSE as usize {
            return None;
        }

        let mut prop_map = analyzer::PropMap::new();

        // Get the sender_idx field.
        let sender_idx = BigEndian::read_u32(data.get(4..8).unwrap());

        // String to sender_idx.
        prop_map.insert("sender_index".to_string(), Rc::new(sender_idx));

        // Store the index to the ring buffer.
        self.put_sender_idx(rev, sender_idx);

        // Get the receiver_idx field.
        let receiver_idx = BigEndian::read_u32(data.get(8..12).unwrap());

        // String to sender_idx.
        prop_map.insert("receiver_index".to_string(), Rc::new(receiver_idx));

        // The matching pair with the receiver_idx.
        prop_map.insert(
            "receiver_index_matched".to_string(),
            Rc::new(self.match_receiver_idx(rev, receiver_idx)),
        );

        Some(prop_map)
    }

    /// Parse the WIREGUARD_TYPE_DATA message.
    ///
    /// # Arguments
    /// * `rev`: Whether it's a request or response.
    /// * `data`: The data buffer we read from.
    ///
    /// # Returns
    ///
    /// The properties map or None
    fn parse_wireguard_packet_data(
        &mut self,
        rev: bool,
        data: &BytesMut,
    ) -> Option<analyzer::PropMap> {
        // Check the message length
        if data.len() < WIREGUARD_MIN_SIZE_PACKET_DATA as usize {
            return None;
        }

        // WireGuard zero padding the packet to make the length a multiple of 16
        if data.len() % 16 != 0 {
            return None;
        }

        let mut prop_map = analyzer::PropMap::new();

        let receiver_idx = BigEndian::read_u32(data.get(4..8).unwrap());
        prop_map.insert("receiver_index".to_string(), Rc::new(receiver_idx));
        prop_map.insert(
            "receiver_index_matched".to_string(),
            Rc::new(self.match_receiver_idx(rev, receiver_idx)),
        );

        // The counter value is a nonce for the ChaCha20Poly1305 AEAD
        // It also functions to avoid replay attacks.
        prop_map.insert(
            "counter".to_string(),
            Rc::new(BigEndian::read_u64(data.get(8..16).unwrap())),
        );

        Some(prop_map)
    }

    /// Parse the WIREGUARD_TYPE_COOKIE_REPLY message.
    ///
    /// # Arguments
    /// * `rev`: Whether it's a request or response.
    /// * `data`: The data buffer we read from.
    ///
    /// # Returns
    ///
    /// The properties map or None
    fn parse_wireguard_packet_cookie_reply(
        &mut self,
        rev: bool,
        data: &BytesMut,
    ) -> Option<analyzer::PropMap> {
        if data.len() != WIREGUARD_SIZE_PACKET_COOKIE_REPLY as usize {
            return None;
        }

        let mut prop_map = analyzer::PropMap::new();

        let receiver_idx = BigEndian::read_u32(data.get(4..8).unwrap());

        prop_map.insert("receiver_index".to_string(), Rc::new(receiver_idx));

        prop_map.insert(
            "receiver_index_matched".to_string(),
            Rc::new(self.match_receiver_idx(rev, receiver_idx)),
        );

        Some(prop_map)
    }

    /// Put the sender index into the ring buffer.
    ///
    /// # Arguments
    ///
    /// * `rev`: Whether it's a request or response.
    /// * `sender_idx`: sender index.
    ///
    fn put_sender_idx(&mut self, rev: bool, sender_idx: u32) {
        let wireguard_idx = WireGuardIdx {
            sender_idx,
            reverse: rev,
        };

        let _ = self.remembered_indexes.try_push(wireguard_idx);
    }

    /// Get the corresponding sender index of the receiver index.
    ///
    /// # Arguments
    ///
    /// * `rev`: Whether it's a request or response.
    /// * `receiver_idx`: receiver index.
    ///
    /// # Returns
    ///
    /// Whether find the corresponding sender index.
    fn match_receiver_idx(&self, rev: bool, receiver_idx: u32) -> bool {
        let mut found = false;

        // Iterate throuth the ring buffer
        for it in self.remembered_indexes.iter() {
            // If the rev is opposite and the index is the same.
            if it.reverse != rev && it.sender_idx == receiver_idx {
                found = true;
                break;
            }
        }

        found
    }
}

impl UDPStream for WireGuardUDPStream {
    fn feed(&mut self, rev: bool, data: &[u8]) -> (Option<crate::analyzer::PropUpdate>, bool) {
        let prop_map = match self.parse_wireguard_packet(rev, &BytesMut::from(data)) {
            Some(map) => map,
            None => {
                self.invalid_count += 1;
                return (
                    None,
                    self.invalid_count >= WIREGUARD_UDP_INVALID_COUNT_THRESHOLD,
                );
            }
        };

        // Reset invalid count on valid WireGuard packet
        self.invalid_count = 0;

        // Extract the message type from prop_map.
        let message_type = prop_map[WIREGUARD_PROPKEY_MESSAGE_TYPE]
            .downcast_ref::<u8>()
            .expect("Expected a u8 value")
            .to_owned();

        let mut prop_update_type = analyzer::PropUpdateType::Merge;

        if message_type == WIREGUARD_TYPE_HANDSHAKE_INITIATION {
            prop_update_type = analyzer::PropUpdateType::Replace;
        }

        (
            Some(analyzer::PropUpdate {
                update_type: prop_update_type,
                map: prop_map,
            }),
            false,
        )
    }

    #[allow(unused_variables)]
    fn close(&mut self, limited: bool) -> Option<crate::analyzer::PropUpdate> {
        None
    }
}
