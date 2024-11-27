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

use std::sync::Arc;

use byteorder::{self, ByteOrder, LittleEndian};
use bytes::BytesMut;
use ringbuf::{
    traits::{Consumer, Producer},
    HeapRb,
};

use crate::*;

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

#[derive(Debug)]
pub struct WireGuardAnalyzer {}

impl WireGuardAnalyzer {
    /// Construct a empty WireGuardAnalyzer.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for WireGuardAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for WireGuardAnalyzer {
    fn name(&self) -> &str {
        "wireguard"
    }

    fn limit(&self) -> i32 {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl UDPAnalyzer for WireGuardAnalyzer {
    /// The argument `info` is not used here.
    #[allow(unused_variables)]
    fn new_udp(&self, info: crate::UDPInfo) -> Box<dyn UDPStream> {
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
    fn parse_wireguard_packet(&mut self, rev: bool, data: &BytesMut) -> Option<PropMap> {
        // Check the first four bytes (1 byte for type and 3 bytes for reserved).
        if data.len() < 4 {
            return None;
        }

        // Check if the reserved field is all 0.
        if *data.get(1..4).unwrap().iter().max().unwrap() != 0_u8 {
            return None;
        }

        let mut prop_key = String::new();
        let prop_value: Option<PropMap>;

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
            _ => {
                prop_value = None;
            }
        };

        // Return the prop map.
        match prop_value {
            None => None,
            Some(prop_value) => {
                let mut prop_map = PropMap::new();

                // String to Message type.
                prop_map.insert(
                    WIREGUARD_PROPKEY_MESSAGE_TYPE.to_string(),
                    Arc::new(message_type.to_string()),
                );
                // Message type to prop_map.
                prop_map.insert(prop_key, Arc::new(prop_value));

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
    ) -> Option<PropMap> {
        // Check the message length
        if data.len() != WIREGUARD_SIZE_HANDSHAKE_INITIATION as usize {
            return None;
        }

        let mut prop_map = PropMap::new();

        // Get the sender_idx field.
        let sender_idx = LittleEndian::read_u32(data.get(4..8).unwrap());

        // String to sender_idx.
        prop_map.insert("sender_index".to_string(), Arc::new(sender_idx.to_string()));

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
    ) -> Option<PropMap> {
        // Check the message length
        if data.len() != WIREGUARD_SIZE_HANDSHAKE_RESPONSE as usize {
            return None;
        }

        let mut prop_map = PropMap::new();

        // Get the sender_idx field.
        let sender_idx = LittleEndian::read_u32(data.get(4..8).unwrap());

        // String to sender_idx.
        prop_map.insert("sender_index".to_string(), Arc::new(sender_idx.to_string()));

        // Store the index to the ring buffer.
        self.put_sender_idx(rev, sender_idx);

        // Get the receiver_idx field.
        let receiver_idx = LittleEndian::read_u32(data.get(8..12).unwrap());

        // String to sender_idx.
        prop_map.insert(
            "receiver_index".to_string(),
            Arc::new(receiver_idx.to_string()),
        );

        // The matching pair with the receiver_idx.
        prop_map.insert(
            "receiver_index_matched".to_string(),
            Arc::new(self.match_receiver_idx(rev, receiver_idx).to_string()),
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
    fn parse_wireguard_packet_data(&mut self, rev: bool, data: &BytesMut) -> Option<PropMap> {
        // Check the message length
        if data.len() < WIREGUARD_MIN_SIZE_PACKET_DATA as usize {
            return None;
        }

        // WireGuard zero padding the packet to make the length a multiple of 16
        if data.len() % 16 != 0 {
            return None;
        }

        let mut prop_map = PropMap::new();

        let receiver_idx = LittleEndian::read_u32(data.get(4..8).unwrap());
        prop_map.insert(
            "receiver_index".to_string(),
            Arc::new(receiver_idx.to_string()),
        );
        prop_map.insert(
            "receiver_index_matched".to_string(),
            Arc::new(self.match_receiver_idx(rev, receiver_idx).to_string()),
        );

        // The counter value is a nonce for the ChaCha20Poly1305 AEAD
        // It also functions to avoid replay attacks.
        prop_map.insert(
            "counter".to_string(),
            Arc::new(LittleEndian::read_u64(data.get(8..16).unwrap()).to_string()),
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
    ) -> Option<PropMap> {
        if data.len() != WIREGUARD_SIZE_PACKET_COOKIE_REPLY as usize {
            return None;
        }

        let mut prop_map = PropMap::new();

        let receiver_idx = LittleEndian::read_u32(data.get(4..8).unwrap());

        prop_map.insert(
            "receiver_index".to_string(),
            Arc::new(receiver_idx.to_string()),
        );

        prop_map.insert(
            "receiver_index_matched".to_string(),
            Arc::new(self.match_receiver_idx(rev, receiver_idx).to_string()),
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
    fn feed(&mut self, rev: bool, data: &[u8]) -> (Option<crate::PropUpdate>, bool) {
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

        let mut prop_update_type = PropUpdateType::Merge;

        if message_type == WIREGUARD_TYPE_HANDSHAKE_INITIATION {
            prop_update_type = PropUpdateType::Replace;
        }

        (
            Some(PropUpdate {
                update_type: prop_update_type,
                map: prop_map,
            }),
            false,
        )
    }

    #[allow(unused_variables)]
    fn close(&mut self, limited: bool) -> Option<crate::PropUpdate> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use hex;
    use ringbuf::traits::Observer;
    use std::num::NonZero;

    #[test]
    fn test_wireguard_analyzer_name() {
        let analyzer = WireGuardAnalyzer {};
        assert_eq!(analyzer.name(), "wireguard");
    }

    #[test]
    fn test_wireguard_analyzer_limit() {
        let analyzer = WireGuardAnalyzer {};
        assert_eq!(analyzer.limit(), 0);
    }

    #[test]
    fn test_wireguard_udp_stream_new() {
        let stream = WireGuardUDPStream::new();
        assert_eq!(stream.invalid_count, 0);
        assert_eq!(
            stream.remembered_indexes.capacity(),
            NonZero::new(WIREGUARD_REMEMBERED_INDEX_COUNT as usize).unwrap()
        );
    }

    #[test]
    fn test_parse_wireguard_packet_invalid_length() {
        let mut stream = WireGuardUDPStream::new();
        let data = BytesMut::from(&[0u8, 0, 0][..]);
        assert!(stream.parse_wireguard_packet(false, &data).is_none());
    }

    #[test]
    fn test_parse_wireguard_packet_invalid_reserved() {
        let mut stream = WireGuardUDPStream::new();
        let data = BytesMut::from(&[1u8, 1, 0, 0][..]);
        assert!(stream.parse_wireguard_packet(false, &data).is_none());
    }

    #[test]
    fn test_parse_wireguard_handshake_initiation() {
        let mut stream = WireGuardUDPStream::new();

        let data = BytesMut::from(
            hex::decode(concat!(
                "01000000029c03c1f30ceb67148",
                "dd27c78d52d0196b6b78b71542986f563ac898879353f022f174770c5b3d433",
                "cfb49fd3311688284ce67ec72111e655129fc5f6bed2e0a44b8d28c222c6e14",
                "79a0833c7a1f6417b733c1ef049fab5e451aff561ea428c2116f7d1023ccdac",
                "2b2a00ecbe0273c9f84b1c695032084b58e7d2ff9fcf19fd00000000000000000000000000000000"
            ))
            .unwrap()
            .as_slice(),
        );
        let prop_map = stream
            .parse_wireguard_handshake_initiation(false, &data)
            .unwrap();
        assert_eq!(
            *prop_map
                .get("sender_index")
                .unwrap()
                .downcast_ref::<u32>()
                .unwrap(),
            0xc1039c02
        );
    }

    #[test]
    fn test_parse_wireguard_handshake_response() {
        let mut stream = WireGuardUDPStream::new();
        let data = BytesMut::from(
            hex::decode(concat!(
                "0200000001fae3dc029c03c1394",
                "ce1067faccdff74d71ddde6450ccedb94839008a7a2c0cdb0b4abe080565b96",
                "d16752c32e60baabfb5413fba24276beae31ece918c01700e5dfe66ca3c7b9",
                "00000000000000000000000000000000"
            ))
            .unwrap()
            .as_slice(),
        );
        let prop_map = stream
            .parse_wireguard_handshake_response(false, &data)
            .unwrap();
        assert_eq!(
            *prop_map
                .get("sender_index")
                .unwrap()
                .downcast_ref::<u32>()
                .unwrap(),
            0xdce3fa01
        );
        assert_eq!(
            *prop_map
                .get("receiver_index")
                .unwrap()
                .downcast_ref::<u32>()
                .unwrap(),
            0xc1039c02
        );
    }

    #[test]
    fn test_parse_wireguard_packet_data() {
        let mut stream = WireGuardUDPStream::new();
        let data = BytesMut::from(
            hex::decode(concat!(
                "0400000006f47dab00000000000",
                "00000a4ebc12ee3f990da18033a0789c04e2700f6f5c271d42ac4b4d6262e66",
                "6549b445a7436e829bffb6ac65f05648bc0c391fe7c58848743761271649401",
                "88f03dba67af8388eaab76c593628bf9dc7be03346d912e916dad862545454",
                "701364f2d2486d7ced4c8642ce547ddb26ef6a46b"
            ))
            .unwrap()
            .as_slice(),
        );
        let prop_map = stream.parse_wireguard_packet_data(false, &data).unwrap();
        assert_eq!(
            *prop_map
                .get("receiver_index")
                .unwrap()
                .downcast_ref::<u32>()
                .unwrap(),
            0xab7df406
        );
    }

    //#[test]
    //fn test_parse_wireguard_packet_cookie_reply() {
    //    let mut stream = WireGuardUDPStream::new();
    //    let data = BytesMut::from();
    //    let prop_map = stream
    //        .parse_wireguard_packet_cookie_reply(false, &data)
    //        .unwrap();
    //    assert_eq!(
    //        *prop_map
    //            .get("receiver_index")
    //            .unwrap()
    //            .downcast_ref::<u32>()
    //            .unwrap(),
    //        1
    //    );
    //}

    #[test]
    fn test_put_sender_idx() {
        let mut stream = WireGuardUDPStream::new();
        stream.put_sender_idx(false, 1);
        assert_eq!(stream.remembered_indexes.occupied_len(), 1);
    }

    #[test]
    fn test_match_receiver_idx() {
        let mut stream = WireGuardUDPStream::new();
        stream.put_sender_idx(false, 1);
        assert!(stream.match_receiver_idx(true, 1));
    }
    //
    #[test]
    fn test_feed_invalid_packet() {
        let mut stream = WireGuardUDPStream::new();
        let data = &[0u8, 0, 0, 0][..];
        let (prop_update, _) = stream.feed(false, data);
        assert!(prop_update.is_none());
    }

    #[test]
    fn test_feed_valid_packet() {
        let mut stream = WireGuardUDPStream::new();
        let data = hex::decode(concat!(
            "01000000029c03c1f30ceb67148",
            "dd27c78d52d0196b6b78b71542986f563ac898879353f022f174770c5b3d433",
            "cfb49fd3311688284ce67ec72111e655129fc5f6bed2e0a44b8d28c222c6e14",
            "79a0833c7a1f6417b733c1ef049fab5e451aff561ea428c2116f7d1023ccdac",
            "2b2a00ecbe0273c9f84b1c695032084b58e7d2ff9fcf19fd00000000000000000000000000000000"
        ))
        .expect("Invalid hex string");
        let (prop_update, is_invalid) = stream.feed(false, &data);
        assert!(prop_update.is_some());
        assert!(!is_invalid);
    }
}
