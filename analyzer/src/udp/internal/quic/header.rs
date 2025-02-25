//! This module provides functionality to parse QUIC headers.
//!
//! It includes functions to parse the initial packet of a QUIC connection and to read QUIC variable-length integers.

use crate::udp::internal::quic::quic;
use bytes::{Buf, BytesMut};
use tracing::error;

/// The Header represents a QUIC header.
#[derive(Debug)]
pub struct Header {
    quic_type: u8,
    version: u32,
    src_connection_id: BytesMut,
    dest_connection_id: BytesMut,
    length: usize,
    token: BytesMut,
}

impl Header {
    /// Return the `version` field in Header
    pub fn get_version(&self) -> u32 {
        self.version
    }

    /// Return the `length` field in Header
    pub fn get_length(&self) -> usize {
        self.length
    }

    /// Return the dcid
    pub fn get_dcid(&self) -> Vec<u8> {
        self.dest_connection_id.to_vec()
    }

    /// Return the `quic_type`
    pub fn get_quic_type(&self) -> u8 {
        self.quic_type
    }

    /// Return the scid
    pub fn get_scid(&self) -> Vec<u8> {
        self.src_connection_id.to_vec()
    }

    /// Return the `token`
    pub fn get_token(&self) -> Vec<u8> {
        self.token.to_vec()
    }
}

/// Parse the initial packet of a QUIC connection
///
/// # Arguments
///
/// * 'data': The byte buffer.
///
/// # Returns
///
/// The initial header and the number of bytes read so far.
///
/// ```text
/// Initial Packet {
///  Header Form (1) = 1,
///  Fixed Bit (1) = 1,
///  Long Packet Type (2) = 0,
///  Reserved Bits (2),
///  Packet Number Length (2),
///  Version (32),
///  Destination Connection ID Length (8),
///  Destination Connection ID (0..160),
///  Source Connection ID Length (8),
///  Source Connection ID (0..160),
///  Token Length (i),
///  Token (..),
///  Length (i),
///  Packet Number (8..32),
///  Packet Payload (8..),
/// }
/// ```
pub fn parse_initial_header(data: &mut BytesMut) -> (Option<Header>, usize) {
    let pkt_len = data.len();
    let hdr = parse_long_header(data);

    let n = pkt_len - data.len();
    (hdr, n)
}

/// Parse the long header.
///
/// # Arguments
///
/// * `data` - The byte buffer containing the packet data.
///
/// # Returns
///
/// An `Option<Header>` which is `Some` if the header was successfully parsed, or `None` if there was an error.
///
/// ```text
/// Long Header Packet {
///  Header Form (1) = 1,
///  Fixed Bit (1) = 1,
///  Long Packet Type (2),
///  Type-Specific Bits (4),
///  Version (32),
///  Destination Connection ID Length (8),
///  Destination Connection ID (0..160),
///  Source Connection ID Length (8),
///  Source Connection ID (0..160),
///  Type-Specific Payload (..),
/// }
/// ```
fn parse_long_header(data: &mut BytesMut) -> Option<Header> {
    // Get the first byte which contains the QUIC type.
    if data.is_empty() {
        error!("No enough data for quic_type");
        return None;
    }
    let quic_type = data.get_u8();

    // Get the version info (next 4 bytes).
    if data.len() < 4 {
        error!("No enough data for version");
        return None;
    }
    let ver = data.get_u32();

    // Check the version and the long packet type to ensure it's a valid QUIC packet.
    if ver != 0 && quic_type & 0x40 == 0 {
        error!("Not a QUIC packet");
        return None;
    }

    // Get the destination connection ID length (next byte).
    if data.is_empty() {
        error!("No enough data for dest_connection_id_len");
        return None;
    }
    let dest_connection_id_len = data.get_u8();

    // Get the destination connection ID (next `dest_connection_id_len` bytes).
    if data.len() < dest_connection_id_len as usize {
        error!("No enough data for dest_connection_id");
        return None;
    }
    let dest_connection_id = data.split_to(dest_connection_id_len as usize);

    // Get the source connection ID length (next byte).
    if data.is_empty() {
        error!("No enough data for src_connection_id_len");
        return None;
    }
    let src_connection_id_len = data.get_u8();

    // Get the source connection ID (next `src_connection_id_len` bytes).
    if data.len() < src_connection_id_len as usize {
        error!("No enough data for src_connection_id");
        return None;
    }
    let src_connection_id = data.split_to(src_connection_id_len as usize);

    // Determine the initial packet type based on the version.
    let initial_packet_type: u8 = match ver {
        quic::V1 => 0b00,
        quic::V2 => 0b01,
        _ => 0b00,
    };

    let mut token = BytesMut::new();

    // If the packet type matches the initial packet type, read the token length.
    if (quic_type >> 4 & 0b11) == initial_packet_type {
        let token_len = match read_var_len_integer(data) {
            Ok(len) => len,
            Err(e) => {
                error!("{}", e);
                return None;
            }
        };

        if data.len() < token_len {
            error!("No enough dta for tokens");
            return None;
        }
        token = data.split_to(token_len);
    }

    // Read the packet length.
    let packet_len = match read_var_len_integer(data) {
        Ok(len) => len,
        Err(e) => {
            error!("{}", e);
            return None;
        }
    };

    Some(Header {
        quic_type,
        version: ver,
        src_connection_id,
        dest_connection_id,
        token,
        length: packet_len,
    })
}

/// Reads a QUIC variable-length integer from the provided buffer.
///
/// The QUIC protocol uses variable-length integers (varints) to encode non-negative integer values in QUIC packets and frames.
///
/// QUIC variable-length integers can be 1, 2, 4, or 8 bytes long. The length is determined by the first two bits of the first byte.
///
///    +------+--------+-------------+-----------------------+
///    | 2Bit | Length | Usable Bits | Range                 |
///    +------+--------+-------------+-----------------------+
///    | 00   | 1      | 6           | 0-63                  |
///    |      |        |             |                       |
///    | 01   | 2      | 14          | 0-16383               |
///    |      |        |             |                       |
///    | 10   | 4      | 30          | 0-1073741823          |
///    |      |        |             |                       |
///    | 11   | 8      | 62          | 0-4611686018427387903 |
///    +------+--------+-------------+-----------------------+
///
///
/// # Arguments
///
/// * `buf` - A mutable reference to a `BytesMut` buffer containing the data.
///
/// # Returns
///
/// A `Result` containing the parsed integer as `usize` if successful, or an error message as `String` if the buffer does not contain enough data or if the length prefix is invalid.
///
/// # References
/// <https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-16#section-16>
pub fn read_var_len_integer(buf: &mut BytesMut) -> Result<usize, String> {
    if buf.is_empty() {
        return Err("Buffer is empty; cannot read var-length integer".into());
    }
    let first_byte = buf.get_u8();
    let length_prefix = first_byte >> 6;

    // Determine length based on the first 2 bits
    let value = match length_prefix {
        0b00 => first_byte as usize & 0x3F, // 1 byte
        0b01 => ((first_byte as usize & 0x3F) << 8) | buf.get_u8() as usize, // 2 bytes
        0b10 => {
            ((first_byte as usize & 0x3F) << 24)
                | (buf.get_u16() as usize) << 8
                | buf.get_u8() as usize
        } // 4 bytes
        0b11 => {
            ((first_byte as usize & 0x3F) << 56)
                | (buf.get_u32() as usize) << 24
                | (buf.get_u16() as usize) << 8
                | buf.get_u8() as usize // 8 bytes
        }
        _ => return Err("Invalid length prefix in variable-length integer".into()),
    };

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_parse_initial_header() {
        let mut data = BytesMut::from(
            &[
                0xcc, 0x0, 0x0, 0x0, 0x1, 0x8, 0x20, 0x3f, 0x9e, 0x9f, 0x68, 0x69, 0x82, 0x74, 0x0,
                0x0, 0x44, 0xbc, 0xac, 0x2d, 0xd2, 0x1b, 0x61, 0xbe, 0x64, 0x8c, 0x61, 0xe6, 0x1f,
                0x70, 0x69, 0x60, 0x0, 0xa, 0xcb, 0x8f, 0xa8, 0xff, 0xcf, 0x12, 0xb6, 0xa4, 0x6d,
                0x3d, 0xda, 0xb8, 0x14, 0xb5, 0xb4, 0x67, 0xd4, 0x4b, 0xea, 0x96, 0xd8, 0xa1, 0x76,
                0xa9, 0x3f, 0x8f, 0x72, 0x13, 0xdb, 0x54, 0x9c, 0xae, 0x23, 0xeb, 0xc9, 0xb1, 0xd1,
                0x66, 0x63, 0x5, 0x23, 0x5e, 0x14, 0x4c, 0x46, 0x56, 0xc0, 0xd0, 0xac, 0x8e, 0x5d,
                0x15, 0xba, 0xe8, 0xa1, 0x59, 0xf5, 0xdf, 0xc7, 0xad, 0xac, 0xa6, 0x51, 0x5b, 0xfc,
                0x5e, 0xee, 0x22, 0xd2, 0x69, 0xa8, 0x7a, 0x8e, 0xab, 0xdf, 0x2c, 0xb1, 0xd3, 0x99,
                0x51, 0x61, 0x47, 0xfd, 0x3d, 0xae, 0x97, 0xaf, 0x51, 0x3c, 0x71, 0x86, 0x3f, 0x7a,
                0x88, 0x12, 0xa1, 0x43, 0xd4, 0xaa, 0xd4, 0x47, 0xa1, 0x95, 0x52, 0x86, 0x5, 0x2e,
                0x2c, 0xc8, 0x59, 0x8, 0xe0, 0x32, 0xac, 0xac, 0xa1, 0x42, 0x1d, 0xa2, 0xd7, 0x95,
                0x63, 0x54, 0x4, 0x40, 0x52, 0x78, 0x16, 0x95, 0xf, 0xa6, 0x94, 0xd9, 0x3c, 0x8,
                0x7c, 0x4b, 0xc3, 0xaf, 0x1c, 0x89, 0x8, 0xf6, 0xf0, 0xee, 0xd5, 0xff, 0xe0, 0xdc,
                0xcc, 0x9c, 0x90, 0x5f, 0x34, 0x72, 0xf4, 0x70, 0x34, 0x7b, 0x8b, 0xe8, 0x3b, 0xc9,
                0xa1, 0x50, 0x43, 0x94, 0xab, 0x48, 0x94, 0x27, 0x29, 0x87, 0x8, 0xd5, 0xef, 0xb8,
                0xfa, 0x29, 0x41, 0x22, 0xc, 0xc4, 0x7b, 0x5e, 0x74, 0xdb, 0x18, 0xda, 0xdb, 0xdb,
                0x60, 0x63, 0xea, 0x35, 0xdb, 0x1e, 0x29, 0x4d, 0x5, 0x42, 0xa2, 0xf1, 0x8e, 0x10,
                0xd, 0x8f, 0xc2, 0x75, 0xe5, 0x8e, 0x53, 0xfd, 0x84, 0xfd, 0x1c, 0x3b, 0xb4, 0x23,
                0x9, 0x25, 0x5c, 0xc, 0x2e, 0x96, 0xf4, 0xf1, 0x42, 0xcf, 0xf2, 0x25, 0x52, 0xf4,
                0xbc, 0x74, 0x6a, 0xa4, 0xbf, 0x92, 0xd, 0x68, 0x77, 0xc6, 0xb6, 0xbf, 0x36, 0xc0,
                0x55, 0x30, 0xa8, 0x40, 0x84, 0x86, 0x11, 0x10, 0x8f, 0xf0, 0xe0, 0x6a, 0x9b, 0x1,
                0xbd, 0xe5, 0x99, 0x4a, 0xc2, 0xfe, 0x7c, 0xa9, 0x21, 0x81, 0x8c, 0x30, 0x1c, 0x82,
                0x3d, 0x69, 0xec, 0x6f, 0xf8, 0xa9, 0x28, 0x81, 0x43, 0x23, 0xc3, 0x5e, 0x8d, 0x7,
                0x75, 0xf4, 0x3e, 0x2f, 0x85, 0x61, 0xcc, 0x75, 0x5e, 0x45, 0xbd, 0x25, 0xcc, 0xe4,
                0x3d, 0x4f, 0x29, 0x8f, 0xc6, 0x45, 0xb2, 0x44, 0x4b, 0x15, 0xd7, 0x88, 0xd8, 0x2,
                0x99, 0xd0, 0xd6, 0xb7, 0xcf, 0xe4, 0x91, 0x25, 0xb3, 0x7, 0xb1, 0x8c, 0x76, 0xef,
                0xde, 0xd3, 0x7c, 0xc, 0x52, 0x76, 0xe, 0x32, 0x67, 0xfa, 0xc2, 0x96, 0x81, 0x54,
                0x32, 0xba, 0x79, 0xb6, 0xae, 0x49, 0xda, 0xf1, 0x8b, 0xcb, 0x57, 0xe6, 0x4, 0xb5,
                0xb3, 0xc7, 0x14, 0xdc, 0xac, 0x18, 0xb2, 0x6e, 0x81, 0x15, 0x77, 0x48, 0xab, 0xfa,
                0x45, 0xd2, 0xf7, 0x78, 0xad, 0x3b, 0x61, 0x58, 0xeb, 0x51, 0xae, 0x3, 0x95, 0x8f,
                0x62, 0x5c, 0x1e, 0xc4, 0x8f, 0xa7, 0xbe, 0x50, 0x47, 0xbe, 0xfa, 0xaf, 0x2d, 0x62,
                0x3b, 0x72, 0x9e, 0x44, 0xd1, 0xbe, 0xdf, 0x8b, 0x19, 0xc3, 0xd8, 0x92, 0xe, 0xd,
                0xc5, 0x13, 0x68, 0x6e, 0xf0, 0xb9, 0x5f, 0xfb, 0x3e, 0x8b, 0x3b, 0xd, 0x2f, 0x4,
                0x46, 0x20, 0x90, 0xa8, 0xd9, 0x89, 0x51, 0xfa, 0x8e, 0xf8, 0x5c, 0x5f, 0x5d, 0x41,
                0x62, 0x31, 0xd8, 0xb8, 0x78, 0xa5, 0x37, 0xca, 0xcf, 0xf1, 0xfb, 0x98, 0x7, 0x2c,
                0x29, 0x88, 0x39, 0x2d, 0x4e, 0xc3, 0xd4, 0x85, 0x1c, 0x75, 0x54, 0xab, 0xdd, 0xbe,
                0xc4, 0x31, 0xd9, 0xd0, 0xa9, 0xaa, 0xc, 0xd5, 0xcc, 0x5d, 0x10, 0x82, 0x67, 0x59,
                0xb3, 0xee, 0x45, 0xba, 0xf, 0x6, 0xbb, 0x5a, 0x3e, 0xbf, 0xac, 0x70, 0x90, 0x62,
                0x43, 0xb1, 0xdb, 0xde, 0xbc, 0x56, 0xfc, 0x9c, 0xeb, 0x50, 0x2f, 0xf0, 0xe8, 0x58,
                0x98, 0xfc, 0x23, 0x29, 0x23, 0xf2, 0x66, 0x70, 0x30, 0x3, 0x4, 0x78, 0x2f, 0xd6,
                0x23, 0x33, 0x2e, 0x9, 0x16, 0xb0, 0x49, 0x72, 0x77, 0x5, 0xfd, 0x19, 0x75, 0xf3,
                0x85, 0x2, 0xc6, 0xf5, 0xfa, 0x9c, 0x14, 0x92, 0xdd, 0xc1, 0x68, 0xdf, 0x63, 0x88,
                0xe6, 0x9d, 0x9a, 0x66, 0xfa, 0xc9, 0x88, 0xed, 0x39, 0x59, 0x52, 0x78, 0xda, 0x58,
                0x8d, 0xa7, 0x98, 0x14, 0x9c, 0x7, 0xb, 0xf5, 0x29, 0xc2, 0x6a, 0x78, 0x8f, 0xb4,
                0x67, 0x84, 0x8f, 0x5, 0x13, 0x4d, 0xaa, 0x87, 0x57, 0xac, 0x86, 0xc1, 0xf4, 0x20,
                0x83, 0x2, 0xaa, 0xc7, 0x66, 0x7c, 0x33, 0x99, 0x58, 0x4f, 0x63, 0xa9, 0x58, 0x38,
                0x7a, 0x39, 0x52, 0xe0, 0x37, 0x7c, 0xfd, 0xe6, 0x8c, 0x3b, 0xa9, 0x9e, 0xfe, 0x6e,
                0x2, 0x7d, 0x3e, 0x8c, 0x90, 0x50, 0xc, 0x3c, 0x69, 0x24, 0x74, 0xfa, 0x67, 0x15,
                0x53, 0xbf, 0xbc, 0xcc, 0x58, 0x20, 0x3f, 0x73, 0xef, 0x9d, 0x6, 0x45, 0x34, 0xec,
                0x91, 0xb6, 0xfe, 0x15, 0x95, 0xc, 0xf9, 0x79, 0xc5, 0x95, 0xb4, 0x55, 0x2e, 0x93,
                0x92, 0xd7, 0x69, 0x45, 0x61, 0xaf, 0x21, 0x10, 0x6a, 0xb7, 0xd9, 0x3b, 0x71, 0x47,
                0x28, 0xe8, 0x61, 0xad, 0xf8, 0x7a, 0xa4, 0x8e, 0x2e, 0x6, 0x98, 0x2a, 0x7a, 0x95,
                0xe5, 0xa2, 0x25, 0x4e, 0x65, 0x4f, 0x3f, 0x14, 0x1a, 0xcd, 0x36, 0xba, 0x4e, 0xbc,
                0x95, 0x6e, 0x20, 0xc8, 0x2e, 0x94, 0x74, 0x8b, 0xb9, 0xfa, 0x7d, 0x3c, 0x4e, 0xa4,
                0x94, 0x83, 0xa3, 0xcf, 0x6b, 0x3c, 0xa7, 0x63, 0xd9, 0xda, 0xc7, 0xbe, 0xfd, 0x28,
                0x95, 0x5e, 0xeb, 0xc3, 0xba, 0xea, 0x10, 0xb4, 0x58, 0xc1, 0xc2, 0xc9, 0xed, 0x95,
                0x96, 0x55, 0x9c, 0x4f, 0x3, 0x3f, 0xa2, 0x67, 0xd0, 0xcc, 0x53, 0x7d, 0x2, 0xa5,
                0xd1, 0x53, 0xb4, 0x44, 0xdd, 0x9b, 0xdc, 0x80, 0xc2, 0x7d, 0x7c, 0x49, 0xc, 0x3,
                0xe2, 0x52, 0x24, 0x79, 0x65, 0x32, 0xb, 0xc6, 0xa3, 0x6, 0x60, 0x94, 0x1e, 0xe5,
                0x7d, 0x6f, 0xed, 0x3, 0x24, 0x7b, 0x51, 0xa2, 0xd5, 0x1, 0x61, 0x79, 0x44, 0xf7,
                0x62, 0x23, 0xc3, 0x64, 0x1b, 0xfa, 0x6e, 0x38, 0x1c, 0x58, 0xea, 0x8c, 0xd0, 0xe2,
                0xa2, 0x1, 0x20, 0x69, 0x18, 0x23, 0x20, 0x40, 0xd1, 0xd7, 0x90, 0xf3, 0xfa, 0xa0,
                0x63, 0xd6, 0xad, 0xda, 0xd7, 0x47, 0x2f, 0x87, 0x90, 0x90, 0xe5, 0xf1, 0x78, 0x5a,
                0xcc, 0xbd, 0xe6, 0x56, 0x6d, 0x80, 0x79, 0x0, 0x94, 0x31, 0xb0, 0xe4, 0xbb, 0xd,
                0x1a, 0xfd, 0xd8, 0x31, 0x5, 0xa0, 0x1, 0x65, 0x6c, 0x93, 0x3e, 0x33, 0x74, 0x15,
                0xa1, 0x67, 0x3f, 0xf0, 0xd0, 0xea, 0x3b, 0xa7, 0xa6, 0x95, 0x8e, 0xa2, 0xa9, 0xef,
                0xd8, 0x20, 0x72, 0x9, 0x19, 0x6, 0x93, 0x6b, 0xb2, 0xd6, 0x85, 0x4a, 0x6, 0xde,
                0xf4, 0x81, 0x14, 0x22, 0xd1, 0xb1, 0xc0, 0xd2, 0xb0, 0xf9, 0xbf, 0x80, 0x44, 0x38,
                0x91, 0x8c, 0xc8, 0xa5, 0x98, 0xbd, 0xe3, 0x4d, 0x80, 0x19, 0xaa, 0x87, 0x10, 0xbe,
                0x24, 0x63, 0x5, 0x3e, 0x74, 0x41, 0xf5, 0x85, 0xf6, 0xc8, 0x6, 0x2a, 0x26, 0xd0,
                0xb2, 0x89, 0xbc, 0x26, 0xf3, 0xbc, 0x5f, 0x27, 0x19, 0x1b, 0x18, 0x4a, 0x14, 0x1a,
                0x66, 0xc5, 0x43, 0x1b, 0x31, 0x81, 0x67, 0x18, 0x10, 0x5b, 0x9c, 0xd4, 0x38, 0x12,
                0xf, 0xa3, 0xcf, 0x60, 0x23, 0x3f, 0x50, 0xf7, 0xdf, 0x93, 0xe8, 0x36, 0x5c, 0x3b,
                0x62, 0x12, 0xf0, 0xed, 0xc4, 0xe0, 0x14, 0xe5, 0x14, 0x0, 0x0, 0x42, 0x6d, 0x59,
                0x5b, 0x5a, 0xc3, 0x1f, 0xd9, 0x77, 0x29, 0x9d, 0xe4, 0x2, 0x74, 0x14, 0xaa, 0x7b,
                0xf, 0x27, 0x9f, 0x3e, 0xfb, 0x4d, 0x4a, 0xa, 0xd, 0x41, 0x61, 0xac, 0xb8, 0x38,
                0x6a, 0x4, 0x36, 0xca, 0xe6, 0x7c, 0xfd, 0x67, 0xfa, 0x5a, 0xc2, 0xc4, 0x7a, 0xe7,
                0x3a, 0x5a, 0x2c, 0x95, 0x88, 0xad, 0xc2, 0xe, 0x44, 0xfc, 0xe0, 0x4e, 0x1e, 0xf3,
                0x60, 0xb0, 0x1b, 0x45, 0xd6, 0xca, 0x13, 0x17, 0xbc, 0x8a, 0x22, 0xca, 0xab, 0xda,
                0xbc, 0xf0, 0xf0, 0x96, 0x17, 0x81, 0xf2, 0xf7, 0x8d, 0x0, 0x5c, 0xd4, 0x27, 0x5a,
                0xb1, 0x62, 0x99, 0xbc, 0x56, 0x72, 0x6d, 0x81, 0x7, 0x47, 0xed, 0x73, 0xf4, 0x22,
                0x24, 0x87, 0x9c, 0x10, 0x54, 0xc7, 0x23, 0x2, 0x9c, 0x43, 0x7a, 0x29, 0xb7, 0xfc,
                0xfa, 0xb, 0xcd, 0x7a, 0x5a, 0x5, 0x10, 0x21, 0x6a, 0x44, 0x79, 0x96, 0xa3, 0xd1,
                0x76, 0x4a, 0x12, 0x43, 0xe4, 0x33, 0x87, 0x20, 0xae, 0x85, 0xc9, 0xe3, 0x8c, 0x7d,
                0x0, 0x7f, 0x18, 0x79, 0xb1, 0xcf, 0x1d, 0x60, 0xba, 0x73, 0x5b, 0xd3, 0x9b, 0xa3,
                0xb7, 0xc8, 0xa3, 0x1a, 0xfa, 0xb7, 0x7e, 0x2, 0x99, 0x53, 0x5a, 0xf, 0xb9, 0xe9,
                0x62, 0xc9, 0x43, 0x25, 0xfa, 0x6b, 0x40, 0xcc, 0x7a, 0x11, 0x18, 0xb3, 0xb4, 0x71,
                0x32, 0x6b, 0xe9, 0x3a, 0x60, 0x6, 0x3a, 0x7b, 0x4c, 0x34, 0xb1,
            ][..],
        );

        let (header, bytes_read) = parse_initial_header(&mut data);
        assert!(header.is_some());

        println!("{:?}", header);
        assert_eq!(bytes_read, 18);
    }

    #[test]
    fn test_parse_long_header() {
        let mut data = BytesMut::from(
            &[
                0xcb, 0x0, 0x0, 0x0, 0x1, 0x0, 0x14, 0x1, 0x30, 0xdf, 0xc5, 0xa0, 0x47, 0xe6, 0xac,
                0xd2, 0x30, 0xb5, 0xc5, 0xe0, 0x47, 0xce, 0xd9, 0xb0, 0xa6, 0xbb, 0xf0, 0x0, 0x40,
                0x17, 0x9a, 0x8, 0xbf, 0x7d, 0xa3, 0xa7, 0x39, 0xa0, 0x65, 0x82, 0x3e, 0x63, 0xac,
                0xf7, 0x23, 0x35, 0x42, 0x53, 0xf9, 0x25, 0x65, 0xb2, 0x26,
            ][..],
        );

        let header = parse_long_header(&mut data);
        println!("{:?}", header);
        assert!(header.is_some());
    }

    #[test]
    fn test_read_var_len_integer() {
        let mut data = BytesMut::from(&[0x40, 0x01][..]);
        let result = read_var_len_integer(&mut data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }
}
