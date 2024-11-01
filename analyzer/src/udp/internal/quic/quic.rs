//! QUIC (Quick UDP Internet Connections) module
//!
//! This module provides constants and functions for handling QUIC protocol versions and their associated cryptographic labels and salts.
//!
//! # Functions
//!
//! - `is_long_header(b: u8) -> bool`: Determines if a given byte represents a long header in QUIC.
//! - `get_salt(v: u32) -> Vec<u8>`: Returns the appropriate salt value for a given QUIC version.
//! - `key_label(v: u32) -> String`: Returns the appropriate HKDF key label for a given QUIC version.
//! - `iv_label(v: u32) -> String`: Returns the appropriate HKDF IV label for a given QUIC version.
//! - `header_protection_label(v: u32) -> String`: Returns the appropriate HKDF header protection label for a given QUIC version.
//!
//! This module is essential for handling the cryptographic aspects of different QUIC versions.

use tracing::error;

pub const V1: u32 = 0x1;
pub const V2: u32 = 0x6b3343cf;

const HKDF_LABEL_KEY_V1: &str = "quic key";
const HKDF_LABEL_KEY_V2: &str = "quicv2 key";
pub const HKDF_LABEL_IV_V1: &str = "quic iv";
pub const HKDF_LABEL_IV_V2: &str = "quicv2 iv";
pub const HKDF_LABEL_HP_V1: &str = "quic hp";
pub const HKDF_LABEL_HP_V2: &str = "quicv2 hp";

const QUIC_SALT_OLD: &[u8] = &[
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];

// https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets
const QUIC_SALT_V1: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

// https://www.ietf.org/archive/id/draft-ietf-quic-v2-10.html#name-initial-salt-2
const QUIC_SALT_V2: &[u8] = &[
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Determines if a given byte represents a long header in QUIC.
///
/// # Arguments
///
/// * `b` - A byte to check.
///
/// # Returns
///
/// * `true` if the byte represents a long header, `false` otherwise.
pub fn is_long_header(b: u8) -> bool {
    b & 0x80 > 0
}

/// Returns the appropriate salt value for a given QUIC version.
///
/// # Arguments
///
/// * `v` - The QUIC version.
///
/// # Returns
///
/// * A vector of bytes representing the salt value.
pub fn get_salt(v: u32) -> &'static [u8] {
    match v {
        V1 => QUIC_SALT_V1,
        V2 => QUIC_SALT_V2,
        _ => QUIC_SALT_OLD,
    }
}

/// Returns the appropriate HKDF key label for a given QUIC version.
///
/// # Arguments
///
/// * `v` - The QUIC version.
///
/// # Returns
///
/// * A string representing the HKDF key label.
pub fn key_label(v: u32) -> String {
    match v {
        V1 => HKDF_LABEL_KEY_V1.to_string(),
        V2 => HKDF_LABEL_KEY_V2.to_string(),
        _ => {
            error!("Invalid version");
            "error".to_string()
        }
    }
}

/// Returns the appropriate HKDF IV label for a given QUIC version.
///
/// # Arguments
///
/// * `v` - The QUIC version.
///
/// # Returns
///
/// * A string representing the HKDF IV label.
fn iv_label(v: u32) -> String {
    match v {
        V1 => HKDF_LABEL_IV_V1.to_string(),
        V2 => HKDF_LABEL_IV_V2.to_string(),
        _ => {
            error!("Invalid version");
            "error".to_string()
        }
    }
}

/// Returns the appropriate HKDF header protection label for a given QUIC version.
///
/// # Arguments
///
/// * `v` - The QUIC version.
///
/// # Returns
///
/// * A string representing the HKDF header protection label.
fn header_protection_label(v: u32) -> String {
    match v {
        V1 => HKDF_LABEL_HP_V1.to_string(),
        V2 => HKDF_LABEL_HP_V2.to_string(),
        _ => {
            error!("Invalid version");
            "error".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_long_header() {
        assert!(is_long_header(0x80));
        assert!(!is_long_header(0x7F));
    }

    #[test]
    fn test_get_salt() {
        assert_eq!(get_salt(V1), QUIC_SALT_V1);
        assert_eq!(get_salt(V2), QUIC_SALT_V2);
        assert_eq!(get_salt(0x0), QUIC_SALT_OLD);
    }

    #[test]
    fn test_key_label() {
        assert_eq!(key_label(V1), HKDF_LABEL_KEY_V1);
        assert_eq!(key_label(V2), HKDF_LABEL_KEY_V2);
        assert_eq!(key_label(0x0), "error");
    }

    #[test]
    fn test_iv_label() {
        assert_eq!(iv_label(V1), HKDF_LABEL_IV_V1);
        assert_eq!(iv_label(V2), HKDF_LABEL_IV_V2);
        assert_eq!(iv_label(0x0), "error");
    }

    #[test]
    fn test_header_protection_label() {
        assert_eq!(header_protection_label(V1), HKDF_LABEL_HP_V1);
        assert_eq!(header_protection_label(V2), HKDF_LABEL_HP_V2);
        assert_eq!(header_protection_label(0x0), "error");
    }
}
