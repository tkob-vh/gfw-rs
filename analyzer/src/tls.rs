//! TLS (Transport Layer Security) module
//!
//! This module provides functionality to parse TLS handshake messages, specifically
//! the ClientHello and ServerHello messages. It also includes constants for various
//! TLS record and handshake message types, as well as extension types.

use bytes::{Buf, BytesMut};
use tracing::error;

use crate::PropMap;
use std::rc::Rc;

/// TLS record types.
/// TLS record type for handshake messages.
pub const RECORD_TYPE_HANDSHAKE: u8 = 0x16;

/// TLS handshake message types.
/// ```text
/// enum {
///          client_hello(1),
///          server_hello(2),
///          new_session_ticket(4),
///          end_of_early_data(5),
///          encrypted_extensions(8),
///          certificate(11),
///          certificate_request(13),
///          certificate_verify(15),
///          finished(20),
///          key_update(24),
///          message_hash(254),
///          (255)
/// } HandshakeType;
/// ```
/// TLS handshake message type for client hello.
pub const TYPE_CLIENT_HELLO: u8 = 0x01;
/// TLS handshake message type for server hello.
pub const TYPE_SERVER_HELLO: u8 = 0x02;

/// TLS extension numbers.
///
/// A number of TLS messages contain tag-length-value encoded extensions
/// structures. Refer to https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
///
/// struct {
///        ExtensionType extension_type;
///        opaque extension_data<0..2^16-1>;
/// } Extension;
///
/// enum {
///        server_name(0),                             /* RFC 6066 */
///        max_fragment_length(1),                     /* RFC 6066 */
///        status_request(5),                          /* RFC 6066 */
///        supported_groups(10),                       /* RFC 8422, 7919 */
///        signature_algorithms(13),                   /* RFC 8446 */
///        use_srtp(14),                               /* RFC 5764 */
///        heartbeat(15),                              /* RFC 6520 */
///        application_layer_protocol_negotiation(16), /* RFC 7301 */
///        signed_certificate_timestamp(18),           /* RFC 6962 */
///        client_certificate_type(19),                /* RFC 7250 */
///        server_certificate_type(20),                /* RFC 7250 */
///        padding(21),                                /* RFC 7685 */
///        pre_shared_key(41),                         /* RFC 8446 */
///        early_data(42),                             /* RFC 8446 */
///        supported_versions(43),                     /* RFC 8446 */
///        cookie(44),                                 /* RFC 8446 */
///        psk_key_exchange_modes(45),                 /* RFC 8446 */
///        certificate_authorities(47),                /* RFC 8446 */
///        oid_filters(48),                            /* RFC 8446 */
///        post_handshake_auth(49),                    /* RFC 8446 */
///        signature_algorithms_cert(50),              /* RFC 8446 */
///        key_share(51),                              /* RFC 8446 */
///        (65535)
/// } ExtensionType;
///
/// TLS extension type for server name indication (SNI).
const EXT_SERVER_NAME: u16 = 0x0000;
/// TLS extension type for application layer protocol negotiation (ALPN).
const EXT_ALPN: u16 = 0x0010;
/// TLS extension type for supported versions.
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
/// TLS extension type for encrypted client hello.
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// Parse the client hello message of tls
///
/// # Arguments
///
/// * `ch_buf` - A mutable reference to a `BytesMut` buffer containing the client hello message data.
///
/// Structure of this message:
/// ```text
/// uint16 ProtocolVersion;
/// opaque Random[32];
/// uint8 CipherSuite[2];    /* Cryptographic suite selector */
/// struct {
///          ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///          Random random;
///          opaque legacy_session_id<0..32>;
///          CipherSuite cipher_suites<2..2^16-2>;
///          opaque legacy_compression_methods<1..2^8-1>;
///          Extension extensions<8..2^16-1>;
/// } ClientHello;
/// ```
/// For more information, refer to <https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2>
pub fn parse_tls_client_hello_msg_data(ch_buf: &mut BytesMut) -> Option<PropMap> {
    let mut prop_map = PropMap::new();

    // Version, random & session ID length combined are within 35 bytes,
    // so no need for bounds checking
    prop_map.insert("version".to_string(), Rc::new(ch_buf.get_u16()));
    prop_map.insert("random".to_string(), Rc::new(ch_buf.split_to(32)));

    let session_id_len = ch_buf.get_u8();
    if ch_buf.len() < session_id_len as usize {
        error!(
            "Not enough data for session ID: session_id_len is {}, but the remaining bytes in ch_buf is {}",
            session_id_len, ch_buf.len()
        );
        return None;
    }
    prop_map.insert(
        "session".to_string(),
        Rc::new(ch_buf.split_to(session_id_len as usize)),
    );

    if ch_buf.len() < 2 {
        error!("No enough data for cipher suites length");
    }
    let cipher_suites_len = ch_buf.get_u16();

    if cipher_suites_len % 2 != 0 {
        error!("Cipher suites are 2 bytes each, so must be even");
        return None;
    }

    let mut ciphers = Vec::with_capacity(cipher_suites_len as usize / 2);
    for _ in 0..(cipher_suites_len / 2) {
        if ch_buf.len() < 2 {
            error!("No enough data for cipher suites");
            return None;
        }
        ciphers.push(ch_buf.get_u16());
    }

    prop_map.insert("ciphers".to_string(), Rc::new(ciphers));

    if ch_buf.is_empty() {
        error!("No enough data for compression methods length");
        return None;
    }
    let compression_method_len = ch_buf.get_u8();

    // Compression methods are 1 byte each, we just put a byte slice here
    if ch_buf.len() < compression_method_len as usize {
        error!("No enough data for compression methods");
        return None;
    }
    prop_map.insert(
        "compression".to_string(),
        Rc::new(ch_buf.split_to(compression_method_len as usize)),
    );

    if ch_buf.len() < 2 {
        error!("No extensions, maybe possible");
        return Some(prop_map);
    }
    let exts_len = ch_buf.get_u16();

    if ch_buf.len() < exts_len as usize {
        error!("No enough data fro extensions");
        return None;
    }
    let mut ext_buf = ch_buf.split_to(exts_len as usize);

    while !ext_buf.is_empty() {
        if ext_buf.len() < 2 {
            error!("No enough data for extension type");
            return None;
        }
        let ext_type = ext_buf.get_u16();

        if ext_buf.len() < 2 {
            error!("No enough data for extension length");
            return None;
        }
        let ext_len = ext_buf.get_u16();

        if ext_buf.len() < ext_len as usize {
            error!("No enough data for extension data");
            return None;
        }
        let mut ext_data_buf = ext_buf.split_to(ext_len as usize);

        if !parse_tls_extensions(ext_type, &mut ext_data_buf, &mut prop_map) {
            error!("Invalid extension");
            return None;
        }
    }

    Some(prop_map)
}

/// Parse the server hello message of tls
///
/// # Arguments
///
/// * `sh_buf` - A mutable reference to a `BytesMut` buffer containing the server hello message data.
///
/// Structure of this message:
/// ```text
/// struct {
///          ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///          Random random;
///          opaque legacy_session_id_echo<0..32>;
///          CipherSuite cipher_suite;
///          uint8 legacy_compression_method = 0;
///          Extension extensions<6..2^16-1>;
/// } ServerHello;
/// ```
/// For more information, refer to <https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3>
pub fn parse_tls_server_hello_msg_data(sh_buf: &mut BytesMut) -> Option<PropMap> {
    let mut prop_map = PropMap::new();
    // Version, random & session ID length combined are within 35 bytes,
    // so no need for bounds checking
    prop_map.insert("version".to_string(), Rc::new(sh_buf.get_u16()));
    prop_map.insert("random".to_string(), Rc::new(sh_buf.split_to(32)));
    let session_id_len = sh_buf.get_u8();

    if sh_buf.len() < session_id_len as usize {
        error!("No enough data for session");
        return None;
    }
    prop_map.insert(
        "session".to_string(),
        Rc::new(sh_buf.split_to(session_id_len as usize)),
    );

    if sh_buf.len() < 2 {
        error!("No enough data for cipher suite");
        return None;
    }
    let cipher_suite = sh_buf.get_u16();
    prop_map.insert("cipher".to_string(), Rc::new(cipher_suite));

    if sh_buf.is_empty() {
        error!("No enough data for compression method");
        return None;
    }
    let compression_method = sh_buf.get_u8();
    prop_map.insert("compression".to_string(), Rc::new(compression_method));

    if sh_buf.len() < 2 {
        error!("No extensions, maybe possible");
        return Some(prop_map);
    }
    let exts_len = sh_buf.get_u16();

    if sh_buf.len() < exts_len as usize {
        error!("No enough data for extensions");
        return None;
    }
    let mut ext_buf = sh_buf.split_to(exts_len as usize);

    while !ext_buf.is_empty() {
        if ext_buf.len() < 2 {
            error!("No enough dta for extension type");
            return None;
        }
        let ext_type = ext_buf.get_u16();

        if ext_buf.len() < 2 {
            error!("No enough data for extension length");
            return None;
        }
        let ext_len = ext_buf.get_u16();

        if ext_buf.len() < ext_len as usize {
            error!("No enough data for extension data");
            return None;
        }
        let mut ext_data_buf = ext_buf.split_to(ext_len as usize);

        if !parse_tls_extensions(ext_type, &mut ext_data_buf, &mut prop_map) {
            error!("Invalid extension");
            return None;
        }
    }

    Some(prop_map)
}

/// Parse the extension part of tls message.
///
/// # Arguments
///
/// - `ext_type`: The type of the extension.
/// - `ext_data_buf`: The byte buffer of the extension
/// - `prop_map`: The prop_map to be added.
///
/// # Returns
///
/// Whether the extension is parsed correctly.
pub fn parse_tls_extensions(
    ext_type: u16,
    ext_data_buf: &mut BytesMut,
    prop_map: &mut PropMap,
) -> bool {
    match ext_type {
        EXT_SERVER_NAME => {
            if ext_data_buf.len() < 2 {
                error!("No enough data for list length");
                return false;
            }
            // Ignore list length, we only care about the first entry for now
            let _ = ext_data_buf.get_u16();

            if ext_data_buf.is_empty() {
                error!("Not enough data for SNI type, or not hostname");
                return false;
            }
            let sni_type = ext_data_buf.get_u8();
            if sni_type != 0 {
                error!("Not hostname");
                return false;
            }

            if ext_data_buf.len() < 2 {
                error!("Not enough data for SNI length");
                return false;
            }
            let sni_len = ext_data_buf.get_u16();

            prop_map.insert(
                "sni".to_string(),
                Rc::new(ext_data_buf.split_to(sni_len as usize)),
            );
        }
        EXT_ALPN => {
            if ext_data_buf.len() < 2 {
                error!("No enough data for list length");
                return false;
            }
            // Ignore list length, we only care about the first entry for now
            let _ = ext_data_buf.get_u16();

            let mut alpn_list = BytesMut::new();
            while !ext_data_buf.is_empty() {
                //if ext_data_buf.is_empty() {
                //    error!("No enough data for ALPN length");
                //    return false;
                //}
                let apln_len = ext_data_buf.get_u8();

                if ext_data_buf.len() < apln_len as usize {
                    error!("No enough data for ALPN");
                    return false;
                }
                let alpn = ext_data_buf.split_to(apln_len as usize);

                alpn_list.extend(alpn);
            }

            prop_map.insert("alpn".to_string(), Rc::new(alpn_list));
        }
        EXT_SUPPORTED_VERSIONS => {
            if ext_data_buf.len() == 2 {
                // Server only selects one version
                prop_map.insert(
                    "supported_versions".to_string(),
                    Rc::new(ext_data_buf.get_u16()),
                );
            } else {
                // Client sends a list of versions

                // Ignore list length, as we read until the end
                if ext_data_buf.is_empty() {
                    error!("No enough data for list length");
                    return false;
                }
                let _ = ext_data_buf.get_u8();

                let mut versions = Vec::new();

                while !ext_data_buf.is_empty() {
                    if ext_data_buf.len() < 2 {
                        error!("No enough data for version");
                        return false;
                    }
                    let ver = ext_data_buf.get_u16();
                    versions.push(ver);
                }

                prop_map.insert("supported_versions".to_string(), Rc::new(versions));
            }
        }
        EXT_ENCRYPTED_CLIENT_HELLO => {
            // We can't parse ECH for now, just set a flag
            prop_map.insert("ech".to_string(), Rc::new(true));
        }
        _ => {
            //info!(
            //    "ext_type: {}, which is not in the list of the implemented ones.",
            //    ext_type
            //);
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;
    use bytes::BytesMut;
    use tracing_subscriber;

    #[test]
    fn test_parse_tls_client_hello_msg_data() {
        // construct a subscriber that prints formatted traces to stdout
        let subscriber = tracing_subscriber::FmtSubscriber::new();
        // use that subscriber to process traces emitted after this point
        let _ = tracing::subscriber::set_global_default(subscriber);

        // client hello without handshake type and length field.
        let mut ch_buf = BytesMut::from(
            hex::decode(concat!("030352362c1012cf23628256e745e903cea696e9f62",
            "a60ba0ae8311d70dea5e41949000004c03000ff020100006f000b000403000102000a00340032000e000d00",
            "19000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f00100",
            "01100230000000d00220020060106020603050105020503040104020403030103020303020102020203010",
            "1000f000101")).unwrap().as_slice()
        );

        let prop_map = parse_tls_client_hello_msg_data(&mut ch_buf).unwrap();

        assert_eq!(
            prop_map
                .get("version")
                .unwrap()
                .downcast_ref::<u16>()
                .unwrap(),
            &0x0303
        );
        assert_eq!(
            prop_map
                .get("random")
                .unwrap()
                .downcast_ref::<BytesMut>()
                .unwrap(),
            &BytesMut::from(
                &[
                    0x52, 0x36, 0x2c, 0x10, 0x12, 0xcf, 0x23, 0x62, 0x82, 0x56, 0xe7, 0x45, 0xe9,
                    0x3, 0xce, 0xa6, 0x96, 0xe9, 0xf6, 0x2a, 0x60, 0xba, 0xa, 0xe8, 0x31, 0x1d,
                    0x70, 0xde, 0xa5, 0xe4, 0x19, 0x49
                ][..]
            )
        );

        if prop_map.contains_key("session") {
            assert_eq!(
                prop_map
                    .get("session")
                    .unwrap()
                    .downcast_ref::<BytesMut>()
                    .unwrap(),
                &BytesMut::from(&[][..])
            );
        }

        assert_eq!(
            prop_map
                .get("ciphers")
                .unwrap()
                .downcast_ref::<Vec<u16>>()
                .unwrap(),
            &vec![0xc030, 0x00ff]
        );
        assert_eq!(
            prop_map
                .get("compression")
                .unwrap()
                .downcast_ref::<BytesMut>()
                .unwrap(),
            &BytesMut::from(&[0x1, 0x0][..])
        );
    }

    #[test]
    fn test_parse_tls_server_hello_msg_data() {
        // construct a subscriber that prints formatted traces to stdout
        let subscriber = tracing_subscriber::FmtSubscriber::new();
        // use that subscriber to process traces emitted after this point
        let _ = tracing::subscriber::set_global_default(subscriber);

        let mut sh_buf = BytesMut::from(
            &[
                0x03, 0x03, // version
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f, // random
                0x20, // session_id_len
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f, // session_id
                0x00, 0x2f, // cipher_suite
                0x00, // compression_method
                0x00, 0x05, // extensions_len
                0x00, 0x0a, 0x00, 0x01, 0x00, // extension
            ][..],
        );

        let prop_map = parse_tls_server_hello_msg_data(&mut sh_buf).unwrap();

        assert_eq!(
            prop_map
                .get("version")
                .unwrap()
                .downcast_ref::<u16>()
                .unwrap(),
            &0x0303
        );
        assert_eq!(
            prop_map
                .get("random")
                .unwrap()
                .downcast_ref::<BytesMut>()
                .unwrap(),
            &BytesMut::from(
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
                ][..]
            )
        );
        assert_eq!(
            prop_map
                .get("session")
                .unwrap()
                .downcast_ref::<BytesMut>()
                .unwrap(),
            &BytesMut::from(
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
                ][..]
            )
        );
        assert_eq!(
            prop_map
                .get("cipher")
                .unwrap()
                .downcast_ref::<u16>()
                .unwrap(),
            &0x002f
        );
        assert_eq!(
            prop_map
                .get("compression")
                .unwrap()
                .downcast_ref::<u8>()
                .unwrap(),
            &0x00
        );
    }
}
