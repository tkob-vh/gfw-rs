//! OpenVPN Analyzer Module
//!
//! This module provides functionality to analyze OpenVPN traffic over UDP and TCP.
//! It defines the `OpenVPNAnalyzer` struct which implements the `Analyzer`, `UDPAnalyzer`, and `TCPAnalyzer` traits.
//! It also defines the `OpenVPNUDPStream` and `OpenVPNTCPStream` structs which implement the `UDPStream` and `TCPStream` traits respectively.

use crate::*;
use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
use std::cell::RefCell;
use std::rc::Rc;

// packet opcodes -- the V1 is intended to allow protocol changes in the future
/// initial key from client, forget previous state
const OPENVPN_CONTROL_HARD_RESET_CLIENT_V1: u8 = 1;
/// initial key from server, forget previous state
const OPENVPN_CONTROL_HARD_RESET_SERVER_V1: u8 = 2;
/// new key, graceful transition from old to new key
const OPENVPN_CONTROL_SOFT_RESET_V1: u8 = 3;
/// control channel packet (usually TLS ciphertext)
const OPENVPN_CONTROL_V1: u8 = 4;
/// acknowledgement for packets received
const OPENVPN_ACK_V1: u8 = 5;
/// data channel packet
const OPENVPN_DATA_V1: u8 = 6;
/// data channel packet with peer-id
const OPENVPN_DATA_V2: u8 = 9;

// indicates key_method >= 2
/// initial key from client, forget previous state
const OPENVPN_CONTROL_HARD_RESET_CLIENT_V2: u8 = 7;
/// initial key from server, forget previous state
const OPENVPN_CONTROL_HARD_RESET_SERVER_V2: u8 = 8;

// indicates key_method >= 2 and client-specific tls-crypt key
/// initial key from client, forget previous state
const OPENVPN_CONTROL_HARD_RESET_CLIENT_V3: u8 = 10;

/// Variant of P_CONTROL_V1 but with appended wrapped key like OPENVPN_CONTROL_HARD_RESET_CLIENT_V3
const OPENVPN_CONTROL_WKC_V1: u8 = 11;

const OPENVPN_MIN_PKT_LEN: u16 = 6;
const OPENVPN_TCP_PKT_DEFAULT_LIMIT: u32 = 256;
const OPENVPN_UDP_PKT_DEFAULT_LIMIT: u32 = 256;

/// `OpenVPNAnalyzer` implements traits `UDPAnalyzer` andd `TCPAnalyzer`.
/// This struct is responsible for creating new UDP and TCP streams for OpenVPN analysis.
pub struct OpenVPNAnalyzer {}

impl Analyzer for OpenVPNAnalyzer {
    fn name(&self) -> &str {
        "openvpn"
    }

    fn limit(&self) -> u32 {
        0
    }
}

impl UDPAnalyzer for OpenVPNAnalyzer {
    /// The argument `info` is not used here.
    #[allow(unused_variables)]
    fn new_udp(&self, info: UDPInfo) -> Box<dyn UDPStream> {
        Box::new(OpenVPNUDPStream::new())
    }
}

impl TCPAnalyzer for OpenVPNAnalyzer {
    /// The argument `info` is not used here.
    #[allow(unused_variables)]
    fn new_tcp(&self, info: TCPInfo) -> Box<dyn TCPStream> {
        Box::new(OpenVPNTCPStream::new())
    }
}

/// Represents an OpenVPN packet (but ignore the payload).
///
/// This struct contains the opcode and keyid of an OpenVPN packet.
struct OpenVPNPkt {
    /// 16 bits, TCP protocol only
    //pkt_len: u16, // not used
    /// 5 bits
    opcode: u8,
    /// 3 bits, not used
    _keyid: u8,
    // We don't care abbout the rest of the packet (payload &[u8])
}

/// `OpenVPNStream` defines common apis for tcp and udp.
///
/// udp and tcp has different features for openvpn, so use trait to define a common api.
///
/// The `req_pkt_parse()` and `resp_pkt_parse()` in the original openVPNStream is replaced
/// by `parse_pkt()` in their(udp and tcp) separate structures.
trait OpenVPNStream {
    /// Parses a control hard reset client packet.
    ///
    /// # Returns
    ///
    /// An `LSMAction` indicating the result of the parsing.
    fn parse_ctl_hard_reset_client(&mut self) -> utils::lsm::LSMAction;

    /// Parses a control hard reset server packet.
    ///
    /// # Returns
    ///
    /// An `LSMAction` indicating the result of the parsing.
    fn parse_ctl_hard_reset_server(&mut self) -> utils::lsm::LSMAction;

    /// Parses a request packet.
    ///
    /// # Returns
    ///
    /// An `LSMAction` indicating the result of the parsing.
    fn parse_req(&mut self) -> utils::lsm::LSMAction;

    /// Parses a response packet.
    ///
    /// # Returns
    ///
    /// An `LSMAction` indicating the result of the parsing.
    fn parse_resp(&mut self) -> utils::lsm::LSMAction;
}

/// `OpenVPNUDPStream` implements trait `UDPStream`.
///
/// This struct is responsible for handling and parsing OpenVPN packets over UDP.
struct OpenVPNUDPStream {
    /// If the prop_map has been updated.
    req_updated: bool,
    req_lsm: Rc<RefCell<utils::lsm::LinearStateMachine<OpenVPNUDPStream>>>,
    /// Whether the request message has been processed.
    req_done: bool,

    resp_updated: bool,
    resp_lsm: Rc<RefCell<utils::lsm::LinearStateMachine<OpenVPNUDPStream>>>,
    resp_done: bool,

    /// The number of received packets
    rx_pkt_cnt: u32,
    /// The nubmer of sent packets
    tx_pkt_cnt: u32,

    pkt_limit: u32,

    /// the last received opcode.
    last_opcode: u8,

    cur_pkt: BytesMut,
    // We don't introduce `invalidCount` here to decrease the false positive rate
    // invalidCount int
}

impl OpenVPNUDPStream {
    /// Creates a new `OpenVPNUDPStream`.
    ///
    /// # Returns
    ///
    /// A new instance of `OpenVPNUDPStream`.
    fn new() -> Self {
        Self {
            req_updated: false,
            req_lsm: Rc::new(RefCell::new(utils::lsm::LinearStateMachine::new(vec![
                Box::new(|s| s.parse_ctl_hard_reset_client()),
                Box::new(|s| s.parse_req()),
            ]))),
            req_done: false,

            resp_updated: false,
            resp_lsm: Rc::new(RefCell::new(utils::lsm::LinearStateMachine::new(vec![
                Box::new(|s| s.parse_ctl_hard_reset_server()),
                Box::new(|s| s.parse_resp()),
            ]))),
            resp_done: false,

            rx_pkt_cnt: 0,
            tx_pkt_cnt: 0,
            pkt_limit: OPENVPN_UDP_PKT_DEFAULT_LIMIT,

            last_opcode: 0,

            cur_pkt: BytesMut::new(),
        }
    }

    /// Parses the current packet in the buffer.
    ///
    /// It is used to parse both the request message and the response message.
    ///
    /// # Returns
    ///
    /// A tuple containing an optional `OpenVPNPkt` and an `LSMAction`.
    fn parse_pkt(&mut self) -> (Option<OpenVPNPkt>, utils::lsm::LSMAction) {
        if self.cur_pkt == BytesMut::new() {
            return (None, utils::lsm::LSMAction::Pause);
        }

        if !openvpn_check_for_valid_opcode(self.cur_pkt.first().unwrap() >> 3) {
            return (None, utils::lsm::LSMAction::Cancel);
        }

        // Parse the packet header
        let packet = OpenVPNPkt {
            opcode: self.cur_pkt.first().unwrap() >> 3,
            _keyid: self.cur_pkt.first().unwrap() & 0x07,
            //pkt_len: 0, // not used
        };

        self.cur_pkt.clear();
        (Some(packet), utils::lsm::LSMAction::Next)
    }
}

impl OpenVPNStream for OpenVPNUDPStream {
    fn parse_ctl_hard_reset_client(&mut self) -> utils::lsm::LSMAction {
        let (pkt, action) = self.parse_pkt();
        if action != utils::lsm::LSMAction::Next {
            return action;
        }
        let opcode = pkt.unwrap().opcode;

        if opcode != OPENVPN_CONTROL_HARD_RESET_CLIENT_V1
            && opcode != OPENVPN_CONTROL_HARD_RESET_CLIENT_V2
            && opcode != OPENVPN_CONTROL_HARD_RESET_CLIENT_V3
        {
            return utils::lsm::LSMAction::Cancel;
        }

        self.last_opcode = opcode;

        utils::lsm::LSMAction::Next
    }

    fn parse_ctl_hard_reset_server(&mut self) -> utils::lsm::LSMAction {
        if self.last_opcode != OPENVPN_CONTROL_HARD_RESET_CLIENT_V1
            && self.last_opcode != OPENVPN_CONTROL_HARD_RESET_CLIENT_V2
            && self.last_opcode != OPENVPN_CONTROL_HARD_RESET_CLIENT_V3
        {
            return utils::lsm::LSMAction::Cancel;
        }

        let (pkt, action) = self.parse_pkt();

        if action != utils::lsm::LSMAction::Next {
            return action;
        }

        let opcode = pkt.unwrap().opcode;

        if opcode != OPENVPN_CONTROL_HARD_RESET_SERVER_V1
            && opcode != OPENVPN_CONTROL_HARD_RESET_SERVER_V2
        {
            return utils::lsm::LSMAction::Cancel;
        }

        self.last_opcode = opcode;

        utils::lsm::LSMAction::Next
    }

    fn parse_req(&mut self) -> utils::lsm::LSMAction {
        let (pkt, action) = self.parse_pkt();

        if action != utils::lsm::LSMAction::Next {
            return action;
        }

        let opcode = pkt.unwrap().opcode;

        if opcode != OPENVPN_CONTROL_SOFT_RESET_V1
            && opcode != OPENVPN_CONTROL_V1
            && opcode != OPENVPN_ACK_V1
            && opcode != OPENVPN_DATA_V1
            && opcode != OPENVPN_DATA_V2
            && opcode != OPENVPN_CONTROL_WKC_V1
        {
            return utils::lsm::LSMAction::Cancel;
        }

        self.tx_pkt_cnt += 1;
        self.req_updated = true;

        utils::lsm::LSMAction::Pause
    }

    fn parse_resp(&mut self) -> utils::lsm::LSMAction {
        let (pkt, action) = self.parse_pkt();

        if action != utils::lsm::LSMAction::Next {
            return action;
        }

        let opcode = pkt.unwrap().opcode;

        if opcode != OPENVPN_CONTROL_SOFT_RESET_V1
            && opcode != OPENVPN_CONTROL_V1
            && opcode != OPENVPN_ACK_V1
            && opcode != OPENVPN_DATA_V1
            && opcode != OPENVPN_DATA_V2
            && opcode != OPENVPN_CONTROL_WKC_V1
        {
            return utils::lsm::LSMAction::Cancel;
        }

        self.rx_pkt_cnt += 1;
        self.resp_updated = true;

        utils::lsm::LSMAction::Pause
    }
}

impl UDPStream for OpenVPNUDPStream {
    fn feed(&mut self, rev: bool, data: &[u8]) -> (Option<PropUpdate>, bool) {
        if data.is_empty() {
            return (None, false);
        }

        let mut update: Option<PropUpdate> = None;
        let cancelled: bool;
        self.cur_pkt = BytesMut::from(data);

        if rev {
            self.resp_updated = false;
            let lsm = self.resp_lsm.clone();
            (cancelled, self.resp_done) = (*lsm).borrow_mut().run(self);

            if self.resp_updated {
                let mut prop_map = PropMap::new();
                prop_map.insert("rx.pkt_cnt".to_string(), Rc::new(self.rx_pkt_cnt));
                prop_map.insert("tx_pkt_cnt".to_string(), Rc::new(self.tx_pkt_cnt));
                update = Some(PropUpdate {
                    update_type: PropUpdateType::Replace,
                    map: prop_map,
                });

                self.resp_updated = false;
            }
        } else {
            self.req_updated = false;

            let lsm = self.req_lsm.clone();
            (cancelled, self.req_done) = (*lsm).borrow_mut().run(self);

            if self.req_updated {
                let mut prop_map = PropMap::new();
                prop_map.insert("rx_pkt_cnt".to_string(), Rc::new(self.rx_pkt_cnt));
                prop_map.insert("tx_pkt_cnt".to_string(), Rc::new(self.tx_pkt_cnt));

                update = Some(PropUpdate {
                    update_type: PropUpdateType::Replace,
                    map: prop_map,
                });

                self.req_updated = false;
            }
        }

        (
            update,
            cancelled
                || (self.req_done && self.resp_done)
                || (self.rx_pkt_cnt + self.tx_pkt_cnt > self.pkt_limit),
        )
    }

    #[allow(unused_variables)]
    fn close(&mut self, limited: bool) -> Option<PropUpdate> {
        None
    }
}

/// `OpenVPNTCPStream` implements trait `TCPStream`.
struct OpenVPNTCPStream {
    /// If the prop_map has been updated.
    req_updated: bool,
    req_lsm: Rc<RefCell<utils::lsm::LinearStateMachine<OpenVPNTCPStream>>>,
    /// Whether the request message has been processed.
    req_done: bool,

    resp_updated: bool,
    resp_lsm: Rc<RefCell<utils::lsm::LinearStateMachine<OpenVPNTCPStream>>>,
    resp_done: bool,

    /// The number of received packets
    rx_pkt_cnt: u32,
    /// The nubmer of sent packets
    tx_pkt_cnt: u32,

    pkt_limit: u32,

    //
    last_opcode: u8,

    req_buf: BytesMut,
    resp_buf: BytesMut,
}

impl OpenVPNTCPStream {
    /// Creates a new `OpenVPNUDPStream`.
    ///
    /// # Returns
    ///
    /// A new instance of `OpenVPNUDPStream`.
    fn new() -> Self {
        Self {
            req_updated: false,
            req_lsm: Rc::new(RefCell::new(utils::lsm::LinearStateMachine::new(vec![
                Box::new(|s| s.parse_ctl_hard_reset_client()),
                Box::new(|s| s.parse_req()),
            ]))),
            req_done: false,

            resp_updated: false,
            resp_lsm: Rc::new(RefCell::new(utils::lsm::LinearStateMachine::new(vec![
                Box::new(|s| s.parse_ctl_hard_reset_server()),
                Box::new(|s| s.parse_resp()),
            ]))),
            resp_done: false,

            rx_pkt_cnt: 0,
            tx_pkt_cnt: 0,

            pkt_limit: OPENVPN_TCP_PKT_DEFAULT_LIMIT,

            last_opcode: 0,

            req_buf: BytesMut::new(),
            resp_buf: BytesMut::new(),
        }
    }

    /// Parses the current packet in the buffer.
    ///
    /// It is used to parse both the request message and the response message.
    ///
    /// # Arguments
    ///
    /// - `rev`: Whether it's a request or response.
    ///
    /// # Returns
    ///
    /// A tuple containing an optional `OpenVPNPkt` and an `LSMAction`.
    fn parse_pkt(&mut self, rev: bool) -> (Option<OpenVPNPkt>, utils::lsm::LSMAction) {
        let buffer = match rev {
            true => &mut self.resp_buf,
            false => &mut self.req_buf,
        };

        // Parse the packet length
        let pkt_len = match buffer.get(0..2) {
            Some(bytes) => BigEndian::read_u16(bytes),
            None => return (None, utils::lsm::LSMAction::Pause),
        };

        if pkt_len < OPENVPN_MIN_PKT_LEN {
            return (None, utils::lsm::LSMAction::Cancel);
        }

        // Get the opcode
        let pkt_op = match buffer.get(2) {
            Some(bytes) => *bytes,
            None => return (None, utils::lsm::LSMAction::Pause),
        };

        if !openvpn_check_for_valid_opcode(pkt_op >> 3) {
            return (None, utils::lsm::LSMAction::Cancel);
        }

        if buffer.len() < (pkt_len + 2) as usize {
            return (None, utils::lsm::LSMAction::Pause);
        }
        let mut pkt = buffer.split_to((pkt_len + 2) as usize);
        let _ = pkt.split_to(2);

        // Parse packet header
        (
            Some(OpenVPNPkt {
                //pkt_len,
                opcode: pkt_op >> 3,
                _keyid: pkt_op & 0x07,
            }),
            utils::lsm::LSMAction::Next,
        )
    }
}

impl OpenVPNStream for OpenVPNTCPStream {
    fn parse_ctl_hard_reset_client(&mut self) -> utils::lsm::LSMAction {
        let (pkt, action) = self.parse_pkt(false);
        if action != utils::lsm::LSMAction::Next {
            return action;
        }
        let opcode = pkt.unwrap().opcode;

        if opcode != OPENVPN_CONTROL_HARD_RESET_CLIENT_V1
            && opcode != OPENVPN_CONTROL_HARD_RESET_CLIENT_V2
            && opcode != OPENVPN_CONTROL_HARD_RESET_CLIENT_V3
        {
            return utils::lsm::LSMAction::Cancel;
        }

        self.last_opcode = opcode;

        utils::lsm::LSMAction::Next
    }
    fn parse_ctl_hard_reset_server(&mut self) -> utils::lsm::LSMAction {
        if self.last_opcode != OPENVPN_CONTROL_HARD_RESET_CLIENT_V1
            && self.last_opcode != OPENVPN_CONTROL_HARD_RESET_CLIENT_V2
            && self.last_opcode != OPENVPN_CONTROL_HARD_RESET_CLIENT_V3
        {
            return utils::lsm::LSMAction::Cancel;
        }

        let (pkt, action) = self.parse_pkt(true);
        if action != utils::lsm::LSMAction::Next {
            return action;
        }

        let opcode = pkt.unwrap().opcode;

        if opcode != OPENVPN_CONTROL_HARD_RESET_SERVER_V1
            && opcode != OPENVPN_CONTROL_HARD_RESET_SERVER_V2
        {
            return utils::lsm::LSMAction::Cancel;
        }
        self.last_opcode = opcode;

        utils::lsm::LSMAction::Next
    }
    fn parse_req(&mut self) -> utils::lsm::LSMAction {
        let (pkt, action) = self.parse_pkt(false);

        if action != utils::lsm::LSMAction::Next {
            return action;
        }

        let opcode = pkt.unwrap().opcode;

        if opcode != OPENVPN_CONTROL_SOFT_RESET_V1
            && opcode != OPENVPN_CONTROL_V1
            && opcode != OPENVPN_ACK_V1
            && opcode != OPENVPN_DATA_V1
            && opcode != OPENVPN_DATA_V2
            && opcode != OPENVPN_CONTROL_WKC_V1
        {
            return utils::lsm::LSMAction::Cancel;
        }

        self.tx_pkt_cnt += 1;
        self.req_updated = true;

        utils::lsm::LSMAction::Pause
    }
    fn parse_resp(&mut self) -> utils::lsm::LSMAction {
        let (pkt, action) = self.parse_pkt(true);

        if action != utils::lsm::LSMAction::Next {
            return action;
        }

        let opcode = pkt.unwrap().opcode;

        if opcode != OPENVPN_CONTROL_SOFT_RESET_V1
            && opcode != OPENVPN_CONTROL_V1
            && opcode != OPENVPN_ACK_V1
            && opcode != OPENVPN_DATA_V1
            && opcode != OPENVPN_DATA_V2
            && opcode != OPENVPN_CONTROL_WKC_V1
        {
            return utils::lsm::LSMAction::Cancel;
        }

        self.rx_pkt_cnt += 1;
        self.resp_updated = true;

        utils::lsm::LSMAction::Pause
    }
}

impl TCPStream for OpenVPNTCPStream {
    #[allow(unused_variables)]
    fn feed(
        &mut self,
        rev: bool,
        start: bool,
        end: bool,
        skip: usize,
        data: &[u8],
    ) -> (Option<PropUpdate>, bool) {
        if skip != 0 {
            return (None, false);
        }

        if data.is_empty() {
            return (None, false);
        }

        let mut update: Option<PropUpdate> = None;
        let cancelled;

        if rev {
            self.resp_buf.extend_from_slice(data);
            self.resp_updated = false;
            let lsm = self.resp_lsm.clone();
            (cancelled, self.resp_done) = (*lsm).borrow_mut().run(self);

            if self.resp_updated {
                let mut prop_map = PropMap::new();
                prop_map.insert("rx_pkt_cnt".to_string(), Rc::new(self.rx_pkt_cnt));
                prop_map.insert("tx_pkt_cnt".to_string(), Rc::new(self.tx_pkt_cnt));

                update = Some(PropUpdate {
                    update_type: PropUpdateType::Replace,
                    map: prop_map,
                });
                self.resp_updated = false;
            }
        } else {
            self.req_buf.extend_from_slice(data);
            self.req_updated = false;
            let lsm = self.req_lsm.clone();
            (cancelled, self.req_done) = (*lsm).borrow_mut().run(self);

            if self.req_updated {
                let mut prop_map = PropMap::new();
                prop_map.insert("rx_pkt_cnt".to_string(), Rc::new(self.rx_pkt_cnt));
                prop_map.insert("tx_pkt_cnt".to_string(), Rc::new(self.tx_pkt_cnt));

                update = Some(PropUpdate {
                    update_type: PropUpdateType::Merge,
                    map: prop_map,
                });
                self.req_updated = false;
            }
        }

        (
            update,
            cancelled
                || (self.req_done && self.resp_done)
                || (self.rx_pkt_cnt + self.tx_pkt_cnt > self.pkt_limit),
        )
    }

    #[allow(unused_variables)]
    fn close(&mut self, limited: bool) -> Option<PropUpdate> {
        self.req_buf.clear();
        self.resp_buf.clear();
        None
    }
}

/// Check whether the opcode is valid.
///
/// # Arguments
///
/// * `opcode`: the opcode to be checked.
///
/// # Returns
///
/// Whether it's valid.
fn openvpn_check_for_valid_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        OPENVPN_CONTROL_HARD_RESET_CLIENT_V1
            | OPENVPN_CONTROL_HARD_RESET_SERVER_V1
            | OPENVPN_CONTROL_SOFT_RESET_V1
            | OPENVPN_CONTROL_V1
            | OPENVPN_ACK_V1
            | OPENVPN_DATA_V1
            | OPENVPN_CONTROL_HARD_RESET_CLIENT_V2
            | OPENVPN_CONTROL_HARD_RESET_SERVER_V2
            | OPENVPN_DATA_V2
            | OPENVPN_CONTROL_HARD_RESET_CLIENT_V3
            | OPENVPN_CONTROL_WKC_V1
    )
}

#[cfg(test)]
mod tests {

    use super::*;
    use bytes::BytesMut;
    use utils::lsm::LSMAction;

    #[test]
    fn test_openvpn_analyzer_name() {
        let analyzer = OpenVPNAnalyzer {};
        assert_eq!(analyzer.name(), "openvpn");
    }

    #[test]
    fn test_openvpn_analyzer_limit() {
        let analyzer = OpenVPNAnalyzer {};
        assert_eq!(analyzer.limit(), 0);
    }

    #[test]
    fn test_openvpn_udp_stream_new() {
        let stream = OpenVPNUDPStream::new();
        assert_eq!(stream.rx_pkt_cnt, 0);
        assert_eq!(stream.tx_pkt_cnt, 0);
        assert_eq!(stream.pkt_limit, OPENVPN_UDP_PKT_DEFAULT_LIMIT);
    }

    #[test]
    fn test_openvpn_udp_stream_parse_pkt() {
        let mut stream = OpenVPNUDPStream::new();
        stream.cur_pkt = BytesMut::from(hex::decode(concat!("20573714a917f36048309c348cccf0903",
        "9f1bba5dd530ceb3c426623880000000550ff262b00000000024886f70d0101050500307a310b30090603550406",
        "13024154310b3009060355040813024f45310d300b0603550407130450524f33310d300b060355040a130450524",
        "f33310d300b060355040b130450524f33310d300b0603550403130450524f33310d30")).unwrap().as_slice());

        let (pkt, action) = stream.parse_pkt();
        assert_eq!(action, LSMAction::Next);
        assert!(pkt.is_some());
        assert_eq!(pkt.unwrap().opcode, 4);
    }

    #[test]
    fn test_openvpn_tcp_stream_new() {
        let stream = OpenVPNTCPStream::new();
        assert_eq!(stream.rx_pkt_cnt, 0);
        assert_eq!(stream.tx_pkt_cnt, 0);
        assert_eq!(stream.pkt_limit, OPENVPN_TCP_PKT_DEFAULT_LIMIT);
    }

    #[test]
    fn test_openvpn_tcp_stream_parse_pkt() {
        let mut stream = OpenVPNTCPStream::new();
        stream.req_buf = BytesMut::from(hex::decode(concat!("008e2057c9b6c4689e6ad488771fd7546",
        "877be317f88ee75e7fd0d3f4d5a250000004850ff2102000000002832a4c975d9b09bfbc9ec7cb27cd6d803b6a2",
        "c46a357b0ab1fd1af2c7bc2efaf727d0e94cc95accf3d6e1735003f873450d895afcdf0bd971ac77ba60a9b8f0f",
        "d7fe4f1d8f184778aede41a03f30d6d8a12f72b38a90f8b9775fc4bd7d94a60d02136c181")).unwrap().as_slice());

        let (pkt, action) = stream.parse_pkt(false);
        assert_eq!(action, LSMAction::Next);
        assert!(pkt.is_some());
        assert_eq!(pkt.unwrap().opcode, 4);
    }

    #[test]
    fn test_openvpn_udp_stream_feed() {
        let mut stream = OpenVPNUDPStream::new();

        // OPENVPN_CONTROL_HARD_RESET_CLIENT_V2
        let mut data = hex::decode(concat!(
            "38813814621d67462dde86734d2cbff151b2b1231b61e",
            "42308a272818e0000000150ff262c0000000000"
        ))
        .unwrap();
        let (update, cancelled) = stream.feed(false, &data);

        assert!(update.is_none());
        assert!(!cancelled);

        // OPENVPN_CONTROL_HARD_RESET_SERVER_V2
        data = hex::decode(concat!(
            "40573714a917f36048885887cdb6dd77785d00d15edbbe9aa6203a45570000000150ff262b0100000000813",
            "814621d67462d00000000"
        ))
        .unwrap();
        let (update, cancelled) = stream.feed(true, &data);

        assert!(update.is_none());
        assert!(!cancelled);

        // OPENVPN_CONTROL_V1
        data = hex::decode(concat!("20573714a917f36048309c348cccf0903",
        "9f1bba5dd530ceb3c426623880000000550ff262b00000000024886f70d0101050500307a310b30090603550406",
        "13024154310b3009060355040813024f45310d300b0603550407130450524f33310d300b060355040a130450524",
        "f33310d300b060355040b130450524f33310d300b0603550403130450524f33310d30")).unwrap();

        let (update, cancelled) = stream.feed(false, &data);

        assert!(update.is_some());
        assert!(!cancelled);

        // OPENVPN_CONTROL_V1
        data = hex::decode(concat!("20573714a917f36048309c348cccf0903",
        "9f1bba5dd530ceb3c426623880000000550ff262b00000000024886f70d0101050500307a310b30090603550406",
        "13024154310b3009060355040813024f45310d300b0603550407130450524f33310d300b060355040a130450524",
        "f33310d300b060355040b130450524f33310d300b0603550403130450524f33310d30")).unwrap();

        let (update, cancelled) = stream.feed(true, &data);

        assert!(update.is_some());

        if let Some(update) = update {
            for (key, value) in update.map.iter() {
                println!("{}: {:?}", key, value);
            }
        }

        assert!(!cancelled);
    }

    #[test]
    fn test_openvpn_tcp_stream_feed() {
        let mut stream = OpenVPNTCPStream::new();

        // OPENVPN_CONTROL_HARD_RESET_CLIENT_V2
        let mut data = hex::decode(concat!(
            "002a3828e1328a7185e6ca779cda2d2230e4755040a7",
            "8df956f0268c51fb710000000150ff20fd0000000000"
        ))
        .unwrap();
        let (update, cancelled) = stream.feed(false, true, false, 0, &data);

        assert!(update.is_none());
        assert!(!cancelled);

        // OPENVPN_CONTROL_HARD_RESET_SERVER_V2
        data = hex::decode(concat!(
            "003640593c3c23232bb90a81031ac1c7fa0bc64c2e29e4a732947a6084f5aa0000000150ff20fc01000000",
            "0028e1328a7185e6ca00000000"
        ))
        .unwrap();
        let (update, cancelled) = stream.feed(true, true, false, 0, &data);

        assert!(update.is_none());
        assert!(!cancelled);

        // OPENVPN_ACK_V1
        data = hex::decode(concat!(
            "00322828e1328a7185e6ca9deee33203672b1962bbae8eda97f7d57d1bae750000000250ff20fd01000000",
            "00593c3c23232bb90a"
        ))
        .unwrap();
        let (update, cancelled) = stream.feed(false, true, false, 0, &data);

        assert!(update.is_some());
        assert!(!cancelled);

        // OPENVPN_ACK_V1
        data = hex::decode(concat!(
            "003228593c3c23232bb90a6a1ac34d1e4b24fbb0149a6deaa049667bf116520000000250ff20fc01000000",
            "0128e1328a7185e6ca"
        ))
        .unwrap();
        let (update, cancelled) = stream.feed(true, true, false, 0, &data);

        assert!(update.is_some());
        assert!(!cancelled);

        if let Some(update) = update {
            for (key, value) in update.map.iter() {
                println!("{}: {:?}", key, value);
            }
        }

        assert!(!cancelled);
    }
}
