//! DNS Analyzer Module
//!
//! This module provides functionality to analyze DNS traffic over both UDP and TCP protocols.
//! It includes implementations for DNS analyzers and streams, which parse and process DNS messages.
//!
//! # Structures
//!
//! - `DNSAnalyzer`: Implements the `Analyzer`, `UDPAnalyzer`, and `TCPAnalyzer` traits for DNS.
//! - `DNSUDPStream`: Implements the `UDPStream` trait for handling DNS messages over UDP.
//! - `DNSTCPStream`: Implements the `TCPStream` trait for handling DNS messages over TCP.
//!
//! # Functions
//!
//! - `parse_dns_message`: Parses a DNS message and returns a property map.
//! - `dns_rr_to_prop_map`: Converts a DNS response record to a property map.

use crate::analyzer::{self, PropUpdateType, TCPStream, UDPAnalyzer, UDPStream};
use crate::analyzer::{Analyzer, TCPAnalyzer};
use crate::utils;
use bytes::{Buf, BytesMut};
use pnet::packet::dns::{self};
use std::cell::RefCell;
use std::rc::Rc;
use tracing::error;

// The max number of consecutive invalid dns packets allowed.
// To allow non-DNS UDP traffic to get offloaded,
// we consider a UDP stream invalid and "done" if
// it has more than a certain number of consecutive
// packets that are not valid DNS messages.
const DNS_UDP_INVALID_COUNT_THRESHOLD: u32 = 4;

/// `DNSAnalyzer` should implement traits `UDPAnalyzer` and `TCPAnalyzer`(which two implement trait
/// `Analyzer`).
pub struct DNSAnalyzer {}

impl Analyzer for DNSAnalyzer {
    fn name(&self) -> &str {
        "dns"
    }

    /// DNS is a stateless protocol, with unlimited amount of back-and-forth exchanges.
    /// Don't limit it here.
    fn limit(&self) -> u32 {
        0
    }
}

impl UDPAnalyzer for DNSAnalyzer {
    /// The argument `info` is not used here.
    #[allow(unused_variables)]
    fn new_udp(&self, info: analyzer::UDPInfo) -> Box<dyn analyzer::UDPStream> {
        Box::new(DNSUDPStream::new())
    }
}

impl TCPAnalyzer for DNSAnalyzer {
    /// The argument `info` is not used here.
    #[allow(unused_variables)]
    fn new_tcp(&self, info: analyzer::TCPInfo) -> Box<dyn analyzer::TCPStream> {
        Box::new(DNSTCPStream::new())
    }
}

/// `DNSUDPStream` should implement trait `UDPStream`.
struct DNSUDPStream {
    /// The number of current invalid count of dns messages.
    invalid_count: u32,
}

impl DNSUDPStream {
    /// Initialize `DNSUDPStream`, with `invalid_count` set to 0.
    fn new() -> Self {
        Self { invalid_count: 0 }
    }
}

impl UDPStream for DNSUDPStream {
    /// The argument `rev` is not used here.
    #[allow(unused_variables)]
    fn feed(&mut self, rev: bool, data: &[u8]) -> (Option<analyzer::PropUpdate>, bool) {
        // Parse the DNS message first.
        let prop_map = match parse_dns_message(&BytesMut::from(data)) {
            Some(map) => map,
            None => {
                self.invalid_count += 1;
                return (None, self.invalid_count >= DNS_UDP_INVALID_COUNT_THRESHOLD);
            }
        };

        // Reset the invalid count on valid DNS message.
        self.invalid_count = 0;

        (
            Some(analyzer::PropUpdate {
                update_type: PropUpdateType::Replace,
                map: prop_map,
            }),
            false,
        )
    }

    /// The argument `limited` is not used here.
    #[allow(unused_variables)]
    fn close(&mut self, limited: bool) -> Option<analyzer::PropUpdate> {
        None
    }
}

/// `DNSTCPStream` should implement trait `TCPStream`.
pub struct DNSTCPStream {
    /// The bytebuffer of the request message.
    req_buf: BytesMut,
    /// The hashmap of the properties in the message.
    req_map: analyzer::PropMap,
    /// If the prop_map has been updated.
    req_updated: bool,
    /// The linear state machine which process the message with the methods in field `steps`.
    req_lsm: Rc<RefCell<utils::lsm::LinearStateMachine<DNSTCPStream>>>,
    /// Whether the request message has been processed.
    req_done: bool,

    resp_buf: BytesMut,
    resp_map: analyzer::PropMap,
    resp_updated: bool,
    resp_lsm: Rc<RefCell<utils::lsm::LinearStateMachine<DNSTCPStream>>>,
    resp_done: bool,

    /// The length of the request message.
    req_msg_len: u16,
    resp_msg_len: u16,
}

impl DNSTCPStream {
    /// Initialize the DNSTCPStream.
    /// We combine Rc and RefCell to allow multi-muttable owners.
    fn new() -> Self {
        Self {
            req_buf: BytesMut::new(),
            req_map: analyzer::PropMap::new(),
            req_updated: false,
            req_lsm: Rc::new(RefCell::new(utils::lsm::LinearStateMachine::new(vec![
                Box::new(|s| s.get_req_message_length()),
                Box::new(|s| s.get_req_message()),
            ]))),
            req_done: false,

            resp_buf: BytesMut::new(),
            resp_map: analyzer::PropMap::new(),
            resp_updated: false,
            resp_lsm: Rc::new(RefCell::new(utils::lsm::LinearStateMachine::new(vec![
                Box::new(|s| s.get_resp_message_length()),
                Box::new(|s| s.get_resp_message()),
            ]))),
            resp_done: false,

            req_msg_len: 0,
            resp_msg_len: 0,
        }
    }

    /// Get the length of the request message.
    /// The first step in the lsm of request message.
    ///
    /// # Returns
    ///
    /// The LSMAction (whether pause or continue).
    fn get_req_message_length(&mut self) -> utils::lsm::LSMAction {
        // Check the number of bytes in the request buffer.
        if self.req_buf.len() < 2 {
            return utils::lsm::LSMAction::Pause;
        }

        // Consume and return the first 2 bytes, with the remainings in req_buf.
        let mut bs = self.req_buf.split_to(2);

        // Get the message length(Big Enddian).
        self.req_msg_len = bs.get_u16();

        utils::lsm::LSMAction::Next
    }

    /// Get the length of the response message.
    /// The first step in the lsm of response message.
    ///
    /// # Returns
    ///
    /// The LSMAction (whether pause or continue).
    fn get_resp_message_length(&mut self) -> utils::lsm::LSMAction {
        // Check the number of bytes in the response buffer.
        if self.resp_buf.len() < 2 {
            return utils::lsm::LSMAction::Pause;
        }

        // Consume and return the first 2 bytes, with the remainings in resp_buf.
        let mut bs = self.resp_buf.split_to(2);

        // Get the message length(Big Enddian).
        self.resp_msg_len = bs.get_u16();

        utils::lsm::LSMAction::Next
    }

    /// Get the content of the request message.
    /// The second step in the lsm of request message.
    ///
    /// # Returns
    ///
    /// The LSMAction(whether pause, cancel or reset).
    fn get_req_message(&mut self) -> utils::lsm::LSMAction {
        // Check the number of bytes in the request buffer.
        if self.req_buf.len() < self.req_msg_len as usize {
            return utils::lsm::LSMAction::Pause;
        }

        // Consume and return the contents, with the remainings in req_buf.
        let bs = self.req_buf.split_to(self.req_msg_len as usize);

        // Parse the DNS message and get the properties map.
        let prop_map = match parse_dns_message(&bs) {
            Some(map) => map,
            None => return utils::lsm::LSMAction::Cancel,
        };

        self.req_map = prop_map;
        self.req_updated = true;

        // Successfully processed the message, and start from the beginning.
        utils::lsm::LSMAction::Reset
    }

    /// Get the content of the response message.
    /// The second step in the lsm of response message.
    ///
    /// # Returns
    ///
    /// The LSMAction(whether pause, cancel or reset).
    fn get_resp_message(&mut self) -> utils::lsm::LSMAction {
        // Check the number of bytes in the response buffer.
        if self.resp_buf.len() < self.resp_msg_len as usize {
            return utils::lsm::LSMAction::Pause;
        }

        // Consume and return the contents, with the remainings in resp_buf.
        let bs = self.resp_buf.split_to(self.resp_msg_len as usize);

        // Parse the DNS message and get the properties map.
        let prop_map = match parse_dns_message(&bs) {
            Some(map) => map,
            None => return utils::lsm::LSMAction::Cancel,
        };

        self.resp_map = prop_map;
        self.resp_updated = true;

        // Successfully processed the message, and start from the beginning.
        utils::lsm::LSMAction::Reset
    }
}

impl TCPStream for DNSTCPStream {
    /// The arguments 'start' and 'end' are not used here.
    #[allow(unused_variables)]
    fn feed(
        &mut self,
        rev: bool,
        start: bool,
        end: bool,
        skip: usize,
        data: &[u8],
    ) -> (Option<analyzer::PropUpdate>, bool) {
        if skip != 0 {
            return (None, true);
        }

        if data.is_empty() {
            return (None, false);
        }

        let mut update: Option<analyzer::PropUpdate> = None;
        let cancelled: bool;

        if rev {
            // It's a response message.

            // Append the data to response buffer.
            self.resp_buf.extend_from_slice(data);
            // Reset the value.
            self.resp_updated = false;

            // Run the lsm of the response message and get its final status.
            let lsm = self.resp_lsm.clone();
            (cancelled, self.resp_done) = (*lsm).borrow_mut().run(self);

            // If the prop_map has been updated, consume it.
            if self.resp_updated {
                update = Some(analyzer::PropUpdate {
                    update_type: analyzer::PropUpdateType::Replace,
                    map: self.resp_map.clone(),
                });
                self.resp_updated = false;
            }
        } else {
            // It's a request message.

            self.req_buf.extend_from_slice(data);
            self.req_updated = false;

            let lsm = self.req_lsm.clone();
            (cancelled, self.req_done) = (*lsm).borrow_mut().run(self);

            if self.req_updated {
                update = Some(analyzer::PropUpdate {
                    update_type: analyzer::PropUpdateType::Replace,
                    map: self.req_map.clone(),
                });
                self.req_updated = false;
            }
        }

        (update, cancelled || (self.req_done && self.resp_done))
    }

    /// The argument `limited` is not used here.
    #[allow(unused_variables)]
    fn close(&mut self, limited: bool) -> Option<analyzer::PropUpdate> {
        self.req_buf.clear();
        self.resp_buf.clear();

        self.req_map.clear();
        self.resp_map.clear();
        None
    }
}

/// Parse the DNS message and store them in the PropMap HashTable.
///
/// [The format of DNS
/// message](https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format)
///
/// # Arguments
///
/// `msg`: The bytes to be converted from.
///
/// # Returns
///
/// The final parsed DNS PropMap.
fn parse_dns_message(msg: &BytesMut) -> Option<analyzer::PropMap> {
    // Construct dns packet from the bytebuffer.
    let dns_packet = match dns::DnsPacket::new(msg) {
        Some(packet) => packet,
        None => {
            error!("Error with constructing DNS packet from bytebuffer.");
            return None;
        }
    };

    let mut prop_map = analyzer::PropMap::new();

    // Extract the properties from the dns packet and store them in the hashmap.

    // Process the flags:
    prop_map.insert("id".to_string(), Rc::new(dns_packet.get_id()));
    prop_map.insert("qr".to_string(), Rc::new(dns_packet.get_is_response()));
    prop_map.insert("opcode".to_string(), Rc::new(dns_packet.get_opcode()));
    prop_map.insert("aa".to_string(), Rc::new(dns_packet.get_is_authoriative()));
    prop_map.insert("tc".to_string(), Rc::new(dns_packet.get_is_truncated()));
    prop_map.insert(
        "rd".to_string(),
        Rc::new(dns_packet.get_is_recursion_desirable()),
    );
    prop_map.insert(
        "ra".to_string(),
        Rc::new(dns_packet.get_is_recursion_available()),
    );
    prop_map.insert("z".to_string(), Rc::new(dns_packet.get_zero_reserved()));
    prop_map.insert("rcode".to_string(), Rc::new(dns_packet.get_rcode()));

    // Process the queries.
    if dns_packet.get_query_count() > 0 {
        let mut prop_map_questions =
            vec![analyzer::PropMap::new(); dns_packet.get_query_count() as usize];

        for (i, q) in dns_packet.get_queries_iter().enumerate() {
            prop_map_questions[i].insert(
                "name".to_string(),
                Rc::new(String::from_utf8(q.get_qname())),
            );
            prop_map_questions[i].insert("type".to_string(), Rc::new(q.get_qtype()));
            prop_map_questions[i].insert("class".to_string(), Rc::new(q.get_qclass()));
        }

        prop_map.insert("questions".to_string(), Rc::new(prop_map_questions));
    }

    // Process the resourse records.
    if dns_packet.get_response_count() > 0 {
        let mut prop_map_answers =
            vec![analyzer::PropMap::new(); dns_packet.get_response_count() as usize];

        for (i, rr) in dns_packet.get_responses_iter().enumerate() {
            prop_map_answers[i] = dns_rr_to_prop_map(&rr);
        }

        prop_map.insert("answers".to_string(), Rc::new(prop_map_answers));
    }

    if dns_packet.get_authority_rr_count() > 0 {
        let mut prop_map_authorities =
            vec![analyzer::PropMap::new(); dns_packet.get_authority_rr_count() as usize];

        for (i, rr) in dns_packet.get_authorities_iter().enumerate() {
            prop_map_authorities[i] = dns_rr_to_prop_map(&rr);
        }

        prop_map.insert("authorities".to_string(), Rc::new(prop_map_authorities));
    }

    if dns_packet.get_additional_rr_count() > 0 {
        let mut prop_map_additionals =
            vec![analyzer::PropMap::new(); dns_packet.get_additional_rr_count() as usize];

        for (i, rr) in dns_packet.get_additional_iter().enumerate() {
            prop_map_additionals[i] = dns_rr_to_prop_map(&rr);
        }

        prop_map.insert("additionals".to_string(), Rc::new(prop_map_additionals));
    }

    Some(prop_map)
}

/// Convert a Response Record to PropMap.
///
/// # Arguments
///
/// `rr`: A response record
///
/// # Returns
///
/// A PropMap
fn dns_rr_to_prop_map(rr: &dns::DnsResponsePacket) -> analyzer::PropMap {
    let mut prop_map = analyzer::PropMap::new();

    prop_map.insert("name".to_string(), Rc::new(rr.get_name_tag().to_string()));
    prop_map.insert("type".to_string(), Rc::new(rr.get_rtype()));
    prop_map.insert("class".to_string(), Rc::new(rr.get_rclass()));
    prop_map.insert("ttl".to_string(), Rc::new(rr.get_ttl()));

    match rr.get_rtype() {
        dns::DnsTypes::A => {
            prop_map.insert("a".to_string(), Rc::new(rr.get_data()));
        }
        dns::DnsTypes::AAAA => {
            prop_map.insert("aaaa".to_string(), Rc::new(rr.get_data()));
        }
        dns::DnsTypes::NS => {
            prop_map.insert("ns".to_string(), Rc::new(rr.get_data()));
        }
        dns::DnsTypes::CNAME => {
            prop_map.insert("cname".to_string(), Rc::new(rr.get_data()));
        }
        dns::DnsTypes::PTR => {
            prop_map.insert("ptr".to_string(), Rc::new(rr.get_data()));
        }
        dns::DnsTypes::TXT => {
            prop_map.insert("txt".to_string(), Rc::new(rr.get_data()));
        }
        dns::DnsTypes::MX => {
            prop_map.insert("mx".to_string(), Rc::new(rr.get_data()));
        }
        _ => {}
    }

    prop_map
}
