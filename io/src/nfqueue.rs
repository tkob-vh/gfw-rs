//! This module provides functionality for managing and interacting with the NFQUEUE subsystem
//! in the Linux kernel. It includes methods for setting up nftables rules, registering packet
//! processing callbacks, and setting verdicts on packets. The module also provides a way to
//! establish protected TCP connections that are governed by the NFQUEUE rules.
//!
//! # References
//!
//! <https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Ct>
//! <https://www.netfilter.org/documentation/index.html>
//!
//! # TODO:
//! * The iptables is not currently implemented. The nft command should be installed on the system.
//! * The Close function is not implemented. (It is used like RAII in go).
//! * The addr family is assumed ipv4.

use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::{any::Any, process::Command, sync::Arc, time::SystemTime};

use nfq::{Conntrack, Message, Queue};
use snafu::{ResultExt, Whatever};
use socket2::{Domain, Socket, Type};
use tokio::{net::TcpStream, sync::Mutex};
use tracing::error;

use crate::{Packet, PacketCallback, PacketIO, Verdict};

const NFQUEUE_NUM: u16 = 100;
const NFQUEUE_MAX_PACKET_LEN: u16 = 0xffff;
const NFQUEUE_DEFAULT_QUEUE_SIZE: u32 = 128;

const NFQUEUE_CONN_MARK_ACCEPT: u32 = 1001;
const NFQUEUE_CONN_MARK_DROP: u32 = 1002;

const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "opengfw";

/// A table in nftables is a namespace that contains a collection of chains, rules, sets, and other objects.
struct NftTableSpec {
    /// Named constants that can be referenced in the rules.
    defines: Vec<String>,

    /// Each table must have an address family assigned. The address family defines the packet types that this table processes.
    ///
    /// `ip`: Matches only IPv4 packets. This is the default if you do not specify an address family.
    /// `ip6`: Matches only IPv6 packets.
    /// `inet`: Matches both IPv4 and IPv6 packets.
    /// `arp`: Matches IPv4 address resolution protocol (ARP) packets.
    /// `bridge`: Matches packets that pass through a bridge device.
    /// `netdev`: Matches packets from ingress.
    family: String,

    /// The table name.
    table: String,

    /// The chains in the table.
    chains: Vec<NftChainSpec>,
}

/// Tables consist of chains which in turn are containers for rules. The following two rule types exists:
///
/// `Base chain`: You can use base chains as an entry point for packets from the networking stack.
/// `Regular chain`: You can use regular chains as a jump target to better organize rules.
///
/// Chain Types:
/// `filter`: Standard chain type.
/// `nat`: Chains of this type perform native address translation based on connection tracking entries. Only the first packet traverses this chain type.
/// `route`: Accepted packets that traverse this chain type cause a new route lookup if relevant parts of the IP header have changed.
///
/// Chain Priorities:
///
/// The priority parameter specifies the order in which packets traverse chains with the same hook value. You can set this parameter to an integer value or use a standard priority name.
///
/// `raw`, `mangle`, `dstnat`, 'filter', `security`, `srcnat`, `out`.
///
/// Chain Policies:
///
/// The chain policy defines whether nftables should accept or drop packets if rules in this chain do not specify any action.
///
/// `accept`(default)
/// `drop`
struct NftChainSpec {
    /// The chain name.
    chain: String,

    /// Format:
    ///
    /// type <type> hook <hook> priority <priority> policy <policy> ;
    header: String,

    /// The rules in the chain.
    rules: Vec<String>,
}

/// Generate rules for nftables.
///
/// # Arguments
/// * `local` -
/// * `rst` -
///
/// # Returns
///
/// A new NftTableSpec or None
fn generate_nft_rules(local: bool, rst: bool) -> Option<NftTableSpec> {
    if local && rst {
        error!("TCP rst is not suppored in local mode");
        return None;
    }

    // Define constants which can be used in the rules.
    let defines = vec![
        format!("define ACCEPT_CTMARK={}", NFQUEUE_CONN_MARK_ACCEPT),
        format!("define DROP_CTMARK={}", NFQUEUE_CONN_MARK_DROP),
        format!("define QUEUE_NUM={}", NFQUEUE_NUM),
    ];

    let mut chains;

    // Create the chains in the table.
    if local {
        chains = vec![
            NftChainSpec {
                chain: "INPUT".to_string(),
                header: "type filter hook input priority filter; policy accept;".to_string(),
                rules: Vec::new(),
            },
            NftChainSpec {
                chain: "OUTPUT".to_string(),
                header: "type filter hook output priority filter; policy accept;".to_string(),
                rules: Vec::new(),
            },
        ];
    } else {
        chains = vec![NftChainSpec {
            chain: "FORWARD".to_string(),
            header: "type filter hook forward priority filter; policy accept;".to_string(),
            rules: Vec::new(),
        }];
    }

    // Add rules in each chain.
    // - Packets with the `$ACCEPT_CTMARK` mark are accepted.
    // - Packets with the `$DROP_CTMARK` mark are either rejected with a TCP reset (if `rst` is true) or dropped.
    // - All packets are sent to the specified NFQUEUE number (`$QUEUE_NUM`) for further processing, with a bypass option if the queue is full.
    for chain in &mut chains {
        // Match packets that have metadata mark equal to `$ACCEPT_CTMARK`.
        // Set the conntrack mark of the packet to `$ACCEPT_CTMARK`.
        chain
            .rules
            .push("meta mark $ACCEPT_CTMARK ct mark set $ACCEPT_CTMARK".to_string());
        // Match packets that have conntrack mark equal to `$ACCEPT_CTMARK`.
        // Increment the packet counter.
        // Accept the packet, allowing it to continue through the network stack.
        chain
            .rules
            .push("ct mark $ACCEPT_CTMARK counter accept".to_string());
        if rst {
            // Match packets that use the TCP protocal.
            // Match packets that have a conntrack mark equal to `$DROP_CTMARK`.
            // Increment the packet counter.
            // Reject the packet and sends a TCP reset packet back to the sender.
            chain.rules.push(
                "ip protocol tcp ct mark $DROP_CTMARK counter reject with tcp reset".to_string(),
            );
        }
        // Match packets that hve a conntrack mark equal to `$DROP_CTMARK`.
        // Increment the packet counter.
        // Drop the packet, preventing it from continuing through the network stack.
        chain
            .rules
            .push("ct mark $DROP_CTMARK counter drop".to_string());
        // Increment the packet counter.
        // Send the pacet to the specified NFQUEUE number.
        // Allow the packet to bypass the queue if the queue is full.
        chain
            .rules
            .push("counter queue num $QUEUE_NUM bypass".to_string());
    }

    Some(NftTableSpec {
        defines,
        family: NFT_FAMILY.to_string(),
        table: NFT_TABLE.to_string(),
        chains,
    })
}

// Iptables not implemented for now.
//struct IptRule {
//    table: String,
//    chain: String,
//    rule_spec: Vec<String>,
//}
//
//fn generate_ipt_rules(local: bool, rst: bool) -> Option<Vec<IptRule>> {
//    if local && rst {
//        error!("TCP rst is not supported in local mode");
//        return None;
//    }
//    let chains = if local {
//        vec!["INPUT".to_string(), "OUTPUT".to_string()]
//    } else {
//        vec!["FORWARD".to_string()]
//    };
//
//    let mut rules: Vec<IptRule> = Vec::with_capacity(4 * chains.len());
//
//    for chain in chains {
//        rules.push(IptRule {
//            table: "filter".to_string(),
//            chain: chain.clone(),
//            rule_spec: vec![
//                "-m".to_string(),
//                "mark".to_string(),
//                "--mark".to_string(),
//                NFQUEUE_CONN_MARK_ACCEPT.to_string(),
//                "-j".to_string(),
//                "CONNMARK".to_string(),
//                "--set-mark".to_string(),
//                NFQUEUE_CONN_MARK_ACCEPT.to_string(),
//            ],
//        });
//
//        rules.push(IptRule {
//            table: "filter".to_string(),
//            chain: chain.clone(),
//            rule_spec: vec![
//                "-m".to_string(),
//                "connmark".to_string(),
//                "--mark".to_string(),
//                NFQUEUE_CONN_MARK_ACCEPT.to_string(),
//                "-j".to_string(),
//                "ACCEPT".to_string(),
//            ],
//        });
//
//        if rst {
//            rules.push(IptRule {
//                table: "filter".to_string(),
//                chain: chain.clone(),
//                rule_spec: vec![
//                    "-p".to_string(),
//                    "tcp".to_string(),
//                    "-m".to_string(),
//                    "connmark".to_string(),
//                    "--mark".to_string(),
//                    NFQUEUE_CONN_MARK_DROP.to_string(),
//                    "-j".to_string(),
//                    "REJECT".to_string(),
//                    "--reject-with".to_string(),
//                    "tcp-reset".to_string(),
//                ],
//            });
//        }
//
//        rules.push(IptRule {
//            table: "filter".to_string(),
//            chain: chain.clone(),
//            rule_spec: vec![
//                "-m".to_string(),
//                "connmark".to_string(),
//                "--mark".to_string(),
//                NFQUEUE_CONN_MARK_DROP.to_string(),
//                "-j".to_string(),
//                "DROP".to_string(),
//            ],
//        });
//
//        rules.push(IptRule {
//            table: "filter".to_string(),
//            chain,
//            rule_spec: vec![
//                "-j".to_string(),
//                "NFQUEUE".to_string(),
//                "--queue-num".to_string(),
//                NFQUEUE_NUM.to_string(),
//                "--queue-bypass".to_string(),
//            ],
//        });
//    }
//
//    Some(rules)
//}

/// The `NFQueuePacketIO` struct is responsible for managing the interaction with the NFQUEUE subsystem
/// in the Linux kernel. It provides methods to set up nftables rules, register packet processing callbacks,
/// and set verdicts on packets.
pub struct NFQueuePacketIO {
    /// represents the NFQUEUE used for packet processing.
    queue: Arc<Mutex<Queue>>,

    /// A boolean flag indicating whether the packet processing is in local mode.
    local: bool,

    /// A boolean flag indicating whether TCP reset is enabled for dropped packets.
    rst: bool,

    /// A boolean flag indicating whether the nftables/iptables rules have been set.
    rule_set: bool,
    // An `NFQueuePacketIOConfig` struct that holds the configuration for the NFQUEUE.
    //config: NFQueuePacketIOConfig,
}

/// Configuration for the `NFQueuePacketIO` struct.
///
/// `read_buffer` and `write_buffer` not implemented now.
#[derive(Debug, Clone)]
pub struct NFQueuePacketIOConfig {
    /// The maximum number of packets that can be queued in the NFQUEUE.
    queue_size: u32,
    //read_buffer: u32,
    //write_buffer: u32,
    /// A boolean flag indicating whether the packet processing is in local mode.
    local: bool,

    /// A boolean flag indicating whether TCP reset is enabled for dropped packets.
    rst: bool,
}

impl Default for NFQueuePacketIOConfig {
    fn default() -> Self {
        Self {
            queue_size: NFQUEUE_DEFAULT_QUEUE_SIZE,
            //read_buffer: 0,
            //write_buffer: 0,
            local: false,
            rst: false,
        }
    }
}

impl NFQueuePacketIO {
    /// Construct a new NFQueuePacketIO instance according to the config.
    pub fn new(config: NFQueuePacketIOConfig) -> Option<Self> {
        // Check if nft is available
        if Command::new("nft").arg("--version").output().is_err() {
            error!("nft required but not found in the $PATH");
            return None;
        }

        // Open a netfilter queue.
        let mut queue = match Queue::open() {
            Ok(q) => q,
            Err(e) => {
                error!("Failed to open queue: {}", e);
                return None;
            }
        };

        // Bind the queue to specific queue number.
        if let Err(e) = queue.bind(NFQUEUE_NUM) {
            error!("Failed to bind queue: {}", e);
            return None;
        }

        // Set the copy range. Packets larger than the range will be truncated.
        if let Err(e) = queue.set_copy_range(NFQUEUE_NUM, NFQUEUE_MAX_PACKET_LEN) {
            error!("Failed to set copy range: {}", e);
            return None;
        }

        // Set the max queue length.
        if let Err(e) = queue.set_queue_max_len(NFQUEUE_NUM, config.queue_size) {
            error!("Failed to set queue max length: {}", e);
            return None;
        }

        // Set the recv function not blocking.
        queue.set_nonblocking(true);

        // copy_mode and flags not set currently. Maybe will incurred some errors.
        // read_buffer and write_buffer is not set too.

        println!("AAAAA");
        Some(Self {
            queue: Arc::new(Mutex::new(queue)),
            local: config.local,
            rst: config.rst,
            rule_set: false,
            //config,
        })
    }

    /// Setup the nftables.
    ///
    /// # Arguments
    ///
    /// * `remove`: Whether to remove rules or add rules.
    async fn setup_nft(&self, remove: bool) -> Result<(), Box<dyn std::error::Error>> {
        if remove {
            // `nft delete table inet opengfw`
            let output = Command::new("nft")
                .args(["delete", "table", NFT_FAMILY, NFT_TABLE])
                .output()?;

            if !output.status.success() {
                return Err(format!(
                    "nft delete failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
        } else if let Some(table_spec) = generate_nft_rules(self.local, self.rst) {
            // Generate the nft script.
            let rules_str = self.nft_table_to_string(&table_spec);

            // First delete any existing rules
            let _ = Command::new("nft")
                .args(["delete", "table", NFT_FAMILY, NFT_TABLE])
                .output();

            // Then add the new rules
            let output = Command::new("nft")
                .args(["-f", "-"])
                .arg(&rules_str)
                .output()?;

            if !output.status.success() {
                return Err(format!(
                    "nft add failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
        }
        Ok(())
    }

    /// Generate the nftables script according to the nft spec.
    fn nft_table_to_string(&self, table: &NftTableSpec) -> String {
        let mut result = String::new();

        // Add defines
        for define in &table.defines {
            result.push_str(define);
            result.push('\n');
        }

        // Add table declaration
        result.push_str(&format!("\ntable {} {} {{\n", table.family, table.table));

        // Add chains
        for chain in &table.chains {
            result.push_str(&format!("  chain {} {{\n", chain.chain));
            result.push_str(&format!("    {}\n", chain.header));
            for rule in &chain.rules {
                result.push_str(&format!("    {}\n", rule));
            }
            result.push_str("  }\n");
        }

        result.push_str("}\n");
        result
    }

    fn packet_attribute_sanity_check(
        local: bool,
        payload: &[u8],
        ct: Option<&Conntrack>,
    ) -> (bool, nfq::Verdict) {
        // 20 is the minimum possible size of an IP packet
        if payload.len() < 20 {
            return (false, nfq::Verdict::Drop);
        }

        // Multicast packets may not have a conntrack, but only appear in local mode
        if ct.is_none() {
            if local {
                return (false, nfq::Verdict::Accept);
            }
            return (false, nfq::Verdict::Drop);
        }
        (true, nfq::Verdict::Accept)
    }
}

#[async_trait::async_trait]
impl PacketIO for NFQueuePacketIO {
    async fn register(&mut self, callback: PacketCallback) -> Result<(), Whatever> {
        // Check if the rules have been set.
        if !self.rule_set {
            let _ = self.setup_nft(false).await;
            self.rule_set = true;
        }

        let queue = self.queue.clone();
        let local = self.local;

        // Attatch a callback to a netfilter queue.
        // If the buffer is full, do not receive the ENOBUFS error (just ignore it),
        // which is the default behavier for nfq::Queue.
        tokio::spawn(async move {
            let mut q = queue.lock().await;
            while let Ok(mut msg) = q.recv() {
                // Get the attributes of the message.
                //let packet_id = msg.get_packet_id();
                let payload = msg.get_payload();
                let ct = msg.get_conntrack();

                // Check the sanity of the attributes.
                let (ok, verdict) =
                    NFQueuePacketIO::packet_attribute_sanity_check(local, payload, ct);

                if !ok {
                    msg.set_verdict(verdict);
                    continue;
                }

                let packet = NFQueuePacket {
                    //id: packet_id,
                    stream_id: ct.map(|c| c.get_id()).unwrap_or(0),
                    timestamp: msg.get_timestamp().unwrap_or_else(SystemTime::now),
                    data: payload.to_vec(),
                    msg,
                };

                if !callback(Box::new(packet), None) {
                    break;
                }
            }
        });

        Ok(())
    }

    async fn set_verdict(
        &self,
        packet: &mut Box<dyn Packet>,
        verdict: Verdict,
        data: Vec<u8>,
    ) -> Result<(), Whatever> {
        // Downcast the Packet trait to NFQueuePacket.
        let nfq_packet = packet
            .as_any_mut()
            .downcast_mut::<NFQueuePacket>()
            .expect("Invalid NFQueuePacket");

        match verdict {
            Verdict::Accept => nfq_packet.msg.set_verdict(nfq::Verdict::Accept),
            Verdict::AcceptModify => {
                nfq_packet.msg.set_verdict(nfq::Verdict::Accept);
                nfq_packet.msg.set_payload(data);
            }
            Verdict::AcceptStream => {
                nfq_packet.msg.set_verdict(nfq::Verdict::Accept);
                nfq_packet.msg.set_nfmark(NFQUEUE_CONN_MARK_ACCEPT);
            }
            Verdict::Drop => nfq_packet.msg.set_verdict(nfq::Verdict::Drop),
            Verdict::DropStream => {
                nfq_packet.msg.set_verdict(nfq::Verdict::Drop);
                nfq_packet.msg.set_nfmark(NFQUEUE_CONN_MARK_DROP);
            }
        }

        Ok(())
    }

    /// Establishes a protected TCP connection to the specified address.
    ///
    /// This function creates a new socket, sets a specific socket mark to ensure that the connection
    /// is protected by the NFQUEUE rules, and then connects to the given address. The socket is set
    /// to non-blocking mode and converted to a Tokio `TcpStream`.
    ///
    /// # Arguments
    ///
    /// * `addr` - A string slice that holds the address to connect to (assumed ipv4).
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// * `Ok(TcpStream)` - If the connection is successfully established.
    /// * `Err(Whatever)` - If there is an error during the process.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The address cannot be parsed.
    /// * The socket cannot be created.
    /// * The socket mark cannot be set.
    /// * The connection to the address fails.
    /// * The socket cannot be set to non-blocking mode.
    /// * The socket cannot be converted to a Tokio `TcpStream`.
    async fn protected_conn(&self, addr: &str) -> Result<TcpStream, Whatever> {
        // Parse the address string into a `SocketAddr`.
        let addr: SocketAddr = addr.parse().whatever_context("Failed to parse address")?;

        // Create a new socket with the specified domain and type.
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None)
            .whatever_context("Failed to create socket")?;

        // Set the socket mark to ensure the connection is protected by the NFQUEUE rules.
        // This is done using the `setsockopt` system call with the `SO_MARK` option.
        unsafe {
            let fd = socket.as_raw_fd();
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &(NFQUEUE_CONN_MARK_ACCEPT as libc::c_int) as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        // Connect the socket to the specified address.
        socket
            .connect(&addr.into())
            .whatever_context("Failed to connect")?;

        // Convert the socket to a standard `TcpStream`.
        let std_stream = std::net::TcpStream::from(socket);

        // Set the standard `TcpStream` to non-blocking mode.
        std_stream
            .set_nonblocking(true)
            .whatever_context("Failed to set non-blocking")?;

        TcpStream::from_std(std_stream).whatever_context("Failed to convert to tokio TcpStream")
    }

    async fn set_cancel_func(
        &self,
        _cancel_func: Box<dyn Fn() + Send + Sync>,
    ) -> Result<(), Whatever> {
        // NFQueue doesn't need cancel functionality
        Ok(())
    }
}

struct NFQueuePacket {
    //id: u32,
    stream_id: u32,
    timestamp: SystemTime,
    data: Vec<u8>,
    msg: Message,
}

impl Packet for NFQueuePacket {
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

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
//#[cfg(test)]
//mod tests {
//    use super::*;
//    use tracing_subscriber;
//    #[test]
//    fn test_generate_nft_rules_local() {
//        tracing_subscriber::fmt::init();
//        let rules = generate_nft_rules(true, false).unwrap();
//        assert_eq!(rules.family, "inet");
//        assert_eq!(rules.table, "opengfw");
//        assert_eq!(rules.chains.len(), 2);
//        assert_eq!(rules.chains[0].chain, "INPUT");
//        assert_eq!(rules.chains[1].chain, "OUTPUT");
//    }
//
//    #[test]
//    fn test_generate_nft_rules_non_local() {
//        let rules = generate_nft_rules(false, false).unwrap();
//        assert_eq!(rules.family, "inet");
//        assert_eq!(rules.table, "opengfw");
//        assert_eq!(rules.chains.len(), 1);
//        assert_eq!(rules.chains[0].chain, "FORWARD");
//    }
//
//    #[tokio::test]
//    async fn test_nfqueue_packet_io_new() {
//        let config = NFQueuePacketIOConfig::default();
//        let nfqueue_packet_io = NFQueuePacketIO::new(config);
//        assert!(nfqueue_packet_io.is_some());
//    }
//
//    #[tokio::test]
//    async fn test_nfqueue_packet_io_setup_nft() {
//        let config = NFQueuePacketIOConfig::default();
//        let nfqueue_packet_io = NFQueuePacketIO::new(config).unwrap();
//        let result = nfqueue_packet_io.setup_nft(false).await;
//        assert!(result.is_ok());
//    }
//
//    #[tokio::test]
//    async fn test_nfqueue_packet_io_protected_conn() {
//        let config = NFQueuePacketIOConfig::default();
//        let nfqueue_packet_io = NFQueuePacketIO::new(config).unwrap();
//        let result = nfqueue_packet_io.protected_conn("127.0.0.1:8080").await;
//        assert!(result.is_ok());
//    }
//
//    #[tokio::test]
//    async fn test_nfqueue_packet_io_register() {
//        let config = NFQueuePacketIOConfig::default();
//        let mut nfqueue_packet_io = NFQueuePacketIO::new(config).unwrap();
//        let callback = Box::new(
//            |_packet: Box<dyn Packet>, _data: Option<Whatever>| -> bool {
//                info!("Packet received");
//                true
//            },
//        );
//        let result = nfqueue_packet_io.register(callback).await;
//        assert!(result.is_ok());
//    }
//}
