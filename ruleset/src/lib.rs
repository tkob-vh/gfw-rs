use gfw_analyzer::Analyzer;
use gfw_modifier::Instance;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug};
use std::net::IpAddr;
use std::sync::Arc;

pub mod expr_rule;
pub mod v2geo;

#[derive(Debug)]
pub enum Protocol {
    TCP,
    UDP,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let protocol_str = match self {
            Protocol::TCP => "TCP",
            Protocol::UDP => "UDP",
        };
        write!(f, "{}", protocol_str)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Maybe,
    Allow,
    Block,
    Drop,
    Modify,
}

#[derive(Debug)]
pub struct StreamInfo {
    pub id: i64,
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub props: gfw_analyzer::CombinedPropMap,
}

pub struct MatchResult {
    pub action: Action,
    pub modifier: Option<Arc<dyn Instance>>,
}

/// The ruleset trait.
pub trait Ruleset: Send + Sync + Debug {
    /// - returns the list of analyzers to use for a stream.
    ///
    /// It must be safe for concurrent use by multiple workers.
    fn analyzers(&self) -> Vec<Arc<dyn Analyzer>>;

    /// - matches a stream against the ruleset and returns the result.
    ///
    /// It must be safe for concurrent use by multiple workers.
    fn matches(&self, info: &StreamInfo) -> MatchResult;
}
