use crate::builtins::geo::v2geo::v2geo::{domain, GeoIP, GeoSite};
use crate::builtins::geo::v2geo::v2geo_loader;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tracing::{debug, error};

pub struct HostInfo {
    pub name: String,
    pub ip: Option<IpAddr>,
}

#[derive(Debug)]
pub struct IpMatcher {
    v4: Vec<IpNetwork>,
    v6: Vec<IpNetwork>,
    inverse: bool,
}

impl IpMatcher {
    pub fn new(list: &GeoIP) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for i in list.cidr.iter() {
            if i.ip.len() == 4 {
                let ip = <[u8; 4]>::try_from(i.ip.clone());
                if ip.is_err() {
                    error!("Invalid IP: {:?}", i);
                    continue;
                }
                let addr = Ipv4Network::new(Ipv4Addr::from(ip.unwrap()), i.prefix as u8);
                if addr.is_err() {
                    error!("Invalid CIDR: {:?}", i);
                    continue;
                }
                v4.push(addr.unwrap().into());
            } else if i.ip.len() == 16 {
                let ip = <[u8; 16]>::try_from(i.ip.clone());
                if ip.is_err() {
                    error!("Invalid IP: {:?}", i);
                    continue;
                }
                let addr = Ipv6Network::new(Ipv6Addr::from(ip.unwrap()), i.prefix as u8);
                if addr.is_err() {
                    error!("Invalid CIDR: {:?}", i);
                    continue;
                }
                v6.push(addr.unwrap().into());
            } else {
                error!("Invalid IP length: {}", i.ip.len());
                continue;
            }
        }
        v4.sort_by_key(|a: &IpNetwork| a.network());
        v6.sort_by_key(|a: &IpNetwork| a.network());
        IpMatcher {
            v4,
            v6,
            inverse: list.inverse_match,
        }
    }

    fn half_search(list: &[IpNetwork], ip: IpAddr) -> bool {
        let mut low = 0;
        let mut high = list.len() - 1;
        while low <= high {
            let mid = (low + high) / 2;
            if list[mid].contains(ip) {
                return true;
            } else if list[mid].network().cmp(&ip) == std::cmp::Ordering::Less {
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }
        false
    }

    pub fn match_ip(&self, host: HostInfo) -> bool {
        if host.ip.is_some() {
            let ip = host.ip.unwrap();
            if ip.is_ipv4() {
                if Self::half_search(&self.v4, ip) {
                    return !self.inverse;
                }
            } else if ip.is_ipv6() && Self::half_search(&self.v6, ip) {
                return !self.inverse;
            }
        }
        self.inverse
    }
}

pub enum GeositeDomainType {
    Plain,
    Regex,
    Root,
    Full,
}

pub struct GeositeDomain {
    domain_type: GeositeDomainType,
    value: String,
    regex: Option<Regex>,
    attrs: HashMap<String, bool>,
}

pub struct SiteMatcher {
    domains: Vec<GeositeDomain>,
    // Attributes are matched using "and" logic - if you have multiple attributes here,
    // a domain must have all of those attributes to be considered a match.
    attrs: Vec<String>,
}

impl SiteMatcher {
    pub fn new(list: &GeoSite, attrs: Vec<String>) -> Self {
        let mut domains = Vec::new();
        for d in list.domain.iter() {
            if let Ok(dtype) = d.type_.enum_value() {
                match dtype {
                    domain::Type::Plain => {
                        domains.push(GeositeDomain {
                            domain_type: GeositeDomainType::Plain,
                            value: d.value.clone(),
                            regex: None,
                            attrs: attribute_to_map(&d.attribute),
                        });
                    }
                    domain::Type::Regex => {
                        let regex = Regex::new(&d.value);
                        if regex.is_err() {
                            error!("Invalid regex: {:?}", d.value);
                            continue;
                        }
                        domains.push(GeositeDomain {
                            domain_type: GeositeDomainType::Regex,
                            value: d.value.clone(),
                            regex: Some(regex.unwrap()),
                            attrs: attribute_to_map(&d.attribute),
                        });
                    }
                    domain::Type::RootDomain => {
                        domains.push(GeositeDomain {
                            domain_type: GeositeDomainType::Root,
                            value: d.value.clone(),
                            regex: None,
                            attrs: attribute_to_map(&d.attribute),
                        });
                    }
                    domain::Type::Full => {
                        domains.push(GeositeDomain {
                            domain_type: GeositeDomainType::Full,
                            value: d.value.clone(),
                            regex: None,
                            attrs: attribute_to_map(&d.attribute),
                        });
                    }
                }
            } else {
                error!("Invalid domain type: {:?}", d.type_);
                continue;
            }
        }
        SiteMatcher { domains, attrs }
    }

    fn match_d(&self, domain: &GeositeDomain, host: &HostInfo) -> bool {
        if !self.attrs.is_empty() {
            if domain.attrs.is_empty() {
                return false;
            }
            for attr in self.attrs.iter() {
                if !domain.attrs.contains_key(attr) && !domain.attrs[attr] {
                    return false;
                }
            }
        }
        match domain.domain_type {
            GeositeDomainType::Plain => return host.name.contains(&domain.value),
            GeositeDomainType::Regex => {
                if domain.regex.is_some() {
                    return domain.regex.as_ref().unwrap().is_match(&host.name);
                }
            }
            GeositeDomainType::Full => {
                return host.name == domain.value;
            }
            GeositeDomainType::Root => {
                return host.name.ends_with(&domain.value);
            }
        }
        false
    }

    pub fn match_domain(&self, host: HostInfo) -> bool {
        for d in self.domains.iter() {
            if self.match_d(d, &host) {
                return true;
            }
        }
        false
    }
}

fn attribute_to_map(attrs: &Vec<domain::Attribute>) -> HashMap<String, bool> {
    let mut map = HashMap::new();
    for a in attrs {
        map.insert(a.key.clone(), true);
    }
    map
}

#[derive(Clone)]
pub struct GeoMatcher {
    geoip: Arc<HashMap<String, IpMatcher>>,
    geosite: Arc<HashMap<String, SiteMatcher>>,
}

impl GeoMatcher {
    pub async fn new(
        geosite_file: &str,
        geoip_file: &str,
        geoip_conditions: HashSet<String>,
        geosite_conditions: HashSet<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let geoloader = v2geo_loader::V2GeoLoader::new(geoip_file, geosite_file);
        let geoip = geoloader.load_geoip().await?;
        let geosite = geoloader.load_geosite().await?;

        let geoip = geoip_conditions
            .into_iter()
            .filter_map(|condition| {
                let country = condition.to_lowercase();
                if country.is_empty() {
                    return None;
                }
                if let Some(list) = geoip.get(&country) {
                    let matcher = IpMatcher::new(list);
                    return Some((condition, matcher));
                }
                None
            })
            .collect();

        let geosite = geosite_conditions
            .into_iter()
            .filter_map(|condition| {
                let condition_l = condition.to_lowercase();
                let (name, attrs) = parse_geo_site_name(&condition_l);
                if name.is_empty() {
                    return None;
                }
                if let Some(list) = geosite.get(&name) {
                    let matcher = SiteMatcher::new(list, attrs);
                    return Some((condition, matcher));
                }
                None
            })
            .collect();

        Ok(Self {
            geoip: Arc::new(geoip),
            geosite: Arc::new(geosite),
        })
    }

    pub fn geoip(&self, ip: String, condition: String) -> bool {
        debug!("geoip: {} {}", ip, condition);
        if !self.geoip.contains_key(&condition) {
            return false;
        }
        if let Ok(ip_addr) = ip.parse::<IpAddr>() {
            let mather = self.geoip.get(&condition).unwrap();
            return mather.match_ip(HostInfo {
                name: "".to_string(),
                ip: Some(ip_addr),
            });
        }
        false
    }

    pub fn geosite(&self, host: String, condition: String) -> bool {
        debug!("geosite: {} {}", host, condition);
        if !self.geosite.contains_key(&condition) {
            return false;
        }
        let matcher = self.geosite.get(&condition).unwrap();
        matcher.match_domain(HostInfo {
            name: host,
            ip: None,
        })
    }
}

fn parse_geo_site_name(s: &str) -> (String, Vec<String>) {
    let parts: Vec<&str> = s.split('@').collect();
    let base = parts[0].trim().to_string();
    let attrs: Vec<String> = parts[1..]
        .iter()
        .map(|&attr| attr.trim().to_string())
        .collect();
    (base, attrs)
}
