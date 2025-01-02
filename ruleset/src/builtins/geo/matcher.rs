use crate::builtins::geo::v2geo::v2geo::{domain, GeoIP, GeoSite};
use crate::builtins::geo::v2geo::v2geo_loader;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use regex::Regex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task;
use tracing::error;

pub struct HostInfo {
    pub name: String,
    pub ip: Option<IpAddr>,
}

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
    geoloader: Arc<Mutex<v2geo_loader::V2GeoLoader>>,
    geoip: Arc<Mutex<HashMap<String, IpMatcher>>>,
    geosite: Arc<Mutex<HashMap<String, SiteMatcher>>>,
}

impl GeoMatcher {
    pub fn new(geosite_file: &str, geoip_file: &str) -> Self {
        Self {
            geoloader: Arc::new(Mutex::new(v2geo_loader::V2GeoLoader::new(
                geoip_file,
                geosite_file,
            ))),
            geoip: Arc::new(Mutex::new(HashMap::new())),
            geosite: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn geoip(&self, ip: String, condition: String) -> bool {
        let geoip = self.geoip.clone();
        let loader = self.geoloader.clone();
        task::block_in_place(move || {
            let mut geoip = geoip.blocking_lock();
            if !geoip.contains_key(&condition) {
                let coutry = condition.to_lowercase();
                if coutry.is_empty() {
                    return false;
                }
                let mut loader = loader.blocking_lock();
                if let Ok(gmap) = loader.load_geoip() {
                    if let Some(list) = gmap.get(&coutry) {
                        let matcher = IpMatcher::new(list);
                        geoip.insert(condition.clone(), matcher);
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            if let Ok(ip_addr) = ip.parse::<IpAddr>() {
                let mather = geoip.get(&condition).unwrap();
                return mather.match_ip(HostInfo {
                    name: "".to_string(),
                    ip: Some(ip_addr),
                });
            }
            false
        })
    }

    pub fn geosite(&self, host: String, condition: String) -> bool {
        let geosite = self.geosite.clone();
        let loader = self.geoloader.clone();
        task::block_in_place(move || {
            let mut geosite = geosite.blocking_lock();
            if !geosite.contains_key(&condition) {
                let condition = condition.to_lowercase();
                let (name, attrs) = parse_geo_site_name(&condition);
                if name.is_empty() {
                    return false;
                }
                let mut loader = loader.blocking_lock();
                if let Ok(smap) = loader.load_geosite() {
                    if let Some(list) = smap.get(&name) {
                        let matcher = SiteMatcher::new(list, attrs);
                        geosite.insert(condition.clone(), matcher);
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            let matcher = geosite.get(&condition).unwrap();
            matcher.match_domain(HostInfo {
                name: host,
                ip: None,
            })
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
