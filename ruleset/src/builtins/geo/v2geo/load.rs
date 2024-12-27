use crate::builtins::geo::v2geo::v2geo::{GeoIP, GeoIPList, GeoSite, GeoSiteList};
use protobuf::Message;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;

pub fn load_geoip(
    filename: &str,
) -> Result<HashMap<String, Arc<GeoIP>>, Box<dyn std::error::Error>> {
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut list = GeoIPList::new();
    list.merge_from_bytes(&buffer)?;

    let mut map = HashMap::new();
    for entry in list.entry {
        map.insert(entry.country_code.to_lowercase(), Arc::new(entry));
    }
    Ok(map)
}

pub fn load_geo_site(
    filename: &str,
) -> Result<HashMap<String, Arc<GeoSite>>, Box<dyn std::error::Error>> {
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut list = GeoSiteList::new();
    list.merge_from_bytes(&buffer)?;

    let mut map = HashMap::new();
    for entry in list.entry {
        map.insert(entry.country_code.to_lowercase(), Arc::new(entry));
    }
    Ok(map)
}
