use crate::v2geo::geo::{GeoIP, GeoIPList, GeoSite, GeoSiteList};
use protobuf::Message;
use std::collections::HashMap;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

async fn load_geoip(
    filename: String,
) -> Result<HashMap<String, GeoIP>, Box<dyn std::error::Error>> {
    let mut file = File::open(filename).await?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await?;

    let mut list = GeoIPList::new();
    list.merge_from_bytes(&buffer)?;

    let mut map = HashMap::new();
    for entry in list.entry {
        map.insert(entry.country_code.to_lowercase(), entry);
    }
    Ok(map)
}

async fn load_geo_site(
    filename: String,
) -> Result<HashMap<String, GeoSite>, Box<dyn std::error::Error>> {
    let mut file = File::open(filename).await?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await?;

    let mut list = GeoSiteList::new();
    list.merge_from_bytes(&buffer)?;

    let mut map = HashMap::new();
    for entry in list.entry {
        map.insert(entry.country_code.to_lowercase(), entry);
    }
    Ok(map)
}
