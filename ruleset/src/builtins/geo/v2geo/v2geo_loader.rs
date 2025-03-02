use super::v2geo::{GeoIP, GeoSite};
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::debug;

const GEOIP_FILENAME: &str = "geoip.dat";
const GEOIP_URL: &str =
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat";
const GEOSITE_FILENAME: &str = "geosite.dat";
const GEOSITE_URL: &str =
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat";

const GEO_DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(7 * 24 * 60 * 60); // 7 days

pub struct V2GeoLoader {
    geoip_filename: String,
    geosite_filename: String,
    update_interval: Duration,
}

impl V2GeoLoader {
    pub fn new(geoip_filename: &str, geosite_filename: &str) -> Self {
        V2GeoLoader {
            geoip_filename: geoip_filename.to_string(),
            geosite_filename: geosite_filename.to_string(),
            update_interval: GEO_DEFAULT_UPDATE_INTERVAL,
        }
    }

    async fn should_download(&self, filename: &str) -> bool {
        if let Ok(metadata) = fs::metadata(filename).await {
            if let Ok(modified) = metadata.modified() {
                if let Ok(elapsed) = modified.elapsed() {
                    return elapsed > self.update_interval;
                }
            }
        }
        true
    }

    async fn download(&self, filename: &str, url: &str) -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new();
        let response = client.get(url).send().await?;
        let mut file = fs::File::create(filename).await?;
        let content = response.bytes().await?;
        file.write_all(&content).await?;
        Ok(())
    }

    pub async fn load_geoip(&self) -> Result<HashMap<String, GeoIP>, Box<dyn std::error::Error>> {
        let filename = if self.geoip_filename.is_empty() {
            GEOIP_FILENAME.to_string()
        } else {
            self.geoip_filename.clone()
        };

        if self.should_download(&filename).await {
            self.download(&filename, GEOIP_URL).await?;
        }
        let geoip_map = super::load::load_geoip(&filename).await?;
        debug!("loaded geoip");
        Ok(geoip_map)
    }

    pub async fn load_geosite(
        &self,
    ) -> Result<HashMap<String, GeoSite>, Box<dyn std::error::Error>> {
        let filename = if self.geosite_filename.is_empty() {
            GEOSITE_FILENAME.to_string()
        } else {
            self.geosite_filename.clone()
        };

        if self.should_download(&filename).await {
            self.download(&filename, GEOSITE_URL).await?;
        }

        let geosite_map = super::load::load_geo_site(&filename).await?;
        debug!("loaded geosite");
        Ok(geosite_map)
    }
}
