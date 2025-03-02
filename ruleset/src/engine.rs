use crate::builtins::cidr::is_ip_in_cidr;
use crate::builtins::geo::matcher;
use rhai::{Module, Shared};
use std::collections::HashSet;

#[derive(Clone)]
// clone this struct same as clone Arc
pub struct Engine {
    pub geoip_filename: String,
    pub geosite_filename: String,
}

impl Engine {
    pub fn new(geoip_file: &str, geosite_file: &str) -> Self {
        Self {
            geoip_filename: geoip_file.to_string(),
            geosite_filename: geosite_file.to_string(),
        }
    }

    pub async fn register(
        &self,
        geoip_conditions: HashSet<String>,
        geosite_conditions: HashSet<String>,
    ) -> Result<rhai::Engine, Box<dyn std::error::Error>> {
        let matcher = matcher::GeoMatcher::new(
            &self.geosite_filename,
            &self.geoip_filename,
            geoip_conditions,
            geosite_conditions,
        )
        .await?;

        let mut engine = rhai::Engine::new();
        let mut global_module = Module::new();
        global_module.set_var("matcher", matcher);
        let global_module: Shared<Module> = global_module.into();
        engine.register_global_module(global_module.clone());
        let clone_moudle = global_module.clone();

        engine.register_fn("geoip", move |ip: String, condition: String| -> bool {
            let matcher: matcher::GeoMatcher = clone_moudle.get_var("matcher").unwrap().cast();
            matcher.geoip(ip, condition)
        });

        let clone_moudle = global_module.clone();
        engine.register_fn("geosite", move |host: String, condition: String| -> bool {
            let matcher: matcher::GeoMatcher = clone_moudle.get_var("matcher").unwrap().cast();
            matcher.geosite(host, condition)
        });

        engine.register_fn("cidr", is_ip_in_cidr);

        Ok(engine)
    }
}
