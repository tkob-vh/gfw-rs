use crate::builtins::geo::matcher;
use rhai::{Module, Shared};
use std::sync::Arc;

#[derive(Clone)]
// clone this struct same as clone Arc
pub struct Engine {
    pub shared_global_module: Shared<Module>,
    pub engine: Arc<rhai::Engine>,
}

impl Engine {
    pub fn new(geoip_file: &str, geosite_file: &str) -> Self {
        let matcher = matcher::GeoMatcher::new(geosite_file, geoip_file);
        let mut engine = rhai::Engine::new();
        let mut global_module = Module::new();
        global_module.set_var("matcher", matcher);
        let global_moudle: Shared<Module> = global_module.into();
        engine.register_global_module(global_moudle.clone());
        let clone_moudle = global_moudle.clone();

        engine.register_fn("geoip", move |ip: String, condition: String| -> bool {
            let matcher: matcher::GeoMatcher = clone_moudle.get_var("matcher").unwrap().cast();
            matcher.geoip(ip, condition)
        });

        let clone_moudle = global_moudle.clone();
        engine.register_fn("geosite", move |host: String, condition: String| -> bool {
            let matcher: matcher::GeoMatcher = clone_moudle.get_var("matcher").unwrap().cast();
            matcher.geosite(host, condition)
        });

        Self {
            shared_global_module: global_moudle,
            engine: Arc::new(engine),
        }
    }
}
