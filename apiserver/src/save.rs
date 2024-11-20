use crate::SharedServerConfig;
use axum::{routing::post, Extension, Json, Router};
use nt_cmd::config::CliConfig;
use nt_ruleset::expr_rule::ExprRule;
use std::sync::Arc;

pub async fn create_router() -> Router {
    Router::new()
        .route("/save/rules", post(save_rules))
        .route("/save/config", post(save_config))
}

async fn save_config(
    Extension(server): Extension<SharedServerConfig>,
    Json(config): Json<CliConfig>,
) {
    let mut server_config = server.write().await;
    server_config.config = Arc::new(config);
    println!("Saved config: {:?}", server_config.config);
}

async fn save_rules(
    Extension(server): Extension<SharedServerConfig>,
    Json(rules): Json<Vec<ExprRule>>,
) {
    let mut server_config = server.write().await;
    println!("Saved rules: {:?}", rules);
    if let Some(old_ruleset) = &server_config.rule_set {
        let new_ruleset = nt_ruleset::expr_rule::compile_expr_rules(
            rules,
            &server_config.analyzers,
            &server_config.modifiers,
            old_ruleset.engine.clone(),
        );
        server_config.rule_set = Some(Arc::new(new_ruleset));
    } else {
        let rhai_engine = Arc::new(rhai::Engine::new());
        let ruleset = nt_ruleset::expr_rule::compile_expr_rules(
            rules,
            &server_config.analyzers,
            &server_config.modifiers,
            rhai_engine,
        );
        server_config.rule_set = Some(Arc::new(ruleset));
    }
}
