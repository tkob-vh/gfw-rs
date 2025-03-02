use crate::error::{IoSnafu, SerdeSnafu, ServiceError};
use crate::SharedServerConfig;
use axum::{routing::post, Extension, Json, Router};
use gfw_config::config::CliConfig;
use gfw_ruleset::expr_rule::ExprRule;
use snafu::ResultExt;
use std::sync::Arc;
use tokio::{fs::File, io::AsyncWriteExt};
use tracing::debug;

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
    debug!("Saved config: {:?}", server_config.config);
}

async fn save_rules(
    Extension(server): Extension<SharedServerConfig>,
    Json(rules): Json<Vec<ExprRule>>,
) -> Result<(), ServiceError> {
    let mut server_config = server.write().await;
    debug!("Saved rules: {:?}", rules);
    // write to file
    let mut file = File::create(&server_config.ruleset_file)
        .await
        .context(IoSnafu)?;
    let rulestr = serde_yaml::to_string(&rules).context(SerdeSnafu)?;
    file.write_all(rulestr.as_bytes()).await.context(IoSnafu)?;

    if server_config.engine_starter.is_none() {
        let ruleset = gfw_ruleset::expr_rule::compile_expr_rules(
            rules,
            &server_config.analyzers,
            &server_config.modifiers,
            server_config.ruleset_engine.clone(),
        )
        .await;
        server_config.rule_set = Some(Arc::new(ruleset));
    }
    Ok(())
}
