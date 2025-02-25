//! This module contains the definition of an expression rule and the logic to read and compile them.
use crate::Action;
use gfw_analyzer::extract_json_from_combinedpropmap;
use gfw_analyzer::Analyzer;
use gfw_modifier::{Instance, Modifier};
use rhai::Dynamic;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info};

/// Represents an expression rule.
#[derive(Deserialize, Debug, Serialize)]
pub struct ExprRule {
    /// The name of the rule.
    pub name: String,
    /// The action to take if the rule matches.
    pub action: Action,
    /// The modifier to apply if the rule matches.
    pub modifier: Option<ModifierEntry>,
    /// The name of the analyzer to use.
    pub analyzer: String,
    /// The expression to evaluate. see <https://crates.io/crates/rhai>
    pub expr: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ModifierEntry {
    pub name: String,
    pub args: HashMap<String, String>,
}

pub async fn read_expr_rules_from_file(
    path: &str,
) -> Result<Vec<ExprRule>, Box<dyn std::error::Error + Send + Sync>> {
    let mut file = File::open(path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;
    let expr_rules: Vec<ExprRule> = serde_yaml::from_str(&contents)?;
    Ok(expr_rules)
}

/// The internal, compiled representation of an expression rule.
#[derive(Debug, Clone)]
pub struct CompiledExprRule {
    pub name: String,
    pub action: Action,
    pub modifier: Option<Arc<dyn Instance>>,
    pub ast: rhai::AST,
}

#[derive(Debug, Clone)]
pub struct ExprRuleset {
    pub engine: Arc<rhai::Engine>,
    pub rules: Vec<CompiledExprRule>,
    pub analyzers: Vec<Arc<dyn Analyzer>>,
}

impl crate::Ruleset for ExprRuleset {
    fn analyzers(&self) -> Vec<Arc<dyn Analyzer>> {
        self.analyzers.clone()
    }

    fn matches(&self, info: &crate::StreamInfo) -> crate::MatchResult {
        let mut scope = rhai::Scope::new();
        get_scope(&mut scope, info);
        for rule in self.rules.iter() {
            let result = self.engine.eval_ast_with_scope(&mut scope, &rule.ast);
            match result {
                Ok(re) => {
                    if re {
                        return {
                            info!("Rule matched: name = {:?}, id = {:?}, src = {:?}:{:?}, dst = {:?}:{:?}, props = {:?}",
                            &rule.name, &info.id, &info.src_ip, &info.src_port, &info.dst_ip, &info.dst_port, &scope);
                            crate::MatchResult {
                                action: rule.action.clone(),
                                modifier: rule.modifier.clone(),
                            }
                        };
                    }
                }
                Err(_e) => {
                    // error!("Rule match error: {}; Rule: {:?}", e, rule.ast);
                }
            }
        }

        debug!("Non of the rules were matched, returning default action 'Maybe'");

        crate::MatchResult {
            action: crate::Action::Maybe,
            modifier: None,
        }
    }
}

fn get_scope(scope: &mut rhai::Scope, info: &crate::StreamInfo) {
    // Convert PropMap to JSON
    let json_value = extract_json_from_combinedpropmap(&info.props);
    let result: Dynamic = serde_json::from_value(json_value).unwrap();

    // // Add JSON string to scope
    scope.push("props", result);
}

/// Compiles a set of expression rules.
/// # Arguments
/// * `rules` - A vector of `ExprRule` structs.
/// * `analyzers` - A vector of `Arc<dyn Analyzer>` structs.
/// * `modifiers` - A vector of `Arc<dyn Modifier>` structs.
/// * `engine` - A `gfw_ruleset::engine::Engine` instance.
///
/// # Returns
/// * An `ExprRuleset` struct containing the compiled rules.
pub fn compile_expr_rules(
    rules: Vec<ExprRule>,
    analyzers: &[Arc<dyn Analyzer>],
    modifiers: &[Arc<dyn Modifier>],
    engine: crate::engine::Engine,
) -> ExprRuleset {
    let analyzers: HashMap<String, Arc<dyn Analyzer>> = analyzers
        .iter()
        .map(|a| (a.name().to_owned(), a.clone()))
        .collect();

    let modifiers: HashMap<String, Arc<dyn Modifier>> = modifiers
        .iter()
        .map(|m| (m.name().to_owned(), m.clone()))
        .collect();

    let mut compiled_rules = Vec::new();
    let mut anal = HashMap::new();
    for rule in rules {
        if let Ok(ast) = engine.engine.compile(rule.expr) {
            let modifier = match rule.modifier {
                Some(modifier) => {
                    let a = modifiers.get(&modifier.name);
                    match a {
                        Some(m) => {
                            let args = modifier.args;
                            m.new_instance(args)
                        }
                        None => None,
                    }
                }
                None => None,
            };
            compiled_rules.push(CompiledExprRule {
                name: rule.name,
                action: rule.action,
                modifier,
                ast,
            });
            if analyzers.contains_key(&rule.analyzer) {
                anal.insert(rule.analyzer.clone(), analyzers[&rule.analyzer].clone());
            }
        } else {
            error!("Failed to compile rule: {}", rule.name);
        }
    }
    ExprRuleset {
        engine: engine.engine.clone(),
        rules: compiled_rules,
        analyzers: anal.into_values().collect(),
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[tokio::test]
//     async fn test_read_expr_rules_from_file() {
//         let rules = read_expr_rules_from_file("../rules.yaml").await.unwrap();
//         assert_eq!(rules.len(), 4);
//     }
// }
