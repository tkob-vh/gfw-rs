use serde::Deserialize;
use std::collections::HashMap;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

#[derive(Deserialize, Debug)]
pub struct ExprRule {
    pub name: String,
    pub action: Action,
    #[serde(default)]
    pub log: bool,
    pub modifier: Option<ModifierEntry>,
    pub expr: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Block,
    Drop,
    Modify,
}

#[derive(Deserialize, Debug)]
struct ModifierEntry {
    pub name: String,
    pub args: HashMap<String, String>,
}

pub async fn read_expr_rules_from_file(
    path: &str,
) -> Result<Vec<ExprRule>, Box<dyn std::error::Error>> {
    let mut file = File::open(path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;
    let expr_rules: Vec<ExprRule> = serde_yaml::from_str(&contents)?;
    Ok(expr_rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_read_expr_rules_from_file() {
        let rules = read_expr_rules_from_file("../rules.yaml").await.unwrap();
        assert_eq!(rules.len(), 4);
    }
}
