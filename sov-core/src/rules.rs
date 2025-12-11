use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleScope {
    Node,
    Net,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleMethod {
    Signature,
    Heuristic,
    Anomaly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSignature {
    pub pattern: String,
    pub is_regex: bool,
    pub target: String, // "node.raw_line" | "net.payload"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,

    pub scope: RuleScope,
    pub method: RuleMethod,
    pub severity: u8,

    pub signature: Option<RuleSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    pub version: String,
    pub rules: Vec<Rule>,
}

pub fn load_rules(path: &str) -> anyhow::Result<RuleSet> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&text)?)
}

