//! Coverage as an [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator)
//! layer, the format security teams review coverage in.

use serde_json::{Value, json};

use crate::coverage::{Coverage, Verdict};
use crate::framework::Framework;

/// The layer format written, which Navigator 5 reads.
const LAYER_FORMAT: &str = "4.5";

/// How each verdict is coloured, and what the legend calls it.
const SHOWN: [(Verdict, &str, &str); 3] = [
    (
        Verdict::Detected,
        "#3fb950",
        "Detected: a rule, and its data collected",
    ),
    (
        Verdict::Blind,
        "#e0533d",
        "Blind: a rule, but none of its data collected",
    ),
    (
        Verdict::Collected,
        "#d9a13b",
        "Collected: data, but no rule",
    ),
];

/// A layer named `name` that colours each technique by its verdict, lists
/// its rules and collected data components in the comment, and leaves
/// uncovered techniques uncoloured.
pub fn layer(framework: &Framework, coverage: &Coverage, name: &str) -> Value {
    let major = framework.version().split('.').next().unwrap_or_default();
    let techniques: Vec<Value> = coverage
        .techniques
        .values()
        .filter_map(|technique| {
            let (_, color, _) = SHOWN
                .iter()
                .find(|(verdict, _, _)| *verdict == technique.verdict)?;
            let mut comment = Vec::new();
            if !technique.rules.is_empty() {
                comment.push(format!("Rules: {}", technique.rules.join("; ")));
            }
            let names = |ids: &std::collections::BTreeSet<String>| {
                ids.iter()
                    .filter_map(|id| framework.data_component(id))
                    .map(|component| component.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            if technique.collected.is_empty() {
                if !technique.needs.is_empty() {
                    comment.push(format!("Needs one of: {}", names(&technique.needs)));
                }
            } else {
                comment.push(format!("Collected: {}", names(&technique.collected)));
            }
            Some(json!({
                "techniqueID": technique.technique,
                "color": color,
                "comment": comment.join(". "),
                "enabled": true,
                "showSubtechniques": framework
                    .techniques()
                    .any(|child| child.parent.as_deref() == Some(technique.technique.as_str())
                        && coverage.techniques.get(&child.id).is_some_and(|child| child.verdict != Verdict::Uncovered)),
            }))
        })
        .collect();
    json!({
        "name": name,
        "versions": { "attack": major, "layer": LAYER_FORMAT },
        "domain": framework.domain(),
        "description": format!(
            "Coverage against {} {}: which techniques a rule detects, and whether the data it needs is collected.",
            framework.name(),
            framework.version()
        ),
        "techniques": techniques,
        "legendItems": SHOWN
            .iter()
            .map(|(_, color, label)| json!({ "label": label, "color": color }))
            .collect::<Vec<_>>(),
    })
}
