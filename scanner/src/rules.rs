//! Loading and validating the rule database (`rules/*.toml`).

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

use crate::walker::Language;

/// The rule files shipped inside the binary. `include_str!` copies each file's
/// text in at compile time, so `threadai` works with no files next to it.
pub const BUILTIN_RULES: [(&str, &str); 4] = [
    ("core.toml", include_str!("../../rules/core.toml")),
    ("js.toml", include_str!("../../rules/js.toml")),
    ("python.toml", include_str!("../../rules/python.toml")),
    ("rust.toml", include_str!("../../rules/rust.toml")),
];

/// Language names a rule may list. "any" means every scanned file.
pub const KNOWN_LANGUAGES: [&str; 4] = ["any", "javascript", "python", "rust"];

/// Ordered low → high so `severity >= min` comparisons work.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// One `[[rule]]` table exactly as written in TOML.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    title: String,
    severity: Severity,
    cwe: String,
    owasp: String,
    languages: Vec<String>,
    pattern: String,
    #[serde(default)]
    exclude: Option<String>,
    #[serde(default)]
    redact: bool,
    #[serde(default)]
    skip_in_tests: bool,
    attack: String,
    fix: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    rule: Vec<RawRule>,
}

/// A rule ready to run: regexes compiled once, up front.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub cwe: String,
    pub owasp: String,
    pub languages: Vec<String>,
    pub pattern: Regex,
    pub exclude: Option<Regex>,
    pub redact: bool,
    /// Don't report in test files (e.g. `.unwrap()` is fine in tests).
    pub skip_in_tests: bool,
    pub attack: String,
    pub fix: String,
    /// Which file the rule came from, for error messages.
    pub source: String,
}

impl Rule {
    pub fn applies_to(&self, lang: Language) -> bool {
        self.languages
            .iter()
            .any(|l| l == "any" || l == lang.name())
    }
}

/// Parse one TOML document into compiled rules.
pub fn parse_rules(source: &str, text: &str) -> Result<Vec<Rule>> {
    let file: RuleFile =
        toml::from_str(text).with_context(|| format!("invalid rule file {source}"))?;

    let mut rules = Vec::with_capacity(file.rule.len());
    for raw in file.rule {
        for lang in &raw.languages {
            if !KNOWN_LANGUAGES.contains(&lang.as_str()) {
                bail!("{source}: rule {} has unknown language {lang:?}", raw.id);
            }
        }
        if raw.languages.is_empty() {
            bail!("{source}: rule {} lists no languages", raw.id);
        }
        let pattern = Regex::new(&raw.pattern)
            .with_context(|| format!("{source}: rule {} has a bad pattern", raw.id))?;
        let exclude = match &raw.exclude {
            Some(p) => Some(
                Regex::new(p)
                    .with_context(|| format!("{source}: rule {} has a bad exclude", raw.id))?,
            ),
            None => None,
        };
        rules.push(Rule {
            id: raw.id,
            title: raw.title,
            severity: raw.severity,
            cwe: raw.cwe,
            owasp: raw.owasp,
            languages: raw.languages,
            pattern,
            exclude,
            redact: raw.redact,
            skip_in_tests: raw.skip_in_tests,
            attack: raw.attack,
            fix: raw.fix,
            source: source.to_string(),
        });
    }
    Ok(rules)
}

/// Reject duplicate IDs across all loaded files.
fn check_unique(rules: &[Rule]) -> Result<()> {
    let mut seen = HashSet::new();
    for r in rules {
        if !seen.insert(r.id.as_str()) {
            bail!("duplicate rule id {} (in {})", r.id, r.source);
        }
    }
    Ok(())
}

/// The rules compiled into the binary.
pub fn load_builtin() -> Result<Vec<Rule>> {
    let mut all = Vec::new();
    for (name, text) in BUILTIN_RULES {
        all.extend(parse_rules(name, text)?);
    }
    check_unique(&all)?;
    Ok(all)
}

/// Every `*.toml` file in `dir`, in file-name order (so output is stable).
pub fn load_dir(dir: &Path) -> Result<Vec<Rule>> {
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("cannot read rules directory {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    paths.sort();
    if paths.is_empty() {
        bail!("no .toml rule files in {}", dir.display());
    }

    let mut all = Vec::new();
    for p in paths {
        let text =
            std::fs::read_to_string(&p).with_context(|| format!("cannot read {}", p.display()))?;
        all.extend(parse_rules(&p.display().to_string(), &text)?);
    }
    check_unique(&all)?;
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_load() {
        let rules = load_builtin().expect("builtin rules must parse");
        assert!(
            rules.len() >= 30,
            "expected a full rule set, got {}",
            rules.len()
        );
    }

    #[test]
    fn rule_ids_match_their_file() {
        for r in load_builtin().unwrap() {
            let prefix = match r.source.as_str() {
                "core.toml" => "TAI-CORE-",
                "js.toml" => "TAI-JS-",
                "python.toml" => "TAI-PY-",
                "rust.toml" => "TAI-RS-",
                other => panic!("unexpected source {other}"),
            };
            assert!(
                r.id.starts_with(prefix),
                "{} should start with {prefix}",
                r.id
            );
        }
    }

    #[test]
    fn every_rule_has_guidance() {
        for r in load_builtin().unwrap() {
            assert!(r.cwe.starts_with("CWE-"), "{} needs a CWE", r.id);
            assert!(
                !r.attack.trim().is_empty(),
                "{} needs an attack scenario",
                r.id
            );
            assert!(!r.fix.trim().is_empty(), "{} needs a fix", r.id);
        }
    }

    #[test]
    fn severity_orders_low_to_high() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn rejects_bad_regex() {
        let toml = r#"
            [[rule]]
            id = "X-1"
            title = "t"
            severity = "low"
            cwe = "CWE-1"
            owasp = ""
            languages = ["any"]
            pattern = "("
            attack = "a"
            fix = "f"
        "#;
        assert!(parse_rules("test", toml).is_err());
    }

    #[test]
    fn rejects_unknown_language() {
        let toml = r#"
            [[rule]]
            id = "X-1"
            title = "t"
            severity = "low"
            cwe = "CWE-1"
            owasp = ""
            languages = ["cobol"]
            pattern = "x"
            attack = "a"
            fix = "f"
        "#;
        assert!(parse_rules("test", toml).is_err());
    }
}
