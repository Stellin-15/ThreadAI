//! Keeps the Claude plugin consistent with the rule database.

use regex::Regex;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use threadai::rules;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn skill_dir() -> PathBuf {
    repo().join("plugin/skills/security-audit")
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// Hand-written plugin docs (the generated catalog is checked elsewhere).
fn handwritten_docs() -> Vec<PathBuf> {
    let refs = skill_dir().join("references");
    let mut docs = vec![
        skill_dir().join("SKILL.md"),
        repo().join("plugin/commands/audit.md"),
    ];
    for name in [
        "threat-model",
        "core",
        "web-js",
        "python",
        "rust",
        "report-template",
    ] {
        docs.push(refs.join(format!("{name}.md")));
    }
    docs
}

fn rule_ids() -> BTreeSet<String> {
    rules::load_builtin()
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect()
}

#[test]
fn every_id_the_plugin_mentions_exists() {
    let id_re = Regex::new(r"TAI-(CORE|JS|PY|RS)-\d{3}").unwrap();
    let known = rule_ids();
    for doc in handwritten_docs() {
        for m in id_re.find_iter(&read(&doc)) {
            assert!(
                known.contains(m.as_str()),
                "{} references unknown rule {}",
                doc.display(),
                m.as_str()
            );
        }
    }
}

#[test]
fn every_rule_appears_in_a_checklist() {
    let all_docs: String = handwritten_docs().iter().map(|p| read(p)).collect();
    let missing: Vec<_> = rule_ids()
        .into_iter()
        .filter(|id| !all_docs.contains(id.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "rules not mentioned in any checklist: {missing:?}"
    );
}

#[test]
fn skill_frontmatter_is_valid() {
    let text = read(&skill_dir().join("SKILL.md")).replace("\r\n", "\n");
    let fm = text
        .strip_prefix("---\n")
        .and_then(|rest| rest.split_once("\n---\n"))
        .map(|(fm, _)| fm)
        .expect("SKILL.md must start with --- frontmatter ---");
    assert!(fm.contains("name: security-audit"));
    let desc = fm
        .lines()
        .find_map(|l| l.strip_prefix("description: "))
        .expect("description required");
    assert!(
        desc.len() > 100 && desc.len() < 1024,
        "description length {}",
        desc.len()
    );
}

#[test]
fn skill_links_point_to_real_files() {
    let link_re = Regex::new(r"\]\((references/[^)]+)\)").unwrap();
    let text = read(&skill_dir().join("SKILL.md"));
    let mut n = 0;
    for cap in link_re.captures_iter(&text) {
        n += 1;
        let p = skill_dir().join(&cap[1]);
        assert!(p.exists(), "SKILL.md links to missing {}", p.display());
    }
    assert!(n >= 6, "expected SKILL.md to link its reference files");
}

#[test]
fn skill_keeps_its_safety_rules() {
    let text = read(&skill_dir().join("SKILL.md")).to_lowercase();
    for must in [
        "untrusted data",
        "prompt-injection",
        "never execute",
        "never repeat secrets",
        "fixes need approval",
        "quote or drop",
        "rule metadata is authoritative",
    ] {
        assert!(text.contains(must), "SKILL.md lost safety rule: {must}");
    }
}

#[test]
fn manifests_agree_on_name_and_version() {
    let plugin: Value =
        serde_json::from_str(&read(&repo().join("plugin/.claude-plugin/plugin.json"))).unwrap();
    let market: Value =
        serde_json::from_str(&read(&repo().join(".claude-plugin/marketplace.json"))).unwrap();
    let entry = &market["plugins"][0];
    assert_eq!(plugin["name"], entry["name"]);
    assert_eq!(plugin["version"], entry["version"]);
    assert_eq!(entry["source"], "./plugin");
    // The plugin and the CLI ship together, so they share a version number.
    assert_eq!(plugin["version"], env!("CARGO_PKG_VERSION"));
}
