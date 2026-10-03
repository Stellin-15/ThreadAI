//! End-to-end checks of the scanner against the sample projects in
//! `tests/fixtures/`. `vulnerable/` marks every expected finding with an
//! `expect: TAI-...` comment on the line above; `clean/` must report nothing.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use threadai::rules::{self, Severity};
use threadai::{report, scan_path, walker};

/// (file, line, rule id)
type Hit = (String, usize, String);

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Collect every `expect:` marker under `dir`.
fn expectations(dir: &Path) -> BTreeSet<Hit> {
    let mut out = BTreeSet::new();
    for path in walker::collect_files(dir).unwrap() {
        let label = path
            .strip_prefix(dir)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&path).unwrap();
        for (idx, line) in text.lines().enumerate() {
            let Some(pos) = line.find("expect:") else {
                continue;
            };
            for id in line[pos + "expect:".len()..]
                .split(|c: char| c.is_whitespace() || c == ',')
                .filter(|w| w.starts_with("TAI-"))
            {
                // marker is on line idx+1 (1-based), so it targets idx+2
                out.insert((label.clone(), idx + 2, id.to_string()));
            }
        }
    }
    out
}

fn hits(dir: &Path) -> BTreeSet<Hit> {
    let rules = rules::load_builtin().unwrap();
    scan_path(dir, &rules, Severity::Info)
        .unwrap()
        .findings
        .into_iter()
        .map(|f| (f.file, f.line, f.rule_id))
        .collect()
}

#[test]
fn vulnerable_fixtures_match_expectations_exactly() {
    let dir = fixtures().join("vulnerable");
    let expected = expectations(&dir);
    let found = hits(&dir);

    let missed: Vec<_> = expected.difference(&found).collect();
    let unexpected: Vec<_> = found.difference(&expected).collect();
    assert!(
        missed.is_empty() && unexpected.is_empty(),
        "\nmissed (rule should have fired): {missed:#?}\nunexpected (false positive): {unexpected:#?}"
    );
}

#[test]
fn clean_fixtures_have_no_findings() {
    let found = hits(&fixtures().join("clean"));
    assert!(
        found.is_empty(),
        "false positives on clean code: {found:#?}"
    );
}

/// Real-looking tokens are assembled at runtime so that this repo never
/// contains a string that GitHub push protection would block.
fn write_generated_secrets(dir: &Path) {
    let github = format!("{}{}", "gh", "p_".to_string() + &"A1b2C3d4E5".repeat(4));
    let slack = format!("{}{}", "xo", "xb-0000000000-0000000000-AbCdEfGhIjKl");
    let pem = format!("-----BEGIN RSA {} KEY-----", "PRIVATE");
    let text = format!("github: {github}\nslack: {slack}\n{pem}\nMIIEtest\n");
    std::fs::write(dir.join("secrets.yml"), text).unwrap();
}

#[test]
fn token_rules_fire_and_are_redacted() {
    let dir = tempfile::tempdir().unwrap();
    write_generated_secrets(dir.path());
    let rules = rules::load_builtin().unwrap();
    let result = scan_path(dir.path(), &rules, Severity::Info).unwrap();

    let ids: BTreeSet<_> = result.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert_eq!(
        ids,
        BTreeSet::from(["TAI-CORE-002", "TAI-CORE-004", "TAI-CORE-005"])
    );
    for f in &result.findings {
        assert!(
            f.snippet.contains("****"),
            "{} not redacted: {}",
            f.rule_id,
            f.snippet
        );
        assert!(
            !f.snippet.contains("A1b2C3d4E5A1b2"),
            "token leaked: {}",
            f.snippet
        );
    }
}

#[test]
fn every_rule_is_covered_by_a_fixture() {
    let mut covered: BTreeSet<String> = expectations(&fixtures().join("vulnerable"))
        .into_iter()
        .map(|(_, _, id)| id)
        .collect();
    covered.extend(["TAI-CORE-002", "TAI-CORE-004", "TAI-CORE-005"].map(String::from));

    let uncovered: Vec<_> = rules::load_builtin()
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .filter(|id| !covered.contains(id))
        .collect();
    assert!(uncovered.is_empty(), "rules with no fixture: {uncovered:?}");
}

#[test]
fn min_severity_filters_findings() {
    let rules = rules::load_builtin().unwrap();
    let result = scan_path(&fixtures().join("vulnerable"), &rules, Severity::Critical).unwrap();
    assert!(!result.findings.is_empty());
    assert!(result
        .findings
        .iter()
        .all(|f| f.severity == Severity::Critical));
}

/// The plugin reads a generated copy of the rules. If you change
/// rules/*.toml, regenerate it with:
///   cargo run -q -- rules --format markdown > plugin/skills/security-audit/references/rules-catalog.md
#[test]
fn plugin_rules_catalog_is_up_to_date() {
    let catalog = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../plugin/skills/security-audit/references/rules-catalog.md");
    let on_disk = std::fs::read_to_string(&catalog)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    let generated = report::rules_to_markdown(&rules::load_builtin().unwrap());
    assert!(
        on_disk == generated,
        "rules-catalog.md is stale — regenerate it (see comment above this test)"
    );
}
