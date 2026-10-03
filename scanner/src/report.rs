//! Turning findings into text, JSON, SARIF or Markdown.

use colored::Colorize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::matcher::Finding;
use crate::rules::{Rule, Severity};
use crate::ScanResult;

pub const TOOL_NAME: &str = "threadai";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const INFO_URI: &str = "https://github.com/Stellin-15/ThreadAI";

fn severity_label(s: Severity) -> colored::ColoredString {
    let text = format!("{:<8}", s.as_str().to_uppercase());
    match s {
        Severity::Critical => text.white().on_red().bold(),
        Severity::High => text.red().bold(),
        Severity::Medium => text.yellow().bold(),
        Severity::Low => text.cyan(),
        Severity::Info => text.dimmed(),
    }
}

/// Counts per severity, highest first, skipping zeros: "1 critical, 3 high".
pub fn summary_line(findings: &[Finding]) -> String {
    let mut counts: BTreeMap<Severity, usize> = BTreeMap::new();
    for f in findings {
        *counts.entry(f.severity).or_default() += 1;
    }
    counts
        .iter()
        .rev()
        .map(|(s, n)| format!("{n} {}", s.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Human-readable report, grouped by file.
pub fn to_text(result: &ScanResult) -> String {
    let mut out = String::new();
    let mut current_file: Option<&str> = None;

    for f in &result.findings {
        if current_file != Some(f.file.as_str()) {
            let _ = writeln!(out, "\n{}", f.file.bold().underline());
            current_file = Some(f.file.as_str());
        }
        let _ = writeln!(
            out,
            "  {:>5}:{:<3} {} {}  {}",
            f.line,
            f.column,
            severity_label(f.severity),
            f.rule_id.bold(),
            f.title
        );
        let _ = writeln!(out, "             {} {}", ">".dimmed(), f.snippet.dimmed());
        let _ = writeln!(out, "             {} {}", "attack:".red(), f.attack);
        let _ = writeln!(out, "             {}    {}", "fix:".green(), f.fix);
    }

    let _ = writeln!(out);
    if result.findings.is_empty() {
        let _ = writeln!(
            out,
            "{} No findings in {} files scanned.",
            "✓".green().bold(),
            result.files_scanned
        );
    } else {
        let _ = writeln!(
            out,
            "{} {} findings ({}) in {} files scanned.",
            "✗".red().bold(),
            result.findings.len(),
            summary_line(&result.findings),
            result.files_scanned
        );
        let _ = writeln!(
            out,
            "  Silence a reviewed false positive with a `threadai-ignore <RULE-ID>` comment on that line."
        );
    }
    out
}

/// Machine-readable report. Stable shape — the Claude plugin parses this.
pub fn to_json(result: &ScanResult) -> String {
    let mut by_severity: BTreeMap<&str, usize> = BTreeMap::new();
    for f in &result.findings {
        *by_severity.entry(f.severity.as_str()).or_default() += 1;
    }
    let doc = json!({
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "files_scanned": result.files_scanned,
        "summary": by_severity,
        "findings": result.findings,
    });
    serde_json::to_string_pretty(&doc).expect("JSON serialization cannot fail")
}

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// GitHub code scanning uses this 0–10 score to rank security alerts.
fn security_score(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "1.0",
    }
}

/// SARIF 2.1.0 — upload to GitHub code scanning or open in a SARIF viewer.
pub fn to_sarif(result: &ScanResult, rules: &[Rule]) -> String {
    let rule_index: BTreeMap<&str, usize> = rules
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id.as_str(), i))
        .collect();

    let sarif_rules: Vec<Value> = rules
        .iter()
        .map(|r| {
            let mut tags = vec!["security".to_string(), r.cwe.clone()];
            if !r.owasp.is_empty() {
                tags.push(format!("OWASP-{}", r.owasp));
            }
            json!({
                "id": r.id,
                "name": r.id.replace('-', ""),
                "shortDescription": { "text": r.title },
                "fullDescription": { "text": r.attack },
                "help": {
                    "text": r.fix,
                    "markdown": format!("**Attack:** {}\n\n**Fix:** {}", r.attack, r.fix),
                },
                "helpUri": format!("{INFO_URI}#rules"),
                "defaultConfiguration": { "level": sarif_level(r.severity) },
                "properties": {
                    "tags": tags,
                    "security-severity": security_score(r.severity),
                    "precision": "medium",
                },
            })
        })
        .collect();

    let results: Vec<Value> = result
        .findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule_id,
                "ruleIndex": rule_index.get(f.rule_id.as_str()),
                "level": sarif_level(f.severity),
                "message": { "text": format!("{} — {}", f.title, f.fix) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file, "uriBaseId": "%SRCROOT%" },
                        "region": { "startLine": f.line, "startColumn": f.column },
                    }
                }],
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": INFO_URI,
                    "rules": sarif_rules,
                }
            },
            "results": results,
        }],
    });
    serde_json::to_string_pretty(&doc).expect("JSON serialization cannot fail")
}

/// Plain-text list of rules for `threadai rules`.
pub fn rules_to_text(rules: &[Rule]) -> String {
    let mut out = String::new();
    for r in rules {
        let _ = writeln!(
            out,
            "{} {} {} [{}]",
            r.id.bold(),
            severity_label(r.severity),
            r.title,
            r.languages.join(", ")
        );
    }
    let _ = writeln!(out, "\n{} rules.", rules.len());
    out
}

pub fn rules_to_json(rules: &[Rule]) -> String {
    let list: Vec<Value> = rules
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "title": r.title,
                "severity": r.severity,
                "cwe": r.cwe,
                "owasp": r.owasp,
                "languages": r.languages,
                "attack": r.attack,
                "fix": r.fix,
            })
        })
        .collect();
    serde_json::to_string_pretty(&list).expect("JSON serialization cannot fail")
}

/// The rules catalog the Claude plugin reads. Generated, never hand-edited:
/// `threadai rules --format markdown > plugin/skills/security-audit/references/rules-catalog.md`
pub fn rules_to_markdown(rules: &[Rule]) -> String {
    let mut out = String::new();
    out.push_str("# ThreadAI rules catalog\n\n");
    out.push_str(
        "<!-- GENERATED by `threadai rules --format markdown`. Edit rules/*.toml, then regenerate. -->\n\n",
    );
    out.push_str(
        "Every pattern the `threadai` CLI checks. Use the same IDs in audit reports so CLI and AI findings line up.\n",
    );

    let groups = [
        ("TAI-CORE-", "Core (all languages)"),
        ("TAI-JS-", "JavaScript / TypeScript"),
        ("TAI-PY-", "Python"),
        ("TAI-RS-", "Rust"),
    ];
    for (prefix, heading) in groups {
        let in_group: Vec<&Rule> = rules.iter().filter(|r| r.id.starts_with(prefix)).collect();
        if in_group.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n## {heading}\n");
        for r in in_group {
            let owasp = if r.owasp.is_empty() {
                String::new()
            } else {
                format!(" · {}", r.owasp)
            };
            let _ = writeln!(out, "### {} — {}\n", r.id, r.title);
            let _ = writeln!(
                out,
                "- **Severity:** {} · {}{}",
                r.severity.as_str(),
                r.cwe,
                owasp
            );
            let _ = writeln!(out, "- **Attack:** {}", r.attack);
            let _ = writeln!(out, "- **Fix:** {}\n", r.fix);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ScanResult {
        ScanResult {
            files_scanned: 1,
            findings: vec![Finding {
                rule_id: "TAI-PY-001".into(),
                title: "pickle".into(),
                severity: Severity::High,
                cwe: "CWE-502".into(),
                owasp: "A08:2021".into(),
                file: "app.py".into(),
                line: 3,
                column: 5,
                snippet: "pickle.loads(x)".into(),
                attack: "rce".into(),
                fix: "use json".into(),
            }],
        }
    }

    #[test]
    fn json_has_expected_shape() {
        let v: Value = serde_json::from_str(&to_json(&sample())).unwrap();
        assert_eq!(v["files_scanned"], 1);
        assert_eq!(v["summary"]["high"], 1);
        assert_eq!(v["findings"][0]["rule_id"], "TAI-PY-001");
        assert_eq!(v["findings"][0]["severity"], "high");
    }

    #[test]
    fn sarif_has_expected_shape() {
        let rules = crate::rules::load_builtin().unwrap();
        let v: Value = serde_json::from_str(&to_sarif(&sample(), &rules)).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let run = &v["runs"][0];
        assert_eq!(
            run["tool"]["driver"]["rules"].as_array().unwrap().len(),
            rules.len()
        );
        let res = &run["results"][0];
        assert_eq!(res["level"], "error");
        let idx = res["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(run["tool"]["driver"]["rules"][idx]["id"], "TAI-PY-001");
        assert_eq!(
            res["locations"][0]["physicalLocation"]["region"]["startLine"],
            3
        );
    }

    #[test]
    fn summary_is_highest_first() {
        let mut r = sample();
        let mut low = r.findings[0].clone();
        low.severity = Severity::Low;
        r.findings.push(low);
        assert_eq!(summary_line(&r.findings), "1 high, 1 low");
    }
}
