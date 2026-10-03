//! Runs the real `threadai` binary, the way users and CI will.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_threadai"))
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn run(args: &[&str], path: &Path) -> Output {
    bin().arg("scan").arg(path).args(args).output().unwrap()
}

#[test]
fn exit_code_1_when_findings() {
    let out = run(&[], &fixture("vulnerable"));
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("TAI-PY-001"));
    assert!(text.contains("findings"));
}

#[test]
fn exit_code_0_when_clean() {
    let out = run(&[], &fixture("clean"));
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("No findings"));
}

#[test]
fn exit_code_2_on_error() {
    let out = run(&[], Path::new("definitely/not/a/real/path"));
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("error"));
}

#[test]
fn json_output_parses() {
    let out = run(&["--format", "json"], &fixture("vulnerable"));
    let v: Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(v["tool"], "threadai");
    assert!(v["findings"].as_array().unwrap().len() > 30);
    // No ANSI colour codes leak into machine output.
    assert!(!String::from_utf8_lossy(&out.stdout).contains('\u{1b}'));
}

#[test]
fn sarif_output_is_valid_shape() {
    let out = run(&["--format", "sarif"], &fixture("vulnerable"));
    let v: Value = serde_json::from_slice(&out.stdout).expect("valid SARIF JSON");
    assert_eq!(v["version"], "2.1.0");
    let results = v["runs"][0]["results"].as_array().unwrap();
    assert!(!results.is_empty());
    for r in results {
        let uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert!(
            !uri.contains('\\'),
            "SARIF URIs must use forward slashes: {uri}"
        );
    }
}

#[test]
fn min_severity_flag_controls_exit_code() {
    // The clean fixtures have no findings at any level...
    let out = run(&["--min-severity", "critical"], &fixture("clean"));
    assert_eq!(out.status.code(), Some(0));
    // ...and only critical findings survive the filter on vulnerable ones.
    let out = run(&["-s", "critical", "-f", "json"], &fixture("vulnerable"));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    for f in v["findings"].as_array().unwrap() {
        assert_eq!(f["severity"], "critical");
    }
}

#[test]
fn output_flag_writes_file() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("report.sarif");
    let out = run(
        &["-f", "sarif", "-o", report.to_str().unwrap()],
        &fixture("vulnerable"),
    );
    assert_eq!(out.status.code(), Some(1));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(report).unwrap()).unwrap();
    assert_eq!(v["version"], "2.1.0");
}

#[test]
fn custom_rules_dir_replaces_builtin() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("mine.toml"),
        r#"
[[rule]]
id = "ACME-001"
title = "TODO left in code"
severity = "info"
cwe = "CWE-546"
owasp = ""
languages = ["any"]
pattern = "TODO"
attack = "n/a"
fix = "Finish it."
"#,
    )
    .unwrap();
    let src = dir.path().join("src.py");
    std::fs::write(&src, "x = 1  # TODO\nimport pickle; pickle.loads(b)\n").unwrap();

    let out = run(
        &[
            "--rules",
            dir.path().to_str().unwrap(),
            "-s",
            "info",
            "-f",
            "json",
        ],
        &src,
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids: Vec<_> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids, vec!["ACME-001"]);
}

#[test]
fn rules_command_lists_everything() {
    let out = bin().args(["rules", "--format", "json"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.as_array().unwrap().len() >= 30);
}

#[test]
fn scanning_never_modifies_files() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.py");
    let body = "import pickle\npickle.loads(b)\n";
    std::fs::write(&f, body).unwrap();
    run(&[], dir.path());
    assert_eq!(std::fs::read_to_string(&f).unwrap(), body);
}
