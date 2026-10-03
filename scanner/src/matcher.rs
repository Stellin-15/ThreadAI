//! Running rules against file contents, one line at a time.

use serde::Serialize;

use crate::rules::{Rule, Severity};
use crate::walker::Language;

/// Longest snippet we print; long minified lines are cut.
const MAX_SNIPPET_CHARS: usize = 200;

/// A comment containing this suppresses findings on the same line.
/// `threadai-ignore` alone silences every rule; follow it with rule IDs
/// (`threadai-ignore TAI-PY-001`) to silence only those.
pub const IGNORE_MARKER: &str = "threadai-ignore";
/// Put this on the line *above* to suppress the next line instead.
pub const IGNORE_NEXT_MARKER: &str = "threadai-ignore-next-line";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub cwe: String,
    pub owasp: String,
    /// Path relative to the scan root, always with forward slashes.
    pub file: String,
    /// 1-based.
    pub line: usize,
    /// 1-based, in characters.
    pub column: usize,
    /// The offending line (trimmed, truncated, secrets masked).
    pub snippet: String,
    pub attack: String,
    pub fix: String,
}

/// Scan one file's text. `rules` is borrowed (`&[Rule]`), not moved, so the
/// caller can reuse the same rules for every file.
pub fn scan_text(rules: &[Rule], lang: Language, file: &str, text: &str) -> Vec<Finding> {
    let in_tests = is_test_path(file);
    let active: Vec<&Rule> = rules
        .iter()
        .filter(|r| r.applies_to(lang) && !(in_tests && r.skip_in_tests))
        .collect();
    let mut findings = Vec::new();
    let mut prev_line = "";

    for (idx, line) in text.lines().enumerate() {
        for rule in &active {
            let Some(m) = rule.pattern.find(line) else {
                continue;
            };
            if rule.exclude.as_ref().is_some_and(|ex| ex.is_match(line)) {
                continue;
            }
            if is_suppressed(line, prev_line, &rule.id) {
                continue;
            }

            let snippet = if rule.redact {
                let masked = format!(
                    "{}{}{}",
                    &line[..m.start()],
                    redact(m.as_str()),
                    &line[m.end()..]
                );
                tidy_snippet(&masked)
            } else {
                tidy_snippet(line)
            };

            findings.push(Finding {
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                severity: rule.severity,
                cwe: rule.cwe.clone(),
                owasp: rule.owasp.clone(),
                file: file.to_string(),
                line: idx + 1,
                column: line[..m.start()].chars().count() + 1,
                snippet,
                attack: rule.attack.clone(),
                fix: rule.fix.clone(),
            });
        }
        prev_line = line;
    }
    findings
}

/// Heuristic for test code: a `test`/`tests`/`__tests__`/`spec` directory,
/// or a file named like `test_x.py`, `x_test.go`, `x.test.ts`, `x.spec.js`.
pub fn is_test_path(file: &str) -> bool {
    let lower = file.to_ascii_lowercase();
    let mut parts: Vec<&str> = lower.split('/').collect();
    let name = parts.pop().unwrap_or("");
    if parts
        .iter()
        .any(|d| matches!(*d, "test" | "tests" | "__tests__" | "spec" | "specs"))
    {
        return true;
    }
    let stem = name.split('.').next().unwrap_or("");
    stem.starts_with("test_")
        || stem.ends_with("_test")
        || stem.ends_with("_tests")
        || name.contains(".test.")
        || name.contains(".spec.")
}

fn is_suppressed(line: &str, prev_line: &str, rule_id: &str) -> bool {
    if let Some(pos) = prev_line.find(IGNORE_NEXT_MARKER) {
        if marker_covers(&prev_line[pos + IGNORE_NEXT_MARKER.len()..], rule_id) {
            return true;
        }
    }
    // Look for a same-line marker that is not the "next-line" variant.
    let mut rest = line;
    while let Some(pos) = rest.find(IGNORE_MARKER) {
        let after = &rest[pos + IGNORE_MARKER.len()..];
        if !after.starts_with("-next-line") && marker_covers(after, rule_id) {
            return true;
        }
        rest = after;
    }
    false
}

/// `after` is the text following a marker. No IDs listed → covers every rule.
fn marker_covers(after: &str, rule_id: &str) -> bool {
    let ids: Vec<&str> = after
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|w| w.starts_with("TAI-"))
        .collect();
    ids.is_empty() || ids.contains(&rule_id)
}

/// Hide a secret but keep enough to recognise which one it was.
/// If the match contains a quoted value, only the value is masked:
///   password = "hunter2hunter2"  ->  password = "hu****"    (threadai-ignore)
/// otherwise the first 4 characters are kept: AKIAIOSFODNN7EXAMPLE -> AKIA****  (threadai-ignore)
pub fn redact(matched: &str) -> String {
    for quote in ['"', '\'', '`'] {
        let (Some(start), Some(end)) = (matched.find(quote), matched.rfind(quote)) else {
            continue;
        };
        if end > start + 1 {
            let value = &matched[start + 1..end];
            let keep: String = value.chars().take(2).collect();
            return format!("{}{keep}****{}", &matched[..=start], &matched[end..]);
        }
    }
    let keep: String = matched.chars().take(4).collect();
    format!("{keep}****")
}

fn tidy_snippet(line: &str) -> String {
    let trimmed = line.trim();
    let shown = if trimmed.chars().count() > MAX_SNIPPET_CHARS {
        let cut: String = trimmed.chars().take(MAX_SNIPPET_CHARS).collect();
        format!("{cut}…")
    } else {
        trimmed.to_string()
    };
    sanitize_for_terminal(&shown)
}

/// Scanned files are untrusted. Make control characters (ANSI escape codes
/// that could rewrite the terminal and hide findings) and Unicode bidi
/// overrides ("Trojan Source", CVE-2021-42574) visible instead of active.
pub fn sanitize_for_terminal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let bidi = matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
        if c == '\t' {
            out.push(' ');
        } else if c.is_control() || bidi {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::load_builtin;

    fn ids(lang: Language, text: &str) -> Vec<String> {
        let rules = load_builtin().unwrap();
        scan_text(&rules, lang, "t", text)
            .into_iter()
            .map(|f| f.rule_id)
            .collect()
    }

    #[test]
    fn finds_pickle() {
        assert_eq!(
            ids(Language::Python, "obj = pickle.loads(data)"),
            vec!["TAI-PY-001"]
        );
    }

    #[test]
    fn language_filter_applies() {
        // pickle rule is Python-only, so a .js file never triggers it.
        assert!(ids(Language::JavaScript, "obj = pickle.loads(data)").is_empty());
    }

    #[test]
    fn exclude_pattern_drops_safe_usage() {
        assert!(ids(Language::Python, "yaml.load(f, Loader=yaml.SafeLoader)").is_empty());
        assert_eq!(ids(Language::Python, "yaml.load(f)"), vec!["TAI-PY-002"]);
    }

    #[test]
    fn same_line_suppression() {
        assert!(ids(Language::Python, "pickle.loads(d)  # threadai-ignore").is_empty());
        assert!(ids(
            Language::Python,
            "pickle.loads(d)  # threadai-ignore TAI-PY-001"
        )
        .is_empty());
        // Suppressing a different ID does not hide this one.
        assert_eq!(
            ids(
                Language::Python,
                "pickle.loads(d)  # threadai-ignore TAI-PY-002"
            ),
            vec!["TAI-PY-001"]
        );
    }

    #[test]
    fn next_line_suppression() {
        let text = "# threadai-ignore-next-line TAI-PY-001\npickle.loads(d)\npickle.loads(e)\n";
        let rules = load_builtin().unwrap();
        let found = scan_text(&rules, Language::Python, "t", text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 3);
    }

    #[test]
    fn secrets_are_redacted() {
        let rules = load_builtin().unwrap();
        let f = scan_text(&rules, Language::Other, "t", "aws_id: AKIAIOSFODNN7EXAMPLE"); // threadai-ignore
        assert_eq!(f[0].snippet, "aws_id: AKIA****");
        assert!(!f[0].snippet.contains("IOSFODNN7"));
    }

    #[test]
    fn redact_masks_quoted_value() {
        // threadai-ignore-next-line
        let input = r#"password = "hunter2hunter2""#;
        // threadai-ignore-next-line
        let expected = r#"password = "hu****""#;
        assert_eq!(redact(input), expected);
        assert_eq!(redact("AKIAIOSFODNN7EXAMPLE"), "AKIA****"); // threadai-ignore
    }

    #[test]
    fn reports_line_and_column() {
        let rules = load_builtin().unwrap();
        let f = scan_text(
            &rules,
            Language::Python,
            "t",
            "x = 1\n    data = pickle.loads(b)\n",
        );
        assert_eq!((f[0].line, f[0].column), (2, 12));
    }

    #[test]
    fn test_files_are_detected() {
        for p in [
            "tests/cli.rs",
            "src/__tests__/a.js",
            "test_app.py",
            "app_test.go",
            "a.test.ts",
            "b.spec.jsx",
        ] {
            assert!(is_test_path(p), "{p} should be a test path");
        }
        for p in ["src/main.rs", "app.py", "contest.py", "latest/x.js"] {
            assert!(!is_test_path(p), "{p} should not be a test path");
        }
    }

    #[test]
    fn skip_in_tests_rules_ignore_test_files() {
        let rules = load_builtin().unwrap();
        let line = "let n: u16 = s.parse().unwrap();"; // threadai-ignore
        assert_eq!(
            scan_text(&rules, Language::Rust, "src/main.rs", line).len(),
            1
        );
        assert!(scan_text(&rules, Language::Rust, "tests/cli.rs", line).is_empty());
    }

    #[test]
    fn terminal_escapes_are_neutralised() {
        let rules = load_builtin().unwrap();
        let line = "x = pickle.loads(d)  # \u{1b}[2K\u{1b}[1Alooks fine \u{202E}evil";
        let f = scan_text(&rules, Language::Python, "t", line);
        assert!(!f[0].snippet.contains('\u{1b}'));
        assert!(!f[0].snippet.contains('\u{202E}'));
        assert!(f[0].snippet.contains(r"\u{1b}[2K"));
        assert!(f[0].snippet.contains(r"\u{202e}"));
    }

    #[test]
    fn method_named_exec_is_not_flagged() {
        // regex.exec() in JS is not child_process.exec
        assert!(ids(Language::JavaScript, "const m = re.exec(input);").is_empty());
    }
}
