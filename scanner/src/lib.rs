//! ThreadAI scanner library. `main.rs` is a thin CLI over this; the
//! integration tests in `tests/` call it directly.

pub mod matcher;
pub mod report;
pub mod rules;
pub mod walker;

use anyhow::Result;
use std::path::Path;

use matcher::Finding;
use rules::{Rule, Severity};

#[derive(Debug, Default)]
pub struct ScanResult {
    pub files_scanned: usize,
    pub findings: Vec<Finding>,
}

/// Scan a file or directory. Files are only ever *read* — nothing is
/// executed, and nothing leaves the machine.
pub fn scan_path(root: &Path, rules: &[Rule], min_severity: Severity) -> Result<ScanResult> {
    let mut result = ScanResult::default();
    let root_is_dir = root.is_dir();

    for path in walker::collect_files(root)? {
        let lang = walker::language_for(&path).unwrap_or(walker::Language::Other);
        let Some(text) = walker::read_text(&path)? else {
            continue; // binary
        };
        result.files_scanned += 1;

        let shown = if root_is_dir {
            path.strip_prefix(root).unwrap_or(&path)
        } else {
            path.as_path()
        };
        // File names come from the scanned repo too, so they get the same treatment.
        let label = matcher::sanitize_for_terminal(&shown.to_string_lossy().replace('\\', "/"));

        result.findings.extend(
            matcher::scan_text(rules, lang, &label, &text)
                .into_iter()
                .filter(|f| f.severity >= min_severity),
        );
    }
    Ok(result)
}
