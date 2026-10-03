//! Finding which files to scan and what language each one is.

use anyhow::{Context, Result};
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

/// Files bigger than this are skipped (minified bundles, data dumps).
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Directories never worth scanning, even without a .gitignore.
const SKIP_DIRS: [&str; 8] = [
    ".git",
    "node_modules",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    JavaScript,
    Python,
    Rust,
    /// Config files and other languages: only "any" rules run on these.
    Other,
}

impl Language {
    /// Matches the names used in a rule's `languages` list.
    pub fn name(self) -> &'static str {
        match self {
            Language::JavaScript => "javascript",
            Language::Python => "python",
            Language::Rust => "rust",
            Language::Other => "other",
        }
    }
}

/// `None` means "not a file we scan".
pub fn language_for(path: &Path) -> Option<Language> {
    let file_name = path.file_name()?.to_str()?.to_ascii_lowercase();
    if file_name == ".env" || file_name.starts_with(".env.") {
        return Some(Language::Other);
    }
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    let lang = match ext.as_str() {
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts" | "vue" | "svelte" => {
            Language::JavaScript
        }
        "py" | "pyw" => Language::Python,
        "rs" => Language::Rust,
        "go" | "java" | "kt" | "rb" | "php" | "cs" | "c" | "cc" | "cpp" | "h" | "hpp" | "swift"
        | "sh" | "bash" | "zsh" | "ps1" | "yml" | "yaml" | "json" | "toml" | "ini" | "cfg"
        | "conf" | "env" | "properties" | "xml" | "tf" | "html" | "sql" | "dockerfile" => {
            Language::Other
        }
        _ => return None,
    };
    Some(lang)
}

/// All scannable files under `root`, sorted for stable output.
///
/// Honours `.gitignore` (even outside a git repo) and a project-specific
/// `.threadaiignore` with the same syntax.
pub fn collect_files(root: &Path) -> Result<Vec<PathBuf>> {
    let meta =
        std::fs::metadata(root).with_context(|| format!("cannot access {}", root.display()))?;
    if meta.is_file() {
        // A file named explicitly is always scanned, even with an odd extension.
        return Ok(vec![root.to_path_buf()]);
    }

    let mut files = Vec::new();
    let walker = WalkBuilder::new(root)
        .hidden(false) // .env files are hidden but very much worth scanning
        .require_git(false)
        .add_custom_ignore_filename(".threadaiignore")
        .filter_entry(|e| {
            let is_dir = e.file_type().is_some_and(|t| t.is_dir());
            !(is_dir
                && e.file_name()
                    .to_str()
                    .is_some_and(|n| SKIP_DIRS.contains(&n)))
        })
        .build();

    for entry in walker {
        let entry = entry?;
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        if language_for(path).is_none() {
            continue;
        }
        if entry
            .metadata()
            .map(|m| m.len() > MAX_FILE_BYTES)
            .unwrap_or(true)
        {
            continue;
        }
        files.push(path.to_path_buf());
    }
    files.sort();
    Ok(files)
}

/// Read a file as text; `None` for binary files (contains a NUL byte).
pub fn read_text(path: &Path) -> Result<Option<String>> {
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.iter().take(8192).any(|&b| b == 0) {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_languages() {
        assert_eq!(
            language_for(Path::new("a/b.tsx")),
            Some(Language::JavaScript)
        );
        assert_eq!(language_for(Path::new("x.py")), Some(Language::Python));
        assert_eq!(language_for(Path::new("main.rs")), Some(Language::Rust));
        assert_eq!(
            language_for(Path::new("config.yaml")),
            Some(Language::Other)
        );
        assert_eq!(language_for(Path::new(".env")), Some(Language::Other));
        assert_eq!(language_for(Path::new(".env.local")), Some(Language::Other));
        assert_eq!(language_for(Path::new("photo.png")), None);
        assert_eq!(language_for(Path::new("Makefile")), None);
    }

    #[test]
    fn walks_and_respects_ignores() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("app.py"), "x = 1\n").unwrap();
        std::fs::write(root.join("skip.py"), "x = 1\n").unwrap();
        std::fs::write(root.join("image.png"), [0u8, 1, 2]).unwrap();
        std::fs::create_dir(root.join("node_modules")).unwrap();
        std::fs::write(root.join("node_modules/lib.js"), "x\n").unwrap();
        std::fs::write(root.join(".threadaiignore"), "skip.py\n").unwrap();

        let files = collect_files(root).unwrap();
        let names: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["app.py"]);
    }

    #[test]
    fn binary_files_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("blob.js");
        std::fs::write(&p, [b'a', 0, b'b']).unwrap();
        assert!(read_text(&p).unwrap().is_none());
    }
}
