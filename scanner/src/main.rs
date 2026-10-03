use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use threadai::report;
use threadai::rules::{self, Rule, Severity};

/// Offline security pattern scanner. Reads your code, never runs or uploads it.
///
/// Exit codes: 0 = no findings, 1 = findings at or above --min-severity, 2 = error.
#[derive(Parser)]
#[command(name = "threadai", version, about, long_about)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Disable colored output (also honours the NO_COLOR env var)
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a file or directory for vulnerability patterns
    Scan {
        /// File or directory to scan
        #[arg(default_value = ".")]
        path: PathBuf,

        #[arg(short, long, value_enum, default_value_t = ScanFormat::Text)]
        format: ScanFormat,

        /// Only report (and fail on) findings at or above this severity
        #[arg(short = 's', long, value_enum, default_value_t = Severity::Low)]
        min_severity: Severity,

        /// Load rules from this directory of .toml files instead of the built-in set
        #[arg(long)]
        rules: Option<PathBuf>,

        /// Write the report to a file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List the rules the scanner checks
    Rules {
        #[arg(short, long, value_enum, default_value_t = RulesFormat::Text)]
        format: RulesFormat,

        /// Load rules from this directory instead of the built-in set
        #[arg(long)]
        rules: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ScanFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum RulesFormat {
    Text,
    Json,
    Markdown,
}

fn load_rules(dir: &Option<PathBuf>) -> Result<Vec<Rule>> {
    match dir {
        Some(d) => rules::load_dir(d),
        None => rules::load_builtin(),
    }
}

/// Returns whether any findings were reported, so `main` can pick the exit code.
fn run(cli: Cli) -> Result<bool> {
    match cli.command {
        Command::Scan {
            path,
            format,
            min_severity,
            rules,
            output,
        } => {
            if output.is_some() {
                colored::control::set_override(false);
            }
            let rules = load_rules(&rules)?;
            let result = threadai::scan_path(&path, &rules, min_severity)?;
            let text = match format {
                ScanFormat::Text => report::to_text(&result),
                ScanFormat::Json => report::to_json(&result),
                ScanFormat::Sarif => report::to_sarif(&result, &rules),
            };
            match output {
                Some(file) => {
                    std::fs::write(&file, text)
                        .with_context(|| format!("cannot write {}", file.display()))?;
                    eprintln!(
                        "Wrote {} findings to {}",
                        result.findings.len(),
                        file.display()
                    );
                }
                None => print!("{text}"),
            }
            Ok(!result.findings.is_empty())
        }
        Command::Rules { format, rules } => {
            let rules = load_rules(&rules)?;
            let text = match format {
                RulesFormat::Text => report::rules_to_text(&rules),
                RulesFormat::Json => report::rules_to_json(&rules),
                RulesFormat::Markdown => report::rules_to_markdown(&rules),
            };
            print!("{text}");
            Ok(false)
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.no_color || !std::io::stdout().is_terminal() {
        colored::control::set_override(false);
    }
    #[cfg(windows)]
    let _ = colored::control::set_virtual_terminal(true);

    match run(cli) {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(1),
        Err(e) => {
            eprintln!("threadai: error: {e:#}");
            ExitCode::from(2)
        }
    }
}
