//! Minimal Go `flag`-compatible command line parser.
//!
//! Only the forms used by the integration scripts are supported:
//! `-name=value`, `-name value`, and bare boolean flags such as `-huge`.
//! Double-dash forms are accepted as well. Parsing stops at the first
//! positional argument, just like the Go `flag` package.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct Args {
    values: HashMap<String, String>,
}

impl Args {
    /// Parse the process arguments. `bool_flags` lists options that never
    /// consume the following argument.
    pub fn parse(bool_flags: &[&str]) -> Self {
        Self::parse_from(std::env::args().skip(1), bool_flags)
    }

    pub fn parse_from<I, S>(iter: I, bool_flags: &[&str]) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let booleans: HashSet<&str> = bool_flags.iter().copied().collect();
        let mut values = HashMap::new();
        let mut iter = iter.into_iter().map(Into::into);
        while let Some(arg) = iter.next() {
            if !arg.starts_with('-') || arg == "-" {
                break;
            }
            let text = arg.trim_start_matches('-');
            if text.is_empty() {
                break;
            }
            if let Some((name, value)) = text.split_once('=') {
                values.insert(name.to_owned(), value.to_owned());
            } else if booleans.contains(text) {
                values.insert(text.to_owned(), "true".to_owned());
            } else {
                let value = iter.next().unwrap_or_default();
                values.insert(text.to_owned(), value);
            }
        }
        Self { values }
    }

    pub fn string(&self, name: &str, default: &str) -> String {
        self.values
            .get(name)
            .cloned()
            .unwrap_or_else(|| default.to_owned())
    }

    pub fn int(&self, name: &str, default: i64) -> i64 {
        match self.values.get(name) {
            None => default,
            Some(text) => text.parse::<i64>().unwrap_or_else(|_| {
                fatal(&format!("invalid value for -{name}: {text:?}"));
            }),
        }
    }

    pub fn boolean(&self, name: &str) -> bool {
        matches!(
            self.values.get(name).map(String::as_str),
            Some("true" | "1" | "yes")
        )
    }
}

/// Print an error and exit with a non-zero status, like Go's `log.Fatalf`.
pub fn fatal(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}
