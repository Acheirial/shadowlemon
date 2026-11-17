//! Error type shared by parsing, validation, file I/O and URL handling.

use std::{io, path::PathBuf};

use thiserror::Error;

/// The result type used throughout this crate.
pub type Result<T> = std::result::Result<T, ConfigError>;

/// Errors produced by loading, validating, mutating and sharing configs.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// An I/O operation (read, write, rename, directory creation) failed.
    #[error("I/O error for '{}': {0}", path.display())]
    Io {
        /// Path the operation was acting on.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The platform configuration directory could not be determined.
    #[error("cannot determine the ShadowLemon configuration directory")]
    NoConfigDir,

    /// The input was not valid JSON, or had the wrong shape for the target type.
    #[error("invalid config JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// The input was not a valid URL.
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),

    /// The payload of a `shadowlemon://` / `shadowlemons://` URL was not base64.
    #[error("invalid base64 payload: {0}")]
    Base64(#[from] base64::DecodeError),

    /// A config value violated a validation rule.
    #[error("invalid configuration at '{path}': {message}")]
    Invalid {
        /// Dotted/indexed path to the offending value, e.g. `profiles[0].mtu`.
        path: String,
        /// Human-readable explanation.
        message: String,
    },

    /// A configuration requested a capability that is compiled out.
    #[error(
        "configuration at '{path}' requires the '{feature}' Cargo feature, which is not enabled"
    )]
    FeatureDisabled {
        /// Dotted/indexed path to the offending value.
        path: String,
        /// Name of the missing Cargo feature.
        feature: &'static str,
    },
}

impl ConfigError {
    /// Build an [`ConfigError::Invalid`] error from a path and a message.
    pub fn invalid(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Invalid {
            path: path.into(),
            message: message.into(),
        }
    }

    /// Wrap an I/O error with the path it relates to.
    pub fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
