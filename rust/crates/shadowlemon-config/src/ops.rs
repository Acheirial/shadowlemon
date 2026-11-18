//! File paths, loading, YAML/JSON merge (`apply`), atomic replace and `describe`.
//!
//! YAML is the recommended configuration format. JSON is still read and
//! written for compatibility (and for `.json` paths), but using it prints a
//! one-time migration hint.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Once,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

use crate::{
    error::{ConfigError, Result},
    validate::Validate,
};

/// Configuration file format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigFormat {
    /// Legacy JSON format (still supported, but not recommended).
    Json,
    /// Recommended YAML format.
    Yaml,
}

impl ConfigFormat {
    /// Format used for writes: JSON only when the path ends in `.json`.
    #[must_use]
    pub fn for_path(path: &Path) -> Self {
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            Self::Json
        } else {
            Self::Yaml
        }
    }

    /// Human-readable name of the format.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Yaml => "YAML",
        }
    }
}

/// Detect a config's format from its content, not its file name.
///
/// A leading `{` means JSON; everything else is parsed as YAML. Since JSON is
/// a subset of YAML this stays permissive for hand-edited files.
#[must_use]
pub fn detect_format(text: &str) -> ConfigFormat {
    match text.trim_start().chars().next() {
        Some('{') => ConfigFormat::Json,
        _ => ConfigFormat::Yaml,
    }
}

fn warn_json_once() {
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "note: JSON configuration is supported but not recommended; migrate to YAML (see rust/docs/config-v0.2.md)"
        );
    });
}

/// Return the per-user ShadowLemon configuration directory.
///
/// Uses [`dirs::config_dir`], which resolves to `~/.config/shadowlemon` on
/// Linux (respecting `XDG_CONFIG_HOME`).
pub fn config_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .map(|dir| dir.join("shadowlemon"))
        .ok_or(ConfigError::NoConfigDir)
}

/// Resolve a default config path, preferring YAML but honouring an existing
/// `.json` file so upgrading does not silently discard a user's configuration.
fn default_config_path(name: &str) -> Result<PathBuf> {
    let dir = config_dir()?;
    let yaml = dir.join(format!("{name}.yaml"));
    if yaml.exists() {
        return Ok(yaml);
    }
    let json = dir.join(format!("{name}.json"));
    if json.exists() {
        return Ok(json);
    }
    Ok(yaml)
}

/// Default path of the client configuration file (`client.yaml`).
pub fn client_config_path() -> Result<PathBuf> {
    default_config_path("client")
}

/// Default path of the server configuration file (`server.yaml`).
pub fn server_config_path() -> Result<PathBuf> {
    default_config_path("server")
}

/// Parse a config from text, auto-detecting YAML vs JSON.
pub fn parse<T: DeserializeOwned>(text: &str) -> Result<T> {
    let format = detect_format(text);
    if format == ConfigFormat::Json {
        warn_json_once();
    }
    match format {
        ConfigFormat::Json => serde_json::from_str(text).map_err(Into::into),
        ConfigFormat::Yaml => serde_yaml::from_str(text).map_err(Into::into),
    }
}

/// Read and fully validate a config file, auto-detecting its format.
pub fn load<T: DeserializeOwned + Validate>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path).map_err(|e| ConfigError::io(path, e))?;
    let value: T = parse(&text)?;
    value.validate()?;
    Ok(value)
}

/// Read and fully validate a JSON config file (kept for JSON-specific callers).
pub fn load_json<T: DeserializeOwned + Validate>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path).map_err(|e| ConfigError::io(path, e))?;
    let value: T = serde_json::from_str(&text)?;
    value.validate()?;
    Ok(value)
}

/// Recursively merge `patch` into `base`.
///
/// Rules from `config-v0.2.md` §9:
/// - scalars overwrite,
/// - objects recurse (keys absent from the patch are preserved),
/// - `null` removes a key,
/// - arrays replace wholesale.
pub fn merge_json(base: &mut Value, patch: &Value) {
    let (Some(base_map), Some(patch_map)) = (base.as_object_mut(), patch.as_object()) else {
        // A non-object patch is not a mergeable config patch; callers normally
        // validate the shape, but replacing wholesale is the safe fallback.
        *base = patch.clone();
        return;
    };
    for (key, patch_value) in patch_map {
        if patch_value.is_null() {
            base_map.remove(key);
        } else if let Some(existing) = base_map.get_mut(key) {
            if existing.is_object() && patch_value.is_object() {
                merge_json(existing, patch_value);
            } else {
                *existing = patch_value.clone();
            }
        } else {
            base_map.insert(key.clone(), patch_value.clone());
        }
    }
}

/// Apply a JSON merge patch to a typed config and fully validate the result.
pub fn apply_json<T>(current: &T, patch_json: &str) -> Result<T>
where
    T: Serialize + DeserializeOwned + Validate,
{
    let mut base = serde_json::to_value(current)?;
    let patch: Value = serde_json::from_str(patch_json)?;
    merge_json(&mut base, &patch);
    let merged: T = serde_json::from_value(base)?;
    merged.validate()?;
    Ok(merged)
}

/// Parse and fully validate a config from a JSON string (used by `replace`).
pub fn replace_json<T: DeserializeOwned + Validate>(json: &str) -> Result<T> {
    let value: T = serde_json::from_str(json)?;
    value.validate()?;
    Ok(value)
}

/// Serialize a config to pretty JSON (used by `describe` and URL export).
pub fn describe<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

/// Serialize a config in the requested format.
pub fn serialize<T: Serialize>(value: &T, format: ConfigFormat) -> Result<String> {
    match format {
        ConfigFormat::Json => serde_json::to_string_pretty(value).map_err(Into::into),
        ConfigFormat::Yaml => serde_yaml::to_string(value).map_err(Into::into),
    }
}

/// Apply a merge patch supplied as either YAML or JSON text.
pub fn apply_text<T>(current: &T, patch: &str) -> Result<T>
where
    T: Serialize + DeserializeOwned + Validate,
{
    let mut base = serde_json::to_value(current)?;
    let format = detect_format(patch);
    if format == ConfigFormat::Json {
        warn_json_once();
    }
    let patch_value: Value = match format {
        ConfigFormat::Json => serde_json::from_str(patch)?,
        ConfigFormat::Yaml => serde_yaml::from_str(patch)?,
    };
    merge_json(&mut base, &patch_value);
    let merged: T = serde_json::from_value(base)?;
    merged.validate()?;
    Ok(merged)
}

/// Parse and fully validate a replacement config in either YAML or JSON.
pub fn replace_text<T: DeserializeOwned + Validate>(text: &str) -> Result<T> {
    parse(text)
}

/// Write a config atomically in JSON (used by URL import).
pub fn write_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_string_pretty(value)?;
    write_bytes_atomic(path, bytes.as_bytes())
}

/// Write a config atomically, choosing the format from the path extension.
/// Paths ending in `.json` keep JSON; everything else is written as YAML.
pub fn write_auto<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serialize(value, ConfigFormat::for_path(path))?;
    write_bytes_atomic(path, bytes.as_bytes())
}

/// Write raw bytes atomically (see [`write_atomic`]).
pub fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| ConfigError::io(parent, e))?;
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp = path.with_file_name(format!(".{file_name}.{}.{nonce}.tmp", std::process::id()));

    let result = (|| -> Result<()> {
        fs::write(&temp, bytes).map_err(|e| ConfigError::io(&temp, e))?;
        fs::rename(&temp, path).map_err(|e| ConfigError::io(path, e))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Load a config file, apply a JSON merge patch, validate and write it back.
/// Returns the merged config.
pub fn apply_file<T>(path: &Path, patch_json: &str) -> Result<T>
where
    T: Default + Serialize + DeserializeOwned + Validate,
{
    // On a fresh installation there is no config file yet. Start from an empty
    // config so `apply config` works without a separate `describe` first.
    let current: T = match fs::read_to_string(path) {
        Ok(text) => {
            let parsed: T = serde_json::from_str(&text)?;
            parsed.validate()?;
            parsed
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => T::default(),
        Err(e) => return Err(ConfigError::io(path, e)),
    };
    let merged = apply_json(&current, patch_json)?;
    write_atomic(path, &merged)?;
    Ok(merged)
}

/// Fully validate a replacement config, then write it atomically. Returns the
/// validated config.
pub fn replace_file<T>(path: &Path, json: &str) -> Result<T>
where
    T: Serialize + DeserializeOwned + Validate,
{
    let value = replace_json::<T>(json)?;
    write_atomic(path, &value)?;
    Ok(value)
}

/// Read and describe a config file. If the file does not exist, an empty
/// config is written first so `describe` always has something to show.
pub fn describe_file<T>(path: &Path) -> Result<String>
where
    T: Default + Serialize + DeserializeOwned + Validate,
{
    let value: T = match fs::read_to_string(path) {
        Ok(text) => {
            let parsed: T = serde_json::from_str(&text)?;
            parsed.validate()?;
            parsed
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let empty = T::default();
            write_atomic(path, &empty)?;
            empty
        }
        Err(e) => return Err(ConfigError::io(path, e)),
    };
    describe(&value)
}

/// Apply a YAML/JSON merge patch to a config file, write it back in the
/// file's own format, and return the merged config as formatted text.
pub fn apply_file_auto<T>(path: &Path, patch: &str) -> Result<String>
where
    T: Default + Serialize + DeserializeOwned + Validate,
{
    // On a fresh installation there is no config file yet. Start from an
    // empty config so `apply config` works without a `describe` first.
    let current: T = match fs::read_to_string(path) {
        Ok(text) => {
            let parsed: T = parse(&text)?;
            parsed.validate()?;
            parsed
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => T::default(),
        Err(e) => return Err(ConfigError::io(path, e)),
    };
    let merged = apply_text(&current, patch)?;
    write_auto(path, &merged)?;
    serialize(&merged, ConfigFormat::for_path(path))
}

/// Replace a config from YAML/JSON text, write it back, and return the result
/// as formatted text.
pub fn replace_file_auto<T>(path: &Path, text: &str) -> Result<String>
where
    T: Serialize + DeserializeOwned + Validate,
{
    let value = replace_text::<T>(text)?;
    write_auto(path, &value)?;
    serialize(&value, ConfigFormat::for_path(path))
}

/// Read and describe a config file in its own format, creating an empty YAML
/// config first when the file does not exist.
pub fn describe_file_auto<T>(path: &Path) -> Result<String>
where
    T: Default + Serialize + DeserializeOwned + Validate,
{
    let value: T = match fs::read_to_string(path) {
        Ok(text) => {
            let parsed: T = parse(&text)?;
            parsed.validate()?;
            parsed
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let empty = T::default();
            write_auto(path, &empty)?;
            empty
        }
        Err(e) => return Err(ConfigError::io(path, e)),
    };
    serialize(&value, ConfigFormat::for_path(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_scalars_objects_null_and_arrays() {
        let mut base = json!({
            "a": 1,
            "b": { "x": 1, "y": 2 },
            "c": [1, 2, 3],
            "d": "keep"
        });
        merge_json(
            &mut base,
            &json!({
                "a": 9,
                "b": { "x": 7 },
                "c": [42],
                "d": null,
                "e": "new"
            }),
        );
        assert_eq!(
            base,
            json!({
                "a": 9,
                "b": { "x": 7, "y": 2 },
                "c": [42],
                "e": "new"
            })
        );
    }

    #[test]
    fn detect_format_by_content() {
        assert_eq!(detect_format("  {\"a\":1}"), ConfigFormat::Json);
        assert_eq!(detect_format("---\na: 1\n"), ConfigFormat::Yaml);
        assert_eq!(detect_format("socks5Port: 1080\n"), ConfigFormat::Yaml);
    }

    #[test]
    fn yaml_round_trip_apply_and_replace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.yaml");

        // A YAML apply patch on a missing file creates a YAML config.
        let patch = "socks5Port: 2080\nloggingLevel: INFO\n";
        let described = apply_file_auto::<crate::ClientConfig>(&path, patch).unwrap();
        assert!(described.contains("socks5Port: 2080"));
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(detect_format(&text), ConfigFormat::Yaml);
        assert!(text.contains("socks5Port: 2080"));

        // A YAML replace patch replaces the whole config.
        let replacement = "socks5Port: 3090\n";
        let described = replace_file_auto::<crate::ClientConfig>(&path, replacement).unwrap();
        assert!(described.contains("socks5Port: 3090"));
        let reloaded: crate::ClientConfig = load(&path).unwrap();
        assert_eq!(reloaded.socks5_port, Some(3090));

        // describe reads YAML back and reports it in YAML.
        let described = describe_file_auto::<crate::ClientConfig>(&path).unwrap();
        assert!(serde_yaml::from_str::<serde_yaml::Value>(&described).is_ok());
    }

    #[test]
    fn json_config_still_loads_and_keeps_its_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        let original = include_str!("../../../../configs/examples/client_config.json");
        fs::write(&path, original).unwrap();

        let loaded: crate::ClientConfig = load(&path).unwrap();
        assert!(!loaded.profiles.is_empty());

        let described =
            apply_file_auto::<crate::ClientConfig>(&path, "{\"socks5Port\":2080}").unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&described).is_ok());
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(detect_format(&text), ConfigFormat::Json);
    }
}
