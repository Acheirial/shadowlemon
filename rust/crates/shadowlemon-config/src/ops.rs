//! File paths, loading, JSON merge (`apply`), atomic replace and `describe`.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

use crate::{
    error::{ConfigError, Result},
    validate::Validate,
};

/// Return the per-user ShadowLemon configuration directory.
///
/// Uses [`dirs::config_dir`], which resolves to:
/// - Linux/BSD: `~/.config/shadowlemon` (respecting `XDG_CONFIG_HOME`)
/// - macOS: `~/Library/Application Support/shadowlemon`
/// - Windows: `%AppData%\shadowlemon`
pub fn config_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .map(|dir| dir.join("shadowlemon"))
        .ok_or(ConfigError::NoConfigDir)
}

/// Default path of the client configuration file.
///
/// The Rust rewrite stores JSON, so this uses `client.json` rather than the
/// Go version's protobuf `client.conf.pb`.
pub fn client_config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("client.json"))
}

/// Default path of the server configuration file.
pub fn server_config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("server.json"))
}

/// Read and fully validate a JSON config file.
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

/// Serialize a config to pretty JSON (used by `describe`).
pub fn describe<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

/// Write a config atomically: encode to pretty JSON, write a temporary file in
/// the same directory, then rename it over the target.
pub fn write_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_string_pretty(value)?;
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
}
