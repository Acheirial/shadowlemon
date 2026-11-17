//! Client and server configuration for ShadowLemon V0.2.
//!
//! This crate owns the serde schema for the JSON files under
//! `configs/examples/`, the [`Validate`] rules from `rust/docs/config-v0.2.md`
//! §8, the JSON `apply` / `replace` / `describe` operations, and the two URL
//! formats from §10. Field names and shapes are intentionally identical to the
//! Go V0.1 protobuf JSON so existing configs load unchanged.
//!
//! # Unknown fields
//!
//! Unrecognized JSON fields are ignored (the crate does **not** use
//! `deny_unknown_fields`). This lets older configs be loaded smoothly; fields
//! deleted in V0.2 (`rpcPort`, `quotas`, `allowLocalDestination`, ...) are
//! simply dropped when the config is re-serialized.
//!
//! # Determinism
//!
//! `DNS::hosts` is a `BTreeMap`, and struct field order is fixed, so
//! serialization is stable. That makes the JSON bytes suitable as the
//! deterministic binary payload of `shadowlemon://` URLs.

#![forbid(unsafe_code)]

mod enums;
mod error;
mod ops;
mod schema;
mod url;
mod validate;

pub use enums::{
    config_suite_to_wire, mask_rotation_to_wire, CipherSuite, DualStack, EgressAction,
    HandshakeMode, KnownEnum, LoggingLevel, LowEntropyMaskRotation, LowEntropyMode,
    MultiplexingLevel, NonceType, ProxyProtocol, TransportProtocol,
};
pub use error::{ConfigError, Result};
pub use ops::{
    apply_file, apply_json, client_config_path, config_dir, describe, describe_file, load_json,
    merge_json, replace_file, replace_json, server_config_path, write_atomic, write_bytes_atomic,
};
pub use schema::{
    is_valid_port, parse_port_range, Auth, ClientConfig, ClientDialer, ClientProfile, Egress,
    EgressProxy, EgressRule, LowEntropyPattern, MultiplexingConfig, NoncePattern, PaddingPattern,
    PortBinding, ServerAdvancedSettings, ServerConfig, ServerEndpoint, TCPFragment, TrafficPattern,
    User, DNS,
};
pub use url::{
    export_full_url, export_simple_urls, import_full_url, import_simple_url, import_url,
};
pub use validate::Validate;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn examples_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../configs/examples")
    }

    #[test]
    fn loads_every_example_config() {
        let dir = examples_dir();
        let mut count = 0;
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            let json: serde_json::Value = serde_json::from_str(&text).unwrap();
            let object = json.as_object().unwrap();
            if object.contains_key("profiles")
                || object.contains_key("activeProfile")
                || object.contains_key("socks5Port")
            {
                let config: ClientConfig = load_json(&path).unwrap();
                assert!(!config.profiles.is_empty(), "{}", path.display());
            } else {
                let config: ServerConfig = load_json(&path).unwrap();
                assert!(!config.port_bindings.is_empty(), "{}", path.display());
            }
            count += 1;
        }
        assert!(count >= 6, "expected all example configs, found {count}");
    }

    #[test]
    fn defaults_match_examples() {
        let cfg = ClientConfig::default();
        assert!(cfg.profiles.is_empty());
        assert_eq!(cfg.socks5_port, Some(1080));
        assert_eq!(ClientProfile::default().mtu, Some(1400));
        let server = ServerConfig::default();
        assert_eq!(server.logging_level, LoggingLevel::Default);
        assert_eq!(server.mtu, Some(1400));
        assert!(ServerAdvancedSettings::default().user_hint_is_mandatory);
        // The example L3 MTU and socks5 port are the documented defaults.
        let example: ClientConfig = serde_json::from_str(include_str!(
            "../../../../configs/examples/client_config.json"
        ))
        .unwrap();
        assert_eq!(example.profiles[0].mtu, Some(1400));
        assert_eq!(example.socks5_port, Some(1080));
    }

    #[test]
    fn apply_patch_then_replace_and_describe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        let original = include_str!("../../../../configs/examples/client_config.json").to_owned();
        write_bytes_atomic(&path, original.as_bytes()).unwrap();

        // Scalar overwrite plus deletion of a key.
        let merged: ClientConfig = apply_file(
            &path,
            r#"{"socks5Port":2080,"loggingLevel":"DEBUG","activeProfile":null}"#,
        )
        .unwrap();
        assert_eq!(merged.socks5_port, Some(2080));
        assert_eq!(merged.logging_level, LoggingLevel::Debug);
        assert_eq!(merged.active_profile, None);

        // Arrays are replaced wholesale; profiles must be complete.
        let with_auth: ClientConfig = apply_file(
            &path,
            r#"{"socks5Authentication":[{"user":"u","password":"p"}]}"#,
        )
        .unwrap();
        assert_eq!(with_auth.socks5_authentication.len(), 1);

        // A failing patch must not corrupt the on-disk config.
        assert!(apply_file::<ClientConfig>(&path, r#"{"socks5Port":70000}"#).is_err());
        let reloaded: ClientConfig = load_json(&path).unwrap();
        assert_eq!(reloaded, with_auth);

        let server_json = include_str!("../../../../configs/examples/server_config.json");
        let replaced: ServerConfig = replace_file(&path, server_json).unwrap();
        assert_eq!(replaced.mtu, Some(1400));
        let reloaded_server: ServerConfig = load_json(&path).unwrap();
        assert_eq!(reloaded_server, replaced);

        let described = describe_file::<ServerConfig>(&path).unwrap();
        let described_json: serde_json::Value = serde_json::from_str(&described).unwrap();
        assert!(described_json.get("portBindings").is_some());
    }

    #[test]
    fn describe_creates_empty_config_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let described = describe_file::<ClientConfig>(&path).unwrap();
        assert_eq!(described, describe(&ClientConfig::default()).unwrap());
        assert!(path.exists());
        let loaded: ClientConfig = load_json(&path).unwrap();
        assert!(loaded.profiles.is_empty());
    }

    #[test]
    fn url_round_trips_from_example() {
        let cfg: ClientConfig = serde_json::from_str(include_str!(
            "../../../../configs/examples/client_config.json"
        ))
        .unwrap();
        let full = export_full_url(&cfg).unwrap();
        assert_eq!(import_full_url(&full).unwrap(), cfg);

        let simple = export_simple_urls(&cfg).unwrap();
        assert_eq!(simple.len(), 1);
        let imported = import_url(&simple[0]).unwrap();
        assert_eq!(
            imported.profiles[0].profile_name,
            cfg.profiles[0].profile_name
        );
        assert_eq!(
            imported.profiles[0].servers[0].ip_address,
            cfg.profiles[0].servers[0].ip_address
        );
    }

    #[test]
    fn cipher_suite_wire_mapping() {
        assert_eq!(config_suite_to_wire(CipherSuite::Unspecified), None);
        assert_eq!(
            config_suite_to_wire(CipherSuite::XChaCha20Poly1305),
            Some(0)
        );
        assert_eq!(config_suite_to_wire(CipherSuite::Aes256Gcm), Some(1));
        assert_eq!(config_suite_to_wire(CipherSuite::Aes128Gcm), Some(2));
        assert_eq!(
            mask_rotation_to_wire(LowEntropyMaskRotation::RotateLeft3),
            Some(61)
        );
    }
}
