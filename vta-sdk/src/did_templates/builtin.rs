//! Built-in templates embedded at SDK compile time.
//!
//! Ship with the crate, always available, can't be tampered with. Operators
//! who want a customized shape fork a built-in to a stored (global or
//! context) template via the CLI's `init` subcommand and edit the JSON.

use super::{DidTemplate, TemplateError};

/// Names of every built-in template, in alphabetical order. Surfaced in
/// `BuiltinNotFound` errors so callers see what's available.
pub const BUILTIN_NAMES: &[&str] = &[
    "didcomm-mediator",
    "vta-admin",
    "webvh-hosting-server",
    "webvh-service",
];

const DIDCOMM_MEDIATOR: &str = include_str!("../../templates/didcomm-mediator.json");
const VTA_ADMIN: &str = include_str!("../../templates/vta-admin.json");
const WEBVH_HOSTING_SERVER: &str = include_str!("../../templates/webvh-hosting-server.json");
const WEBVH_SERVICE: &str = include_str!("../../templates/webvh-service.json");

/// Load a built-in template by name. Returns [`TemplateError::BuiltinNotFound`]
/// for any name not in [`BUILTIN_NAMES`].
pub fn load_embedded(name: &str) -> Result<DidTemplate, TemplateError> {
    let raw = match name {
        "didcomm-mediator" => DIDCOMM_MEDIATOR,
        "vta-admin" => VTA_ADMIN,
        "webvh-hosting-server" => WEBVH_HOSTING_SERVER,
        "webvh-service" => WEBVH_SERVICE,
        _ => return Err(TemplateError::BuiltinNotFound(name.to_string())),
    };
    let value: serde_json::Value = serde_json::from_str(raw)?;
    DidTemplate::from_json(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_parses_and_validates() {
        for name in BUILTIN_NAMES {
            let tpl = load_embedded(name)
                .unwrap_or_else(|e| panic!("builtin '{name}' failed to load: {e}"));
            assert_eq!(tpl.name, *name, "builtin name field must match lookup key");
        }
    }

    #[test]
    fn unknown_builtin_errors() {
        let err = load_embedded("does-not-exist").unwrap_err();
        assert!(matches!(err, TemplateError::BuiltinNotFound(_)));
    }
}
