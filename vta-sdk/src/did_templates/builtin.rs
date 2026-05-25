//! Built-in templates embedded at SDK compile time.
//!
//! Ship with the crate, always available, can't be tampered with. Operators
//! who want a customized shape fork a built-in to a stored (global or
//! context) template via the CLI's `init` subcommand and edit the JSON.

use super::{DidTemplate, TemplateError};

/// Names of every built-in template, in alphabetical order. Surfaced in
/// `BuiltinNotFound` errors so callers see what's available.
pub const BUILTIN_NAMES: &[&str] = &[
    "did-hosting-control",
    "did-hosting-daemon",
    "did-hosting-server",
    "didcomm-mediator",
    "vta-admin",
    "vtc-host",
];

/// Legacy template-name aliases retained for one release after the
/// `webvh-*` → `did-hosting-*` rename. Each entry maps an old name to
/// its canonical replacement; [`load_embedded`] silently resolves an
/// alias to the renamed template. Removed in the next minor release
/// — update operator configs to use the canonical names.
const LEGACY_ALIASES: &[(&str, &str)] = &[
    ("webvh-control", "did-hosting-control"),
    ("webvh-daemon", "did-hosting-daemon"),
    ("webvh-server", "did-hosting-server"),
];

const DIDCOMM_MEDIATOR: &str = include_str!("../../templates/didcomm-mediator.json");
const VTA_ADMIN: &str = include_str!("../../templates/vta-admin.json");
const VTC_HOST: &str = include_str!("../../templates/vtc-host.json");
const DID_HOSTING_CONTROL: &str = include_str!("../../templates/did-hosting-control.json");
const DID_HOSTING_DAEMON: &str = include_str!("../../templates/did-hosting-daemon.json");
const DID_HOSTING_SERVER: &str = include_str!("../../templates/did-hosting-server.json");

/// Resolve a legacy template-name alias to its canonical replacement.
/// Pure lookup — no I/O, no logging. Returns the input unchanged when
/// it isn't an alias.
fn resolve_alias(name: &str) -> &str {
    for (old, new) in LEGACY_ALIASES {
        if name == *old {
            return new;
        }
    }
    name
}

/// Load a built-in template by name. Returns [`TemplateError::BuiltinNotFound`]
/// for any name not in [`BUILTIN_NAMES`]. Legacy `webvh-*` aliases are
/// silently resolved to their `did-hosting-*` canonical names for the
/// deprecation window — the returned `DidTemplate.name` is always the
/// canonical name.
pub fn load_embedded(name: &str) -> Result<DidTemplate, TemplateError> {
    let canonical = resolve_alias(name);
    let raw = match canonical {
        "didcomm-mediator" => DIDCOMM_MEDIATOR,
        "vta-admin" => VTA_ADMIN,
        "vtc-host" => VTC_HOST,
        "did-hosting-control" => DID_HOSTING_CONTROL,
        "did-hosting-daemon" => DID_HOSTING_DAEMON,
        "did-hosting-server" => DID_HOSTING_SERVER,
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

    #[test]
    fn legacy_webvh_aliases_resolve_to_did_hosting_canonical() {
        // Operators on the previous template names keep working for one
        // release. The returned template carries the canonical name —
        // any caller round-tripping `tpl.name` writes back the new name.
        for (old, new) in [
            ("webvh-control", "did-hosting-control"),
            ("webvh-daemon", "did-hosting-daemon"),
            ("webvh-server", "did-hosting-server"),
        ] {
            let tpl = load_embedded(old)
                .unwrap_or_else(|e| panic!("legacy alias '{old}' failed to resolve: {e}"));
            assert_eq!(
                tpl.name, new,
                "legacy alias '{old}' must surface the canonical name '{new}'"
            );
        }
    }
}
