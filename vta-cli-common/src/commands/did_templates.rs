//! Offline DID template commands.
//!
//! Phase 1 surface: no network, no VTA client. Operators author templates
//! locally and lint them before uploading, or scaffold a starter by forking
//! a built-in. Phase 2 adds the `list`, `show`, `create`, `update`, `delete`
//! commands that hit the VTA.

use std::path::PathBuf;

use vta_sdk::did_templates::{BUILTIN_NAMES, DidTemplate, load_embedded};

use crate::render::{CYAN, DIM, GREEN, RED, RESET, YELLOW};

/// `pnm did-templates validate <file>` / `cnm did-templates validate <file>`.
///
/// Loads a template JSON file, runs the structural + semantic validator, and
/// reports pass/fail. Never touches the network.
pub fn cmd_validate(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    match DidTemplate::load_file(&path) {
        Ok(tpl) => {
            println!(
                "{GREEN}\u{2713}{RESET} Template {CYAN}'{}'{RESET} ({DIM}{}{RESET}) is valid.",
                tpl.name, tpl.kind
            );
            println!("  schemaVersion: {}", tpl.schema_version);
            if let Some(desc) = &tpl.description {
                println!("  description:   {desc}");
            }
            if !tpl.methods.is_empty() {
                println!("  methods:       {}", tpl.methods.join(", "));
            }
            if !tpl.required_vars.is_empty() {
                println!("  requiredVars:  {}", tpl.required_vars.join(", "));
            }
            if !tpl.optional_vars.is_empty() {
                let names: Vec<&str> = tpl.optional_vars.keys().map(String::as_str).collect();
                println!("  optionalVars:  {}", names.join(", "));
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("{RED}\u{2717}{RESET} Template validation failed:");
            eprintln!("  {e}");
            Err(format!("invalid template at {}", path.display()).into())
        }
    }
}

/// `pnm did-templates init <kind>` / `cnm did-templates init <kind>`.
///
/// Emit a starter template on stdout by forking an embedded built-in. The
/// operator can redirect to a file, edit, and upload. `kind` is a built-in
/// name (`didcomm-mediator`, `webvh-hosting-server`).
pub fn cmd_init(kind: String) -> Result<(), Box<dyn std::error::Error>> {
    // Accept either the exact builtin name or a short alias.
    let builtin_name = match kind.as_str() {
        "mediator" => "didcomm-mediator",
        "webvh-hosting" | "hosting" => "webvh-hosting-server",
        other if BUILTIN_NAMES.contains(&other) => other,
        other => {
            eprintln!(
                "{RED}\u{2717}{RESET} Unknown builtin kind '{other}'. Available: {}",
                BUILTIN_NAMES.join(", ")
            );
            return Err("unknown builtin".into());
        }
    };

    // Load the builtin, re-serialize as pretty-printed JSON for editing.
    let tpl = load_embedded(builtin_name)?;
    let pretty = serde_json::to_string_pretty(&tpl)?;
    println!("{pretty}");

    // Hint goes to stderr so stdout stays redirect-friendly.
    eprintln!();
    eprintln!(
        "{YELLOW}Tip:{RESET} redirect to a file and edit the {DIM}name{RESET}, {DIM}description{RESET},"
    );
    eprintln!("     and any placeholder values before uploading. For example:");
    eprintln!("       pnm did-templates init {kind} > my-{builtin_name}.json");
    Ok(())
}

/// `pnm did-templates list-builtins`.
///
/// Show the names of every built-in template shipped with this SDK.
pub fn cmd_list_builtins() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{CYAN}Built-in templates{RESET} ({} total):\n",
        BUILTIN_NAMES.len()
    );
    for name in BUILTIN_NAMES {
        let tpl = load_embedded(name)?;
        println!(
            "  {GREEN}\u{25b8}{RESET} {CYAN}{name}{RESET} ({DIM}{}{RESET})",
            tpl.kind
        );
        if let Some(desc) = &tpl.description {
            println!("    {desc}");
        }
        if !tpl.required_vars.is_empty() {
            println!(
                "    {DIM}requiredVars: {}{RESET}",
                tpl.required_vars.join(", ")
            );
        }
    }
    Ok(())
}
