//! DID template commands — offline (Phase 1) and online (Phase 2 global scope).
//!
//! Offline: validate a file, init a starter from an embedded builtin, list
//! builtins. Online: list/show/create/update/delete/render against the VTA.

use std::collections::HashMap;
use std::path::PathBuf;

use vta_sdk::did_templates::{BUILTIN_NAMES, DidTemplate, load_embedded};
use vta_sdk::prelude::*;

use crate::duration::format_local_time;
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

// ── Online (Phase 2: global scope against the VTA) ──────────────────

/// `pnm did-templates list` — show stored global templates on the VTA.
///
/// Built-ins are not merged in here — use `list-builtins` for those. Keeping
/// the two listings separate makes it obvious whether a template is
/// server-managed (listed here) or forked from a built-in.
pub async fn cmd_list(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let records = client.list_did_templates().await?;
    if records.is_empty() {
        println!("No DID templates stored on the VTA.");
        println!("  {DIM}Scaffold one with{RESET} `pnm did-templates init <kind> > tpl.json`,");
        println!("  {DIM}then{RESET} `pnm did-templates create --file tpl.json`.");
        return Ok(());
    }

    println!(
        "{CYAN}Stored DID templates{RESET} ({} total):\n",
        records.len()
    );
    for r in &records {
        println!(
            "  {GREEN}\u{25b8}{RESET} {CYAN}{}{RESET} ({DIM}{}{RESET})",
            r.template.name, r.template.kind
        );
        if let Some(desc) = &r.template.description {
            println!("    {desc}");
        }
        if !r.template.required_vars.is_empty() {
            println!(
                "    {DIM}requiredVars: {}{RESET}",
                r.template.required_vars.join(", ")
            );
        }
        println!(
            "    {DIM}created: {} by {}{RESET}",
            format_local_time(r.created_at),
            r.created_by
        );
    }
    Ok(())
}

/// `pnm did-templates show <name> [--rendered --var K=V ...]` — fetch one template.
///
/// Without `--rendered`, prints the raw record. With `--rendered`, fetches the
/// template then renders it server-side with caller-supplied `--var` pairs
/// (useful for previewing what the eventual DID document will look like).
pub async fn cmd_show(
    client: &VtaClient,
    name: &str,
    rendered: bool,
    vars: Vec<(String, String)>,
) -> Result<(), Box<dyn std::error::Error>> {
    if rendered {
        let mut vars_map: HashMap<String, serde_json::Value> = HashMap::new();
        for (k, v) in vars {
            vars_map.insert(k, serde_json::Value::String(v));
        }
        // Ambient reserved vars not supplied by the server in Phase 2 (DID,
        // SIGNING_KEY_MB, KA_KEY_MB, CONTEXT_ID, CONTEXT_DID) must come from
        // --var so the preview doesn't fail. Phase 4 wires these through a
        // create flow; preview is a best-effort tool for authors.
        let doc = client.render_did_template(name, vars_map).await?;
        println!("{}", serde_json::to_string_pretty(&doc)?);
        return Ok(());
    }

    let r = client.get_did_template(name).await?;
    let pretty = serde_json::to_string_pretty(&r)?;
    println!("{pretty}");
    Ok(())
}

/// `pnm did-templates create --file <path>` — upload a new global template.
///
/// The file is validated locally before upload, so authoring errors fail
/// immediately without burning a round-trip to a super admin ACL check.
pub async fn cmd_create(
    client: &VtaClient,
    file: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let tpl = DidTemplate::load_file(&file)
        .map_err(|e| format!("template at {} is invalid: {e}", file.display()))?;
    let record = client.create_did_template(tpl).await?;
    println!(
        "{GREEN}\u{2713}{RESET} Created {CYAN}'{}'{RESET} ({DIM}{}{RESET}) on the VTA.",
        record.template.name, record.template.kind
    );
    Ok(())
}

/// `pnm did-templates update <name> --file <path>` — replace a stored template.
pub async fn cmd_update(
    client: &VtaClient,
    name: &str,
    file: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let tpl = DidTemplate::load_file(&file)
        .map_err(|e| format!("template at {} is invalid: {e}", file.display()))?;
    if tpl.name != name {
        return Err(format!(
            "file's template name '{}' does not match --name argument '{}'",
            tpl.name, name
        )
        .into());
    }
    let record = client.update_did_template(name, tpl).await?;
    println!(
        "{GREEN}\u{2713}{RESET} Updated {CYAN}'{}'{RESET} on the VTA.",
        record.template.name
    );
    Ok(())
}

/// `pnm did-templates delete <name>` — remove a stored template.
pub async fn cmd_delete(client: &VtaClient, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    client.delete_did_template(name).await?;
    println!("{GREEN}\u{2713}{RESET} Deleted {CYAN}'{name}'{RESET} on the VTA.");
    Ok(())
}

// ── Offline (Phase 1 helpers) ───────────────────────────────────────

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
