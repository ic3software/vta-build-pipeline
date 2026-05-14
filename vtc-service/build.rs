// build.rs — builds the admin SPA before `include_dir!` reads it.
//
// The admin UI is a Vite/React/TS project under `admin-ui/`. Vite
// produces a `dist/` directory that `src/admin_ui.rs` bakes into the
// binary via `include_dir!`. To keep `cargo build` self-contained,
// build.rs invokes `npm install` + `npm run build` before src/
// compiles.
//
// Trade-off accepted: Rust devs need a working node + npm install
// to build vtc-service. This is the workspace's first npm-in-build
// dependency. Skipping the build is supported via an env var
// (`VTC_SKIP_ADMIN_UI_BUILD=1`) so CI matrices or air-gapped
// environments that ship a pre-built `dist/` can opt out.
//
// `cargo:rerun-if-changed` directives are scoped to admin-ui
// sources only, so building unrelated parts of vtc-service doesn't
// re-trigger npm.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Re-run when admin-ui source changes; leave the rest of the
    // crate alone.
    println!("cargo:rerun-if-changed=admin-ui/src");
    println!("cargo:rerun-if-changed=admin-ui/index.html");
    println!("cargo:rerun-if-changed=admin-ui/package.json");
    println!("cargo:rerun-if-changed=admin-ui/package-lock.json");
    println!("cargo:rerun-if-changed=admin-ui/vite.config.ts");
    println!("cargo:rerun-if-changed=admin-ui/tsconfig.json");
    println!("cargo:rerun-if-env-changed=VTC_SKIP_ADMIN_UI_BUILD");

    if std::env::var("VTC_SKIP_ADMIN_UI_BUILD").is_ok() {
        eprintln!(
            "build.rs: VTC_SKIP_ADMIN_UI_BUILD set, skipping admin-ui build (expecting a \
             pre-built dist/)"
        );
        ensure_dist_exists();
        return;
    }

    if std::env::var("CARGO_FEATURE_ADMIN_UI").is_err() {
        // Crate built without `admin-ui` feature — `include_dir!`
        // isn't referencing dist/, so no need to build. Still
        // make sure the directory exists as an empty stub so the
        // `include_dir!` macro doesn't error if it ever gets
        // evaluated.
        ensure_dist_exists();
        return;
    }

    build_admin_ui();
}

fn admin_ui_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("admin-ui")
}

fn dist_dir() -> PathBuf {
    admin_ui_dir().join("dist")
}

fn ensure_dist_exists() {
    let dist = dist_dir();
    if !dist.exists() {
        std::fs::create_dir_all(&dist).ok();
        // include_dir! needs at least one file present; a
        // placeholder is cheaper than failing the build.
        let placeholder = dist.join(".gitkeep");
        if !placeholder.exists() {
            let _ = std::fs::write(
                &placeholder,
                "# admin-ui dist not built — set VTC_SKIP_ADMIN_UI_BUILD=1 or rebuild the SPA\n",
            );
        }
    }
}

fn build_admin_ui() {
    let admin_ui = admin_ui_dir();

    if !admin_ui.exists() {
        panic!(
            "build.rs: admin-ui directory missing at {}",
            admin_ui.display()
        );
    }

    // npm install — idempotent; npm decides whether to do work.
    run_npm(&admin_ui, &["install", "--no-audit", "--no-fund"]);

    // npm run build — produces admin-ui/dist/.
    run_npm(&admin_ui, &["run", "build"]);

    // Sanity: dist/index.html must exist or include_dir! has
    // nothing to bake. Fail loud rather than silently shipping an
    // empty admin UI.
    let index = dist_dir().join("index.html");
    if !index.exists() {
        panic!(
            "build.rs: admin-ui build did not produce {}; check `npm run build` output",
            index.display()
        );
    }
}

fn run_npm(cwd: &Path, args: &[&str]) {
    let npm = std::env::var("VTC_NPM").unwrap_or_else(|_| "npm".to_string());
    eprintln!(
        "build.rs: running `{npm} {args}` in {cwd}",
        npm = npm,
        args = args.join(" "),
        cwd = cwd.display()
    );
    let status = Command::new(&npm)
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|e| {
            panic!(
                "build.rs: failed to spawn `{npm}`: {e}. Install Node.js (https://nodejs.org) or \
                 set VTC_SKIP_ADMIN_UI_BUILD=1 and ship a pre-built dist/."
            )
        });
    if !status.success() {
        panic!(
            "build.rs: `{npm} {}` exited with {status}. Re-run manually in admin-ui/ for full \
             output.",
            args.join(" ")
        );
    }
}
