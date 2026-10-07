//! Repo tasks. `cargo xtask check-deps` enforces the architecture §3.1 dependency rules,
//! which cargo-deny cannot express (it bans crates, not per-crate dependency closures).
//! `cargo xtask oscal` regenerates oscal/component-definition.json from compliance/controls.toml.

mod oscal;

use std::collections::{BTreeMap, BTreeSet};
use std::process::{Command, ExitCode};

/// Pure crates and the only normal (non-dev) dependencies their whole closure may contain.
const PURE: &[(&str, &[&str])] = &[("markings", &[]), ("policy", &["markings"])];
/// The only crates allowed to depend directly on `openmls*`.
const OPENMLS_USERS: &[&str] = &["identity", "client", "ds"];
const BINARIES: &[&str] = &["ds", "custodian", "garble-cli", "garble-desktop"];
/// `tlog` hashes opaque leaves; it must not know GARBLE's types.
const TLOG_FORBIDDEN: &[&str] = &["markings", "policy", "proto", "identity", "client"];

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("check-deps") => match check_deps() {
            Ok(()) => {
                println!("check-deps: ok");
                ExitCode::SUCCESS
            }
            Err(errors) => {
                errors.iter().for_each(|e| eprintln!("check-deps: {e}"));
                ExitCode::FAILURE
            }
        },
        Some("oscal") => match oscal::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(errors) => {
                errors.iter().for_each(|e| eprintln!("oscal: {e}"));
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("usage: cargo xtask check-deps | oscal");
            ExitCode::FAILURE
        }
    }
}

fn check_deps() -> Result<(), Vec<String>> {
    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["metadata", "--format-version", "1", "--locked"])
        .output()
        .map_err(|e| vec![format!("cargo metadata: {e}")])?;
    if !out.status.success() {
        return Err(vec![String::from_utf8_lossy(&out.stderr).into_owned()]);
    }
    let meta: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| vec![format!("metadata json: {e}")])?;

    let name_of: BTreeMap<&str, &str> = meta["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| Some((p["id"].as_str()?, p["name"].as_str()?)))
        .collect();
    // Normal-dependency edges by package name (dev and build deps excluded).
    let mut edges: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for node in meta["resolve"]["nodes"].as_array().into_iter().flatten() {
        let Some(from) = node["id"].as_str().and_then(|id| name_of.get(id)) else {
            continue;
        };
        let deps = edges.entry(from).or_default();
        for dep in node["deps"].as_array().into_iter().flatten() {
            let normal = dep["dep_kinds"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|k| k["kind"].is_null());
            if let (true, Some(to)) = (normal, dep["pkg"].as_str().and_then(|id| name_of.get(id))) {
                deps.insert(*to);
            }
        }
    }

    let members: BTreeSet<&str> = meta["workspace_members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|id| name_of.get(id.as_str()?).copied())
        .collect();

    let mut errors = Vec::new();
    for (krate, allowed) in PURE {
        let mut seen = BTreeSet::new();
        let mut stack = vec![*krate];
        while let Some(c) = stack.pop() {
            for d in edges.get(c).into_iter().flatten() {
                if seen.insert(*d) {
                    stack.push(d);
                }
            }
        }
        for d in seen.iter().filter(|d| !allowed.contains(d)) {
            errors.push(format!("{krate} is pure (§3.1) but depends on {d}"));
        }
    }
    for (from, deps) in edges.iter().filter(|(from, _)| members.contains(*from)) {
        for to in deps {
            if to.starts_with("openmls") && !OPENMLS_USERS.contains(from) {
                errors.push(format!(
                    "{from} depends on {to}; only {OPENMLS_USERS:?} may"
                ));
            }
            if BINARIES.contains(to) {
                errors.push(format!("{from} depends on binary crate {to}"));
            }
            if *from == "tlog" && TLOG_FORBIDDEN.contains(to) {
                errors.push(format!(
                    "tlog depends on {to}; it must not know GARBLE types"
                ));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
