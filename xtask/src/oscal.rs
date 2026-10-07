//! `cargo xtask oscal`: compliance/controls.toml -> oscal/component-definition.json
//! (architecture §9.1). Every path, symbol and test the TOML names has to exist, so a
//! rename that orphans a control fails here instead of at assessment.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::process::Command;

use serde_json::{Value, json};
use toml::{Table, Value as Toml};
use uuid::Uuid;

const SOURCE: &str = "compliance/controls.toml";
const OUT: &str = "oscal/component-definition.json";
const NS: &str = "https://garble.invalid/ns/oscal";

struct Row<'a> {
    control: &'a str,
    component: &'a str,
    responsibility: &'a str,
    statement: &'a str,
    code: Vec<&'a str>,
    tests: Vec<&'a str>,
}

pub fn run() -> Result<(), Vec<String>> {
    let text = fs::read_to_string(SOURCE).map_err(|e| vec![format!("{SOURCE}: {e}")])?;
    let doc: Table = text.parse().map_err(|e| vec![format!("{SOURCE}: {e}")])?;
    let rows = rows(&doc)?;
    let mut errors = check_rows(&doc, &rows);
    errors.extend(check_code(&rows));
    errors.extend(check_tests(&rows));
    if !errors.is_empty() {
        return Err(errors);
    }
    let out = render(&doc, &rows)?;
    fs::create_dir_all("oscal").map_err(|e| vec![format!("oscal/: {e}")])?;
    fs::write(OUT, out).map_err(|e| vec![format!("{OUT}: {e}")])?;
    println!("oscal: {} requirements -> {OUT}", rows.len());
    Ok(())
}

fn str_of<'a>(t: &'a Table, key: &str) -> Result<&'a str, String> {
    t.get(key)
        .and_then(Toml::as_str)
        .ok_or_else(|| format!("{SOURCE}: `{key}` missing or not a string"))
}

fn strs<'a>(t: &'a Table, key: &str) -> Result<Vec<&'a str>, String> {
    t.get(key)
        .and_then(Toml::as_array)
        .ok_or_else(|| format!("{SOURCE}: `{key}` missing or not a list"))?
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| format!("{SOURCE}: `{key}` holds a non-string"))
        })
        .collect()
}

fn rows(doc: &Table) -> Result<Vec<Row<'_>>, Vec<String>> {
    let list = doc
        .get("row")
        .and_then(Toml::as_array)
        .ok_or_else(|| vec![format!("{SOURCE}: no [[row]] entries")])?;
    let mut errors = Vec::new();
    let mut rows = Vec::new();
    for (i, v) in list.iter().enumerate() {
        let Some(t) = v.as_table() else {
            errors.push(format!("{SOURCE}: row {i} isn't a table"));
            continue;
        };
        let row = (|| {
            Ok::<_, String>(Row {
                control: str_of(t, "control")?,
                component: str_of(t, "component")?,
                responsibility: str_of(t, "responsibility")?,
                statement: str_of(t, "statement")?,
                code: strs(t, "code")?,
                tests: strs(t, "tests")?,
            })
        })();
        match row {
            Ok(r) => rows.push(r),
            Err(e) => errors.push(format!("row {i}: {e}")),
        }
    }
    if errors.is_empty() {
        Ok(rows)
    } else {
        Err(errors)
    }
}

fn check_rows(doc: &Table, rows: &[Row]) -> Vec<String> {
    let components = doc.get("components").and_then(Toml::as_table);
    let mut seen = BTreeSet::new();
    let mut errors = Vec::new();
    for r in rows {
        let at = format!("{} / {}", r.component, r.control);
        if components.is_none_or(|c| !c.contains_key(r.component)) {
            errors.push(format!("{at}: no [components.{}]", r.component));
        }
        if !seen.insert((r.component, r.control)) {
            errors.push(format!("{at}: more than one row"));
        }
        if !["provided", "inherited", "hybrid"].contains(&r.responsibility) {
            errors.push(format!("{at}: responsibility `{}`", r.responsibility));
        }
        if r.code.is_empty() || r.tests.is_empty() {
            errors.push(format!("{at}: needs both code and tests"));
        }
    }
    errors
}

fn check_code(rows: &[Row]) -> Vec<String> {
    let mut errors = Vec::new();
    for r in rows {
        for c in &r.code {
            let (path, symbol) = c.split_once('#').map_or((*c, None), |(p, s)| (p, Some(s)));
            match fs::read_to_string(path) {
                Err(e) => errors.push(format!("{} / {}: {path}: {e}", r.component, r.control)),
                Ok(src) => {
                    if let Some(s) = symbol.filter(|s| !src.contains(s)) {
                        errors.push(format!(
                            "{} / {}: `{s}` not in {path}",
                            r.component, r.control
                        ));
                    }
                }
            }
        }
    }
    errors
}

fn check_tests(rows: &[Row]) -> Vec<String> {
    let mut by_package: BTreeMap<&str, Result<String, String>> = BTreeMap::new();
    let mut errors = Vec::new();
    for r in rows {
        for t in &r.tests {
            let Some((package, name)) = t.split_once("::") else {
                errors.push(format!("{t}: expected package::test::path"));
                continue;
            };
            let listing = by_package
                .entry(package)
                .or_insert_with(|| list_tests(package));
            match listing {
                Err(e) => errors.push(format!("{t}: {e}")),
                Ok(out) if !out.lines().any(|l| l.strip_suffix(": test") == Some(name)) => {
                    errors.push(format!("{} / {}: no test {t}", r.component, r.control));
                }
                Ok(_) => {}
            }
        }
    }
    errors.sort();
    errors.dedup();
    errors
}

fn list_tests(package: &str) -> Result<String, String> {
    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["test", "-p", package, "--locked", "--", "--list"])
        .output()
        .map_err(|e| format!("cargo test: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo test -p {package} --list failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Stable across runs, so regenerating only shows real changes.
fn id(parts: &[&str]) -> String {
    let name = format!("{NS}/{}", parts.join("/"));
    Uuid::new_v5(&Uuid::NAMESPACE_URL, name.as_bytes()).to_string()
}

fn prop(name: &str, value: &str) -> Value {
    json!({ "name": name, "value": value, "ns": NS })
}

fn render(doc: &Table, rows: &[Row]) -> Result<String, Vec<String>> {
    let meta = doc
        .get("meta")
        .and_then(Toml::as_table)
        .ok_or_else(|| vec![format!("{SOURCE}: no [meta]")])?;
    let field = |k| str_of(meta, k).map_err(|e| vec![e]);
    let source = field("catalog")?;
    let mut components = Vec::new();
    let empty = Table::new();
    let defs = doc
        .get("components")
        .and_then(Toml::as_table)
        .unwrap_or(&empty);
    for (key, def) in defs {
        let def = def
            .as_table()
            .ok_or_else(|| vec![format!("components.{key} isn't a table")])?;
        let requirements: Vec<Value> = rows
            .iter()
            .filter(|r| r.component == key)
            .map(|r| requirement(key, r))
            .collect();
        if requirements.is_empty() {
            continue;
        }
        components.push(json!({
            "uuid": id(&["component", key]),
            "type": "software",
            "title": str_of(def, "title").map_err(|e| vec![e])?,
            "description": str_of(def, "description").map_err(|e| vec![e])?,
            "control-implementations": [{
                "uuid": id(&["implementation", key]),
                "source": source,
                "description": format!("NIST SP 800-53 Rev 5 controls implemented by {key}."),
                "implemented-requirements": requirements,
            }],
        }));
    }
    let out = json!({ "component-definition": {
        "uuid": id(&["component-definition"]),
        "metadata": {
            "title": field("title")?,
            "last-modified": field("last_modified")?,
            "version": env!("CARGO_PKG_VERSION"),
            "oscal-version": field("oscal_version")?,
        },
        "components": components,
    }});
    let mut s = serde_json::to_string_pretty(&out).map_err(|e| vec![e.to_string()])?;
    s.push('\n');
    Ok(s)
}

fn requirement(component: &str, r: &Row) -> Value {
    let links: Vec<Value> = r
        .code
        .iter()
        .map(|c| match c.split_once('#') {
            Some((path, symbol)) => json!({ "href": path, "rel": "reference", "text": symbol }),
            None => json!({ "href": c, "rel": "reference" }),
        })
        .collect();
    let mut props = vec![prop("responsibility", r.responsibility)];
    props.extend(r.tests.iter().map(|t| prop("test", t)));
    json!({
        "uuid": id(&["requirement", component, r.control]),
        "control-id": r.control,
        "description": r.statement,
        "props": props,
        "links": links,
    })
}
