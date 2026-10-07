//! Portion and banner rendering. Ported from Meridian `render` / `sar_tokens`
//! (marking.rs:418–469, 606–640). Output always follows CAPCO slot order and is
//! deterministic, so `parse(render(m)) == m` (see `proptests`).

use std::collections::{BTreeMap, BTreeSet};

use crate::{Country, Dissem, Fgi, Level, Marking, TreePath};

impl Marking {
    /// Portion mark: `TS//SI-G ABCD/TK//NF`.
    pub fn portion(&self) -> String {
        self.render(false)
    }

    /// Banner mark: `TOP SECRET//SI-G ABCD/TK//NOFORN`.
    pub fn banner(&self) -> String {
        self.render(true)
    }

    fn render(&self, banner: bool) -> String {
        let mut parts: Vec<String> = Vec::new();
        match (&self.cui, self.level) {
            // CUI shows only on unclassified markings. A classified aggregate keeps the
            // CUI block in its data and canonical bytes but displays the classification.
            // TODO-verify against DoDI 5200.48 for classified documents containing CUI.
            (Some(cui), Level::Unclassified) => {
                parts.push("CUI".into());
                if !cui.categories.is_empty() {
                    parts.push(cui.categories.iter().cloned().collect::<Vec<_>>().join("/"));
                }
            }
            _ => parts.push(
                if banner {
                    self.level.banner()
                } else {
                    self.level.portion()
                }
                .into(),
            ),
        }

        if !self.sci.is_empty() {
            let systems: Vec<String> = self.sci.iter().map(|(s, c)| system(s, c)).collect();
            parts.push(systems.join("/"));
        }
        // Each SAR program is its own token (Meridian `sar_not_grouped`).
        parts.extend(
            self.sap
                .iter()
                .map(|(p, c)| format!("SAR-{}", system(p, c))),
        );
        parts.extend(self.aea.iter().map(|a| a.token().to_owned()));
        match &self.fgi {
            Some(Fgi::Concealed) => parts.push("FGI".into()),
            Some(Fgi::Countries(cs)) => {
                parts.extend(cs.iter().map(|c| format!("FGI-{}", c.as_str())))
            }
            None => {}
        }

        let name = |d: &Dissem| if banner { d.banner() } else { d.portion() }.to_owned();
        parts.extend(
            self.dissem
                .iter()
                .filter(|d| **d < Dissem::Relido)
                .map(name),
        );
        if let Some(rel) = &self.rel_to {
            // TODO-verify: CAPCO separator (", " vs ",") and the portion form `REL`.
            let list = capco_order(rel).join(",");
            parts.push(if banner {
                format!("REL TO {list}")
            } else {
                format!("REL {list}")
            });
        }
        parts.extend(
            self.dissem
                .iter()
                .filter(|d| **d >= Dissem::Relido)
                .map(name),
        );
        parts.join("//")
    }
}

/// `SI` + {G: {ABCD, EFGH}, H: {}} → `SI-G ABCD EFGH-H`.
fn system(sys: &str, comps: &BTreeMap<String, BTreeSet<String>>) -> String {
    let mut out = sys.to_owned();
    for (comp, subs) in comps {
        out.push('-');
        out.push_str(comp);
        for s in subs {
            out.push(' ');
            out.push_str(s);
        }
    }
    out
}

pub(crate) fn capco_order(list: &BTreeSet<Country>) -> Vec<&str> {
    let mut v: Vec<&Country> = list.iter().collect();
    v.sort_by(|a, b| a.capco_key().cmp(&b.capco_key()));
    v.into_iter().map(Country::as_str).collect()
}

pub(crate) fn tree_path((sys, comp, sub): &TreePath) -> String {
    match (comp, sub) {
        (None, _) => sys.clone(),
        (Some(c), None) => format!("{sys}-{c}"),
        (Some(c), Some(s)) => format!("{sys}-{c} {s}"),
    }
}
