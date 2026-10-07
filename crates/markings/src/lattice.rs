//! Comparing markings with each other (`within`, `max`) and with people (`dominates`).
//!
//! The three are designed to agree. The property tests check:
//! * `a.within(&a.max(&b))`: aggregation never lowers a marking;
//! * `dominates(c, ceiling) ∧ m.within(ceiling) ⇒ dominates(c, m)`: anyone cleared for a
//!   room is cleared for every message the room accepts. That is what makes "check the
//!   joiner against the ceiling, check each message against the ceiling" sound (§4.4).

use std::collections::BTreeSet;

use crate::{
    Aea, Compartments, Country, CuiBlock, Dissem, Fgi, Level, Marking, MarkingError, Registers,
    tree_from_paths, tree_missing, tree_union,
};

/// What a person holds. Built by `identity` from a verified `AttributeCredential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clearance {
    pub level: Level,
    pub sci: Compartments,
    pub sap: Compartments,
    pub aea: BTreeSet<Aea>,
    /// May handle foreign government information.
    pub fgi: bool,
    pub citizenship: Country,
    /// Explicit grants for access-restricting dissem controls (ORCON, RSEN, FISA, …).
    /// Default deny: a control not listed here is a shortfall.
    pub dissem_grants: BTreeSet<Dissem>,
    pub cui: BTreeSet<String>,
}

/// Who may receive a marking, before personal clearance is considered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Releasability {
    /// Unclassified with no foreign-disclosure control.
    Unrestricted,
    /// Only nationals of these (collectives expanded at check time). `{USA}` = NOFORN.
    To(BTreeSet<Country>),
}

/// Every reason a clearance falls short of a marking. Empty fields mean no gap.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Shortfall {
    /// The level needed, if the clearance's level is too low.
    pub level: Option<Level>,
    pub sci: Compartments,
    pub sap: Compartments,
    pub aea: BTreeSet<Aea>,
    pub fgi: bool,
    pub dissem: BTreeSet<Dissem>,
    /// The releasability the citizenship failed, if it failed.
    pub releasability: Option<Releasability>,
    pub cui: BTreeSet<String>,
}

impl Shortfall {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// May the holder of `c` see something marked `m`? Returns every gap at once, so a
/// denial can show the whole picture rather than the first failure.
pub fn dominates(c: &Clearance, m: &Marking, reg: &Registers) -> Result<(), Box<Shortfall>> {
    let mut s = Shortfall {
        level: (c.level < m.level).then_some(m.level),
        sci: tree_from_paths(tree_missing(&m.sci, &c.sci)),
        sap: tree_from_paths(tree_missing(&m.sap, &c.sap)),
        aea: m.aea.difference(&c.aea).copied().collect(),
        fgi: m.fgi.is_some() && !c.fgi,
        dissem: m
            .dissem
            .iter()
            .filter(|d| d.needs_grant() && !c.dissem_grants.contains(d))
            .copied()
            .collect(),
        releasability: None,
        cui: m
            .cui
            .iter()
            .flat_map(|b| b.categories.difference(&c.cui).cloned())
            .collect(),
    };
    if let Releasability::To(list) = m.releasability()
        && !reg.releasable_to(&list, &c.citizenship)
    {
        s.releasability = Some(Releasability::To(list));
    }
    if s.is_empty() {
        Ok(())
    } else {
        Err(Box::new(s))
    }
}

/// Foreign-disclosure state of one marking.
enum Fd<'a> {
    None,
    Noforn,
    RelTo(&'a BTreeSet<Country>),
}

impl Marking {
    fn fd(&self) -> Fd<'_> {
        if self.dissem.contains(&Dissem::Noforn) {
            Fd::Noforn
        } else if let Some(r) = &self.rel_to {
            Fd::RelTo(r)
        } else {
            Fd::None
        }
    }

    pub fn releasability(&self) -> Releasability {
        match self.fd() {
            Fd::Noforn => Releasability::To(BTreeSet::from([Country::usa()])),
            Fd::RelTo(r) => Releasability::To(r.clone()),
            // TODO-verify against CAPCO: a classified portion with no foreign-disclosure
            // control is not releasable, so it behaves as NOFORN (§4.1.1 item 8).
            Fd::None if self.level > Level::Unclassified => {
                Releasability::To(BTreeSet::from([Country::usa()]))
            }
            Fd::None => Releasability::Unrestricted,
        }
    }

    /// May `self` be held under `ceiling`? True when everyone cleared for the ceiling
    /// is cleared for `self`. A partial order: reflexive, and `a.within(a.max(b))`.
    pub fn within(&self, ceiling: &Marking) -> bool {
        let rel = match (self.releasability(), ceiling.releasability()) {
            (Releasability::Unrestricted, _) => true,
            (Releasability::To(_), Releasability::Unrestricted) => false,
            // Token comparison, no collective expansion: conservative, never unsound.
            (Releasability::To(mine), Releasability::To(theirs)) => theirs.is_subset(&mine),
        };
        let restricting = |m: &Marking| -> BTreeSet<Dissem> {
            m.dissem
                .iter()
                .filter(|d| d.needs_grant())
                .copied()
                .collect()
        };
        self.level <= ceiling.level
            && tree_missing(&self.sci, &ceiling.sci).is_empty()
            && tree_missing(&self.sap, &ceiling.sap).is_empty()
            && self.aea.is_subset(&ceiling.aea)
            && fgi_within(self.fgi.as_ref(), ceiling.fgi.as_ref())
            && restricting(self).is_subset(&restricting(ceiling))
            && rel
            && cui_categories(self).is_subset(&cui_categories(ceiling))
    }

    /// High-water mark of two markings (Meridian `max` + `reconcile_releasability`,
    /// marking.rs:369–388, 644–685). Infallible: the result of two valid markings is valid.
    pub fn max(&self, other: &Marking) -> Marking {
        let mut sci = self.sci.clone();
        tree_union(&mut sci, &other.sci);
        let mut sap = self.sap.clone();
        tree_union(&mut sap, &other.sap);

        let mut dissem: BTreeSet<Dissem> = self.dissem.union(&other.dissem).copied().collect();
        dissem.remove(&Dissem::Noforn);
        // RELIDO only rolls up if every part carries it. TODO-verify against CAPCO.
        if !(self.dissem.contains(&Dissem::Relido) && other.dissem.contains(&Dissem::Relido)) {
            dissem.remove(&Dissem::Relido);
        }
        let mut rel_to = None;
        let classified = |m: &Marking| m.level > Level::Unclassified;
        match (self.fd(), other.fd()) {
            (Fd::Noforn, _) | (_, Fd::Noforn) => {
                dissem.insert(Dissem::Noforn);
            }
            // REL TO lists intersect. USA is in every list, so the result is never empty.
            (Fd::RelTo(a), Fd::RelTo(b)) => rel_to = Some(a.intersection(b).cloned().collect()),
            // Item 8: REL TO combined with an unmarked *classified* part becomes NOFORN.
            // TODO-verify against CAPCO.
            (Fd::RelTo(r), Fd::None) | (Fd::None, Fd::RelTo(r)) => {
                let unmarked = if matches!(self.fd(), Fd::None) {
                    self
                } else {
                    other
                };
                if classified(unmarked) {
                    dissem.insert(Dissem::Noforn);
                } else {
                    rel_to = Some(r.clone());
                }
            }
            (Fd::None, Fd::None) => {}
        }

        let cui = (self.cui.is_some() || other.cui.is_some()).then(|| CuiBlock {
            categories: cui_categories(self)
                .union(&cui_categories(other))
                .cloned()
                .collect(),
        });

        Marking {
            level: self.level.max(other.level),
            sci,
            sap,
            aea: self.aea.union(&other.aea).copied().collect(),
            fgi: fgi_max(self.fgi.clone(), other.fgi.clone()),
            dissem,
            rel_to,
            cui,
        }
    }
}

/// High-water mark of many markings, e.g. everything currently on screen (§7.1 `banner`).
/// Zero markings is an error, not UNCLASSIFIED.
pub fn aggregate<'a>(ms: impl IntoIterator<Item = &'a Marking>) -> Result<Marking, MarkingError> {
    let mut it = ms.into_iter();
    let first = it.next().ok_or(MarkingError::EmptyAggregate)?.clone();
    Ok(it.fold(first, |acc, m| acc.max(m)))
}

/// Concealed FGI dominates acknowledged FGI: combining them hides the sources.
pub(crate) fn fgi_max(a: Option<Fgi>, b: Option<Fgi>) -> Option<Fgi> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(Fgi::Concealed), _) | (_, Some(Fgi::Concealed)) => Some(Fgi::Concealed),
        (Some(Fgi::Countries(mut x)), Some(Fgi::Countries(y))) => {
            x.extend(y);
            Some(Fgi::Countries(x))
        }
    }
}

fn fgi_within(a: Option<&Fgi>, ceiling: Option<&Fgi>) -> bool {
    match (a, ceiling) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(_), Some(Fgi::Concealed)) => true,
        (Some(Fgi::Concealed), Some(Fgi::Countries(_))) => false,
        (Some(Fgi::Countries(x)), Some(Fgi::Countries(y))) => x.is_subset(y),
    }
}

fn cui_categories(m: &Marking) -> BTreeSet<String> {
    m.cui
        .iter()
        .flat_map(|c| c.categories.iter().cloned())
        .collect()
}

impl Clearance {
    /// The least clearance that sees everything `access` covers: e.g. access
    /// `TS//SI/TK//OC` grants TS, SI, TK and an ORCON grant. Lets an issuer state a
    /// clearance in marking syntax.
    pub fn covering(access: &Marking, citizenship: Country) -> Clearance {
        Clearance {
            level: access.level,
            sci: access.sci.clone(),
            sap: access.sap.clone(),
            aea: access.aea.clone(),
            fgi: access.fgi.is_some(),
            citizenship,
            dissem_grants: access
                .dissem
                .iter()
                .copied()
                .filter(|d| d.needs_grant())
                .collect(),
            cui: cui_categories(access),
        }
    }
}

impl std::fmt::Display for Shortfall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut gaps: Vec<String> = Vec::new();
        if let Some(l) = self.level {
            gaps.push(format!("level {}", l.portion()));
        }
        let paths = |t: &Compartments| {
            tree_missing(t, &Compartments::new())
                .iter()
                .map(crate::render::tree_path)
                .collect::<Vec<_>>()
                .join(", ")
        };
        if !self.sci.is_empty() {
            gaps.push(format!("SCI {}", paths(&self.sci)));
        }
        if !self.sap.is_empty() {
            gaps.push(format!("SAR {}", paths(&self.sap)));
        }
        if !self.aea.is_empty() {
            let a: Vec<_> = self.aea.iter().map(|a| a.token()).collect();
            gaps.push(format!("AEA {}", a.join(", ")));
        }
        if self.fgi {
            gaps.push("FGI access".into());
        }
        if !self.dissem.is_empty() {
            let d: Vec<_> = self.dissem.iter().map(|d| d.banner()).collect();
            gaps.push(format!("grants {}", d.join(", ")));
        }
        if let Some(Releasability::To(list)) = &self.releasability {
            gaps.push(format!(
                "releasability ({})",
                crate::render::capco_order(list).join(",")
            ));
        }
        if !self.cui.is_empty() {
            gaps.push(format!(
                "CUI {}",
                self.cui.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
        write!(f, "missing {}", gaps.join("; "))
    }
}
