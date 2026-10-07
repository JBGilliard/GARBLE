//! CAPCO classification markings for GARBLE (architecture §4.1).
//!
//! Adapted from Meridian's `lexicon-core/src/marking.rs` (copied, not depended on).
//! Pure: no I/O, no clock, no randomness, no crypto. Registers are passed in;
//! there is no built-in fallback outside the `sample-registers` feature.
//!
//! A [`Marking`] can only be built by [`parse`], [`Marking::from_canonical`] or
//! [`Marking::max`], so every value in circulation has passed validation.

mod canonical;
mod error;
mod lattice;
mod parse;
mod registers;
mod render;

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub use error::MarkingError;
pub use lattice::{Clearance, Releasability, Shortfall, aggregate, dominates};
pub use parse::parse;
pub use registers::Registers;

/// Classification level. CUI is deliberately not a level (see [`CuiBlock`]).
/// Discriminants are the canonical encoding; never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Level {
    Unclassified = 0,
    Confidential = 1,
    Secret = 2,
    TopSecret = 3,
}

impl Level {
    pub fn portion(self) -> &'static str {
        match self {
            Self::Unclassified => "U",
            Self::Confidential => "C",
            Self::Secret => "S",
            Self::TopSecret => "TS",
        }
    }

    pub fn banner(self) -> &'static str {
        match self {
            Self::Unclassified => "UNCLASSIFIED",
            Self::Confidential => "CONFIDENTIAL",
            Self::Secret => "SECRET",
            Self::TopSecret => "TOP SECRET",
        }
    }

    /// Accepts Meridian's aliases. Input must already be upper case.
    fn parse(s: &str) -> Option<Self> {
        match s {
            "U" | "UNCLASS" | "UNCLASSIFIED" => Some(Self::Unclassified),
            "C" | "CONF" | "CONFIDENTIAL" => Some(Self::Confidential),
            "S" | "SECRET" => Some(Self::Secret),
            "TS" | "TOPSECRET" | "TOP SECRET" => Some(Self::TopSecret),
            _ => None,
        }
    }

    fn from_u8(v: u8) -> Option<Self> {
        [
            Self::Unclassified,
            Self::Confidential,
            Self::Secret,
            Self::TopSecret,
        ]
        .into_iter()
        .find(|l| *l as u8 == v)
    }
}

/// Control system → compartment → sub-compartments.
/// SCI (`SI-G ABCD`) and SAR (`SAR-EXAMPLE-FOUR A1`) share this shape. A map, not a set of
/// structs, so one system can't appear twice with different contents.
pub type Compartments = BTreeMap<String, BTreeMap<String, BTreeSet<String>>>;

/// Atomic Energy Act markings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Aea {
    Rd = 1,
    Frd = 2,
    Cnwdi = 3,
}

impl Aea {
    const ALL: [Aea; 3] = [Aea::Rd, Aea::Frd, Aea::Cnwdi];

    pub fn token(self) -> &'static str {
        match self {
            Self::Rd => "RD",
            Self::Frd => "FRD",
            Self::Cnwdi => "CNWDI",
        }
    }
}

/// Foreign government information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Fgi {
    /// Source concealed: renders as bare `FGI`.
    Concealed,
    /// Acknowledged sources. Never empty.
    Countries(BTreeSet<Country>),
}

/// Dissemination controls, in CAPCO display order. REL TO is held separately
/// (`Marking::rel_to`) and renders between PROPIN and RELIDO.
/// Discriminants are the canonical encoding; never renumber.
/// TODO-verify: the set and order against the current ISM CVE / CAPCO register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Dissem {
    Hvsaco = 1,
    Waived = 2,
    Rsen = 3,
    Fisa = 4,
    Orcon = 5,
    Imcon = 6,
    Noforn = 7,
    Propin = 8,
    Relido = 9,
    Dsen = 10,
    Limdis = 11,
    Exdis = 12,
    Nodis = 13,
}

impl Dissem {
    const ALL: [Dissem; 13] = [
        Dissem::Hvsaco,
        Dissem::Waived,
        Dissem::Rsen,
        Dissem::Fisa,
        Dissem::Orcon,
        Dissem::Imcon,
        Dissem::Noforn,
        Dissem::Propin,
        Dissem::Relido,
        Dissem::Dsen,
        Dissem::Limdis,
        Dissem::Exdis,
        Dissem::Nodis,
    ];

    pub fn banner(self) -> &'static str {
        match self {
            Self::Hvsaco => "HVSACO",
            Self::Waived => "WAIVED",
            Self::Rsen => "RSEN",
            Self::Fisa => "FISA",
            Self::Orcon => "ORCON",
            Self::Imcon => "IMCON",
            Self::Noforn => "NOFORN",
            Self::Propin => "PROPIN",
            Self::Relido => "RELIDO",
            Self::Dsen => "DSEN",
            Self::Limdis => "LIMDIS",
            Self::Exdis => "EXDIS",
            Self::Nodis => "NODIS",
        }
    }

    pub fn portion(self) -> &'static str {
        match self {
            Self::Rsen => "RS",
            Self::Orcon => "OC",
            Self::Imcon => "IMC",
            Self::Noforn => "NF",
            Self::Propin => "PR",
            Self::Limdis => "DS",
            Self::Exdis => "XD",
            Self::Nodis => "ND",
            other => other.banner(),
        }
    }

    fn from_token(s: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|d| d.banner() == s || d.portion() == s)
    }

    /// Controls that restrict *who* may see the content, so a reader needs an explicit
    /// grant. NOFORN is handled by releasability; RELIDO restricts nothing.
    fn needs_grant(self) -> bool {
        !matches!(self, Self::Noforn | Self::Relido)
    }
}

/// An ISO 3166-1 alpha-3 trigraph or a tetragraph collective (`FVEY`). Format-checked
/// on construction; register membership is checked by [`validate`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Country(String);

impl Country {
    pub fn new(code: &str) -> Result<Self, MarkingError> {
        let ok = matches!(code.len(), 3 | 4) && code.bytes().all(|b| b.is_ascii_uppercase());
        if ok {
            Ok(Self(code.to_owned()))
        } else {
            Err(MarkingError::InvalidCountry(code.to_owned()))
        }
    }

    pub fn usa() -> Self {
        Self("USA".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// CAPCO list order: USA first, then trigraphs, then tetragraphs, each alphabetical.
    fn capco_key(&self) -> (u8, usize, &str) {
        (u8::from(self.0 != "USA"), self.0.len(), &self.0)
    }
}

/// Controlled Unclassified Information. Orthogonal to [`Level`]: a marking at any
/// level may carry it. Text form `CUI[//CAT/CAT]` is parsed only at the unclassified
/// level in v1; a classified aggregate keeps it in the data and omits it from rendering.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct CuiBlock {
    pub categories: BTreeSet<String>,
}

/// A validated CAPCO marking. Fields are private: build one with [`parse`],
/// [`Marking::from_canonical`] or [`Marking::max`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Marking {
    level: Level,
    sci: Compartments,
    sap: Compartments,
    aea: BTreeSet<Aea>,
    fgi: Option<Fgi>,
    dissem: BTreeSet<Dissem>,
    rel_to: Option<BTreeSet<Country>>,
    cui: Option<CuiBlock>,
}

impl Marking {
    fn unclassified() -> Self {
        Self {
            level: Level::Unclassified,
            sci: Compartments::new(),
            sap: Compartments::new(),
            aea: BTreeSet::new(),
            fgi: None,
            dissem: BTreeSet::new(),
            rel_to: None,
            cui: None,
        }
    }

    pub fn level(&self) -> Level {
        self.level
    }
    pub fn sci(&self) -> &Compartments {
        &self.sci
    }
    pub fn sap(&self) -> &Compartments {
        &self.sap
    }
    pub fn aea(&self) -> &BTreeSet<Aea> {
        &self.aea
    }
    pub fn fgi(&self) -> Option<&Fgi> {
        self.fgi.as_ref()
    }
    pub fn dissem(&self) -> &BTreeSet<Dissem> {
        &self.dissem
    }
    pub fn rel_to(&self) -> Option<&BTreeSet<Country>> {
        self.rel_to.as_ref()
    }
    pub fn cui(&self) -> Option<&CuiBlock> {
        self.cui.as_ref()
    }
}

impl fmt::Display for Marking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.portion())
    }
}

/// Structural and register checks shared by `parse` and `from_canonical`, so the
/// two entry points can't drift apart.
fn validate(m: &Marking, reg: &Registers) -> Result<(), MarkingError> {
    let has_controls =
        !m.sci.is_empty() || !m.sap.is_empty() || !m.aea.is_empty() || m.fgi.is_some();
    if m.level == Level::Unclassified && has_controls {
        return Err(MarkingError::ControlsRequireClassified);
    }
    if let Some(path) = tree_missing(&m.sci, reg.sci()).into_iter().next() {
        return Err(MarkingError::UnknownSci(render::tree_path(&path)));
    }
    if let Some(path) = tree_missing(&m.sap, reg.sap()).into_iter().next() {
        return Err(MarkingError::UnknownSar(render::tree_path(&path)));
    }
    if let Some(rel) = &m.rel_to {
        if m.dissem.contains(&Dissem::Noforn) {
            return Err(MarkingError::NofornWithRelTo);
        }
        if rel.is_empty() {
            return Err(MarkingError::RelToEmpty);
        }
        if !rel.contains(&Country::usa()) {
            return Err(MarkingError::RelToWithoutUsa);
        }
        for c in rel {
            reg.check_country(c)?;
        }
    }
    match &m.fgi {
        Some(Fgi::Countries(cs)) if cs.is_empty() => {
            return Err(MarkingError::MalformedCompartment("FGI-".into()));
        }
        Some(Fgi::Countries(cs)) => {
            for c in cs {
                reg.check_country(c)?;
            }
        }
        _ => {}
    }
    if let Some(cui) = &m.cui {
        for cat in &cui.categories {
            if !reg.cui().contains(cat) {
                return Err(MarkingError::UnknownCuiCategory(cat.clone()));
            }
        }
    }
    Ok(())
}

/// One path of a compartment tree: (system, compartment, sub-compartment).
type TreePath = (String, Option<String>, Option<String>);

/// Everything in `a` that `b` does not cover, as paths. A system present in `b`
/// covers a bare system in `a`; compartments and subs must match exactly.
fn tree_missing(a: &Compartments, b: &Compartments) -> Vec<TreePath> {
    let mut out = Vec::new();
    for (sys, comps) in a {
        let Some(have) = b.get(sys) else {
            out.push((sys.clone(), None, None));
            continue;
        };
        for (comp, subs) in comps {
            let Some(have_subs) = have.get(comp) else {
                out.push((sys.clone(), Some(comp.clone()), None));
                continue;
            };
            for sub in subs.difference(have_subs) {
                out.push((sys.clone(), Some(comp.clone()), Some(sub.clone())));
            }
        }
    }
    out
}

fn tree_from_paths(paths: Vec<TreePath>) -> Compartments {
    let mut t = Compartments::new();
    for (sys, comp, sub) in paths {
        let comps = t.entry(sys).or_default();
        if let Some(comp) = comp {
            let subs = comps.entry(comp).or_default();
            if let Some(sub) = sub {
                subs.insert(sub);
            }
        }
    }
    t
}

fn tree_union(a: &mut Compartments, b: &Compartments) {
    for (sys, comps) in b {
        let mine = a.entry(sys.clone()).or_default();
        for (comp, subs) in comps {
            mine.entry(comp.clone())
                .or_default()
                .extend(subs.iter().cloned());
        }
    }
}
