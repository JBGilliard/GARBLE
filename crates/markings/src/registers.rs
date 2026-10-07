use std::collections::{BTreeMap, BTreeSet};

use crate::{Compartments, Country, MarkingError};

/// Accreditor-supplied value lists. In production they come from the signed trust
/// bundle (§4.3); `markings` never loads them itself and has no default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registers {
    version: u32,
    sci: Compartments,
    sap: Compartments,
    countries: BTreeSet<Country>,
    collectives: BTreeMap<Country, BTreeSet<Country>>,
    cui: BTreeSet<String>,
}

impl Registers {
    /// Validates names so later rendering and encoding can trust them:
    /// control names are `[A-Z0-9]+`, countries are trigraphs, collectives are
    /// tetragraphs whose members are registered trigraphs.
    pub fn new(
        version: u32,
        sci: Compartments,
        sap: Compartments,
        countries: BTreeSet<Country>,
        collectives: BTreeMap<Country, BTreeSet<Country>>,
        cui: BTreeSet<String>,
    ) -> Result<Self, MarkingError> {
        for tree in [&sci, &sap] {
            for (sys, comps) in tree {
                check_name(sys)?;
                for (comp, subs) in comps {
                    check_name(comp)?;
                    subs.iter().try_for_each(|s| check_name(s))?;
                }
            }
        }
        if let Some(c) = countries.iter().find(|c| c.as_str().len() != 3) {
            return Err(MarkingError::InvalidRegister(format!(
                "'{}' is not a trigraph",
                c.as_str()
            )));
        }
        for (name, members) in &collectives {
            if name.as_str().len() != 4 {
                return Err(MarkingError::InvalidRegister(format!(
                    "collective '{}' is not a tetragraph",
                    name.as_str()
                )));
            }
            if let Some(m) = members.iter().find(|m| !countries.contains(*m)) {
                return Err(MarkingError::InvalidRegister(format!(
                    "collective '{}' names unregistered '{}'",
                    name.as_str(),
                    m.as_str()
                )));
            }
        }
        for cat in &cui {
            let ok = !cat.is_empty()
                && cat
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-');
            if !ok {
                return Err(MarkingError::InvalidRegister(format!(
                    "bad CUI category '{cat}'"
                )));
            }
        }
        Ok(Self {
            version,
            sci,
            sap,
            countries,
            collectives,
            cui,
        })
    }

    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn sci(&self) -> &Compartments {
        &self.sci
    }
    pub fn sap(&self) -> &Compartments {
        &self.sap
    }
    pub fn cui(&self) -> &BTreeSet<String> {
        &self.cui
    }

    pub(crate) fn knows_sci_system(&self, sys: &str) -> bool {
        self.sci.contains_key(sys)
    }

    pub(crate) fn check_country(&self, c: &Country) -> Result<(), MarkingError> {
        if self.countries.contains(c) || self.collectives.contains_key(c) {
            Ok(())
        } else {
            Err(MarkingError::UnknownCountry(c.as_str().to_owned()))
        }
    }

    /// Whether `citizenship` falls inside a REL TO list, expanding collectives.
    pub(crate) fn releasable_to(&self, list: &BTreeSet<Country>, citizenship: &Country) -> bool {
        list.iter().any(|c| {
            c == citizenship
                || self
                    .collectives
                    .get(c)
                    .is_some_and(|members| members.contains(citizenship))
        })
    }

    /// Sample registers adapted from Meridian's `sci_register.json` and
    /// `iso3166_alpha3.txt`. SAMPLE DATA: not authoritative.
    #[cfg(any(test, feature = "sample-registers"))]
    pub fn sample() -> Self {
        // Built with the marking grammar itself: `SYS-COMP SUB SUB`.
        fn tree(paths: &[&str]) -> Compartments {
            let mut t = Compartments::new();
            for p in paths {
                match crate::parse::parse_tree(p) {
                    Ok(x) => crate::tree_union(&mut t, &x),
                    Err(e) => panic!("sample register path {p}: {e}"),
                }
            }
            t
        }
        let sci = tree(&["HCS-P", "KDK", "SI-G ABCD EFGH", "TK"]);
        let sap = tree(&["SAMPLE", "EXAMPLE-TWO-ONE-THREE-FOUR A1 A2"]);
        let countries: BTreeSet<Country> = include_str!("../data/sample_countries.txt")
            .lines()
            .map(str::trim)
            .filter(|l| l.len() == 3 && !l.starts_with('#'))
            .filter_map(|l| Country::new(l).ok())
            .collect();
        let fvey = ["USA", "AUS", "CAN", "GBR", "NZL"].map(|c| Country(c.to_owned()));
        let collectives = BTreeMap::from([(Country("FVEY".to_owned()), fvey.into())]);
        let cui = ["CTI", "PRVCY", "SP-CTI", "SP-PRVCY"]
            .into_iter()
            .map(String::from)
            .collect();
        match Self::new(1, sci, sap, countries, collectives, cui) {
            Ok(r) => r,
            Err(e) => panic!("sample registers are invalid: {e}"),
        }
    }
}

fn check_name(s: &str) -> Result<(), MarkingError> {
    let ok = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err(MarkingError::InvalidRegister(format!(
            "bad control name '{s}'"
        )))
    }
}
