//! Property tests over random valid markings drawn from the sample registers.

use std::collections::BTreeSet;

use proptest::prelude::*;
use proptest::sample::subsequence;

use crate::*;

const SCI: &[&str] = &[
    "TK",
    "HCS",
    "HCS-P",
    "SI",
    "SI-G",
    "SI-G ABCD",
    "SI-G ABCD EFGH",
    "KDK",
];
const SAR: &[&str] = &[
    "SAMPLE",
    "EXAMPLE",
    "EXAMPLE-ONE",
    "EXAMPLE-TWO",
    "EXAMPLE-FOUR A1",
    "EXAMPLE-FOUR A1 A2",
];
const REL: &[&str] = &["GBR", "AUS", "CAN", "NZL", "FVEY", "DEU"];
const FGI: &[&str] = &["GBR", "DEU", "FRA"];
const CUI: &[&str] = &["CTI", "PRVCY", "SP-CTI", "SP-PRVCY"];
const CITIZEN: &[&str] = &["USA", "GBR", "AUS", "DEU"];

fn level() -> impl Strategy<Value = Level> {
    prop_oneof![
        Just(Level::Unclassified),
        Just(Level::Confidential),
        Just(Level::Secret),
        Just(Level::TopSecret)
    ]
}

fn tree_of(paths: Vec<&str>) -> Compartments {
    let mut t = Compartments::new();
    for p in paths {
        if let Ok(x) = crate::parse::parse_tree(p) {
            tree_union(&mut t, &x);
        }
    }
    t
}

fn set<T: Ord + Clone>(xs: &[T]) -> BTreeSet<T> {
    xs.iter().cloned().collect()
}

prop_compose! {
    fn raw_marking()(
        level in level(),
        sci in subsequence(SCI, 0..3),
        sap in subsequence(SAR, 0..2),
        aea in subsequence(&Aea::ALL[..], 0..2),
        fgi in prop_oneof![Just(None), Just(Some(Fgi::Concealed)), subsequence(FGI, 1..3).prop_map(|cs| Some(Fgi::Countries(cs.into_iter().filter_map(|c| Country::new(c).ok()).collect())))],
        dissem in subsequence(&Dissem::ALL[..], 0..3),
        rel in prop_oneof![Just(None), subsequence(REL, 0..3).prop_map(Some)],
        cui in prop_oneof![Just(None), subsequence(CUI, 0..2).prop_map(Some)],
    ) -> Marking {
        let rel_to = rel.map(|r| {
            let mut s: BTreeSet<Country> = r.into_iter().filter_map(|c| Country::new(c).ok()).collect();
            s.insert(Country::usa());
            s
        });
        let mut dissem = set(&dissem);
        if rel_to.is_some() { dissem.remove(&Dissem::Noforn); }
        // Strip controls that need a classified level rather than filtering, so
        // unclassified markings stay common (25%) in the sample.
        let classified = level > Level::Unclassified;
        Marking {
            level,
            sci: if classified { tree_of(sci) } else { Compartments::new() },
            sap: if classified { tree_of(sap) } else { Compartments::new() },
            aea: if classified { set(&aea) } else { BTreeSet::new() },
            fgi: fgi.filter(|_| classified),
            dissem,
            rel_to,
            // v1 text grammar carries CUI only on unclassified markings.
            cui: cui.filter(|_| level == Level::Unclassified).map(|c| CuiBlock { categories: c.into_iter().map(String::from).collect() }),
        }
    }
}

/// Valid markings only: the generator overshoots and `validate` filters.
fn marking() -> impl Strategy<Value = Marking> {
    raw_marking().prop_filter("invalid marking", |m| {
        validate(m, &Registers::sample()).is_ok()
    })
}

prop_compose! {
    fn clearance()(
        level in level(),
        sci in subsequence(SCI, 0..5),
        sap in subsequence(SAR, 0..4),
        aea in subsequence(&Aea::ALL[..], 0..3),
        fgi in any::<bool>(),
        citizenship in prop::sample::select(CITIZEN),
        grants in subsequence(&Dissem::ALL[..], 0..8),
        cui in subsequence(CUI, 0..4),
    ) -> Clearance {
        Clearance {
            level,
            sci: tree_of(sci),
            sap: tree_of(sap),
            aea: set(&aea),
            fgi,
            citizenship: Country::new(citizenship).unwrap_or_else(|_| Country::usa()),
            dissem_grants: set(&grants),
            cui: cui.into_iter().map(String::from).collect(),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn portion_round_trips(m in marking()) {
        prop_assert_eq!(parse(&m.portion(), &Registers::sample()), Ok(m));
    }

    #[test]
    fn banner_round_trips(m in marking()) {
        prop_assert_eq!(parse(&m.banner(), &Registers::sample()), Ok(m));
    }

    #[test]
    fn parse_canonical_parse(m in marking()) {
        let r = Registers::sample();
        let parsed = parse(&m.portion(), &r).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let bytes = parsed.canonical_bytes().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let decoded = Marking::from_canonical(&bytes, &r).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(&decoded, &m);
        prop_assert_eq!(parse(&decoded.portion(), &r), Ok(m));
    }

    #[test]
    fn canonical_rejects_every_truncation(m in marking()) {
        let r = Registers::sample();
        let bytes = m.canonical_bytes().map_err(|e| TestCaseError::fail(e.to_string()))?;
        for n in 0..bytes.len() {
            prop_assert!(Marking::from_canonical(&bytes[..n], &r).is_err());
        }
    }

    #[test]
    fn within_is_reflexive(m in marking()) {
        prop_assert!(m.within(&m));
    }

    #[test]
    fn max_is_an_upper_bound_and_commutes(a in marking(), b in marking()) {
        let m = a.max(&b);
        prop_assert!(a.within(&m), "{} not within {}", a, m);
        prop_assert!(b.within(&m), "{} not within {}", b, m);
        prop_assert_eq!(&m, &b.max(&a));
        prop_assert!(validate(&m, &Registers::sample()).is_ok(), "max produced invalid {}", m);
        prop_assert!(Marking::from_canonical(&m.canonical_bytes().unwrap_or_default(), &Registers::sample()).is_ok());
    }

    #[test]
    fn max_is_idempotent(a in marking()) {
        prop_assert_eq!(a.max(&a), a);
    }

    /// idea-v1 §4a: dominance is consistent with the join.
    #[test]
    fn dominating_each_part_means_dominating_the_aggregate(c in clearance(), a in marking(), b in marking()) {
        let r = Registers::sample();
        if dominates(&c, &a, &r).is_ok() && dominates(&c, &b, &r).is_ok() {
            prop_assert!(dominates(&c, &a.max(&b), &r).is_ok(), "{:?} sees {} and {} but not their join", c, a, b);
        }
    }

    #[test]
    fn max_is_associative(a in marking(), b in marking(), c in marking()) {
        prop_assert_eq!(a.max(&b).max(&c), a.max(&b.max(&c)));
    }

    /// The soundness property the room-ceiling design rests on (§4.4).
    #[test]
    fn cleared_for_ceiling_implies_cleared_for_contents(c in clearance(), m in marking(), other in marking()) {
        // Build a ceiling that `m` is within, so the precondition isn't vacuous.
        let r = Registers::sample();
        let ceiling = m.max(&other);
        prop_assert!(m.within(&ceiling));
        if dominates(&c, &ceiling, &r).is_ok() {
            prop_assert!(dominates(&c, &m, &r).is_ok(), "{:?} dominates {} but not {}", c, ceiling, m);
        }
    }

    #[test]
    fn dominating_an_aggregate_means_dominating_each_part(c in clearance(), a in marking(), b in marking()) {
        let r = Registers::sample();
        if dominates(&c, &a.max(&b), &r).is_ok() {
            prop_assert!(dominates(&c, &a, &r).is_ok());
            prop_assert!(dominates(&c, &b, &r).is_ok());
        }
    }
}

/// The least clearance that dominates `ceiling`, with a citizenship drawn from its
/// releasability. Anything `within` the ceiling must be visible to this person.
fn minimal_clearance(ceiling: &Marking, pick: usize) -> Clearance {
    let citizenship = match ceiling.releasability() {
        Releasability::Unrestricted => CITIZEN[pick % CITIZEN.len()].to_owned(),
        Releasability::To(list) => {
            let v: Vec<&Country> = list.iter().collect();
            match v[pick % v.len()].as_str() {
                "FVEY" => "GBR".to_owned(),
                other => other.to_owned(),
            }
        }
    };
    Clearance::covering(
        ceiling,
        Country::new(&citizenship).unwrap_or_else(|_| Country::usa()),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// `within` must never admit a message that the ceiling's least-cleared member
    /// can't see. Candidates sit just past the ceiling (`ceiling.max(extra)`) or are
    /// unrelated, so a too-permissive `within` gets caught.
    #[test]
    fn within_is_sound_for_the_least_cleared_member(ceiling in marking(), extra in marking(), pick in 0usize..8) {
        let r = Registers::sample();
        let c = minimal_clearance(&ceiling, pick);
        prop_assert!(dominates(&c, &ceiling, &r).is_ok(), "minimal clearance must dominate {}", ceiling);
        for m in [ceiling.max(&extra), extra.clone()] {
            if m.within(&ceiling) {
                prop_assert!(dominates(&c, &m, &r).is_ok(), "{} within {} but hidden from {:?}", m, ceiling, c);
            }
        }
    }
}
