//! Unit tests. Part 1 ports Meridian's tests (marking.rs:849–1277), adapted where
//! GARBLE is stricter; each adaptation says why. Part 2 proves each fail-open fix
//! from architecture §4.1.1 now fails closed. Part 3 covers dominance and `within`.

use std::collections::{BTreeMap, BTreeSet};

use crate::*;

fn reg() -> Registers {
    Registers::sample()
}

fn p(s: &str) -> Marking {
    match parse(s, &reg()) {
        Ok(m) => m,
        Err(e) => panic!("{s}: {e}"),
    }
}

fn err(s: &str) -> MarkingError {
    match parse(s, &reg()) {
        Ok(m) => panic!("{s} parsed as {m}"),
        Err(e) => e,
    }
}

fn c(code: &str) -> Country {
    Country::new(code).unwrap()
}

fn tree(paths: &[&str]) -> Compartments {
    // "SI-G ABCD" style, via the parser's own grammar.
    let mut t = Compartments::new();
    for path in paths {
        tree_union(&mut t, &crate::parse::parse_tree(path).unwrap());
    }
    t
}

fn clearance(level: Level, sci: &[&str]) -> Clearance {
    Clearance {
        level,
        sci: tree(sci),
        sap: Compartments::new(),
        aea: BTreeSet::new(),
        fgi: false,
        citizenship: Country::usa(),
        dissem_grants: BTreeSet::new(),
        cui: BTreeSet::new(),
    }
}

// ───────────────────────── Part 1: ported from Meridian ─────────────────────────

#[test]
fn parse_and_display_portion() {
    let m = p("TS//TK//NOFORN");
    assert_eq!(m.level(), Level::TopSecret);
    assert_eq!(m.dissem(), &BTreeSet::from([Dissem::Noforn]));
    assert_eq!(m.sci(), &tree(&["TK"]));
    assert_eq!(m.to_string(), "TS//TK//NF");
    assert_eq!(m.portion(), "TS//TK//NF");
}

#[test]
fn banner_spells_out_level_and_dissem() {
    assert_eq!(p("TS//TK//NF").banner(), "TOP SECRET//TK//NOFORN");
    let s = p("S//REL TO USA,GBR");
    assert_eq!(s.banner(), "SECRET//REL TO USA,GBR");
    assert_eq!(s.portion(), "S//REL USA,GBR");
    assert_eq!(p("U").banner(), "UNCLASSIFIED");
}

#[test]
fn parse_portion_abbreviations() {
    assert_eq!(p("TS//TK//NF").dissem(), &BTreeSet::from([Dissem::Noforn]));
    assert_eq!(p("S//OC").dissem(), &BTreeSet::from([Dissem::Orcon]));
    assert_eq!(p("S//RS").dissem(), &BTreeSet::from([Dissem::Rsen]));
    assert_eq!(
        p("S//REL USA,GBR").rel_to(),
        Some(&BTreeSet::from([c("USA"), c("GBR")]))
    );
}

#[test]
fn parse_parenthesized_portion() {
    assert_eq!(p("(TS//TK//NF)").to_string(), "TS//TK//NF");
}

#[test]
fn parse_rel_to() {
    let m = p("S//REL TO USA,GBR");
    assert_eq!(m.to_string(), "S//REL USA,GBR");
    // Adapted: Meridian accepted `REL TO FVEY` alone; CAPCO lists always name USA.
    let fvey = p("S//REL TO USA,FVEY");
    assert_eq!(fvey.rel_to(), Some(&BTreeSet::from([c("USA"), c("FVEY")])));
    assert_eq!(err("S//REL TO FVEY"), MarkingError::RelToWithoutUsa);
}

#[test]
fn parse_hvsaco_and_waived() {
    let h = p("TS//TK//HVSACO");
    assert_eq!(h.dissem(), &BTreeSet::from([Dissem::Hvsaco]));
    assert_eq!(h.to_string(), "TS//TK//HVSACO");
    let w = p("TS//SAR-EXAMPLE//WAIVED//NOFORN");
    assert!(w.dissem().contains(&Dissem::Waived) && w.dissem().contains(&Dissem::Noforn));
    assert_eq!(w.to_string(), "TS//SAR-EXAMPLE//WAIVED//NF");
    // Distinct canonical tags: no collision.
    assert_ne!(
        p("TS//WAIVED").canonical_bytes(),
        p("TS//HVSACO").canonical_bytes()
    );
}

#[test]
fn parse_aea() {
    assert_eq!(p("TS//RD").aea(), &BTreeSet::from([Aea::Rd]));
    assert_eq!(
        p("TS//RD-CNWDI").aea(),
        &BTreeSet::from([Aea::Rd, Aea::Cnwdi])
    );
    assert_eq!(p("TS//RD//CNWDI").to_string(), "TS//RD//CNWDI");
    // Adapted: Meridian's `RD-FRD` is not a CAPCO marking (RD and FRD are separate).
    assert!(matches!(err("TS//RD-FRD"), MarkingError::UnknownToken(_)));
}

#[test]
fn parse_fgi() {
    let m = p("S//FGI");
    assert_eq!(m.fgi(), Some(&Fgi::Concealed));
    assert_eq!(m.to_string(), "S//FGI");
    let gbr = p("S//FGI-GBR");
    assert_eq!(gbr.fgi(), Some(&Fgi::Countries(BTreeSet::from([c("GBR")]))));
    assert_eq!(gbr.to_string(), "S//FGI-GBR");
    assert_eq!(gbr.banner(), "SECRET//FGI-GBR");
    assert_eq!(p("S//FGI-DEU//FGI-GBR").to_string(), "S//FGI-DEU//FGI-GBR");
}

#[test]
fn rejects_unknown_level() {
    assert_eq!(err("banana"), MarkingError::UnknownLevel("BANANA".into()));
}

#[test]
fn rejects_unknown_sci_designator() {
    assert!(matches!(err("TS//ZZZZ"), MarkingError::UnknownToken(_)));
    assert_eq!(err("TS//SI-ZZZ"), MarkingError::UnknownSci("SI-ZZZ".into()));
    assert_eq!(err("TS//SI/ZZZZ"), MarkingError::UnknownSci("ZZZZ".into()));
    // Adapted: legacy `SCI/<dg>` was accepted by Meridian's strict parse. No legacy rows here.
    assert!(matches!(err("TS//SCI/TK"), MarkingError::UnknownToken(_)));
}

#[test]
fn rejects_bare_sci_token() {
    assert_eq!(err("TS//SCI"), MarkingError::BareSci);
}

#[test]
fn rejects_unknown_sap_designator() {
    assert_eq!(err("TS//SAR-ZZZZ"), MarkingError::UnknownSar("ZZZZ".into()));
    assert_eq!(err("TS//SAR"), MarkingError::BareSar);
    // Adapted: legacy `SAP/<dg>` rejected.
    assert!(matches!(
        err("TS//SAP/SAMPLE"),
        MarkingError::UnknownToken(_)
    ));
    assert_eq!(p("TS//SAR-SAMPLE").to_string(), "TS//SAR-SAMPLE");
}

#[test]
fn parse_sar_hyphen_and_compartment() {
    let m = p("TS//TK//SAR-EXAMPLE-ONE//NOFORN");
    assert_eq!(m.sci(), &tree(&["TK"]));
    assert_eq!(m.sap(), &tree(&["EXAMPLE-ONE"]));
    assert_eq!(m.to_string(), "TS//TK//SAR-EXAMPLE-ONE//NF");
    assert_eq!(m.banner(), "TOP SECRET//TK//SAR-EXAMPLE-ONE//NOFORN");
    assert_eq!(
        err("TS//SAR-EXAMPLE/ONE"),
        MarkingError::SarSlash("SAR-EXAMPLE/ONE".into())
    );
}

#[test]
fn sar_not_grouped() {
    let m = p("TS//SAR-EXAMPLE//SAR-SAMPLE");
    assert_eq!(m.sap().len(), 2);
    // Programs render alphabetically (BTreeMap), each as its own token.
    assert_eq!(m.to_string(), "TS//SAR-EXAMPLE//SAR-SAMPLE");
}

#[test]
fn rejects_unknown_rel_to_country() {
    assert_eq!(
        err("S//REL TO USA,ZZZ"),
        MarkingError::UnknownCountry("ZZZ".into())
    );
    assert_eq!(err("S//REL TO "), MarkingError::RelToEmpty);
    assert_eq!(
        err("S//REL TO USA,GB"),
        MarkingError::InvalidCountry("GB".into())
    );
}

#[test]
fn parse_with_injected_registers() {
    let r = Registers::new(
        7,
        BTreeMap::from([("FOO".to_string(), BTreeMap::new())]),
        Compartments::new(),
        BTreeSet::from([c("USA")]),
        BTreeMap::new(),
        BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(r.version(), 7);
    assert!(parse("TS//FOO", &r).is_ok());
    assert!(parse("TS//TK", &r).is_err());
    assert!(parse("S//REL TO USA", &r).is_ok());
    assert!(parse("S//REL TO USA,GBR", &r).is_err());
}

#[test]
fn sample_registers_cover_samples() {
    let r = reg();
    for s in [
        "TS//TK",
        "TS//HCS-P",
        "TS//SI-G ABCD",
        "TS//SAR-EXAMPLE-ONE",
        "S//REL TO USA,GBR,CAN,AUS,NZL,FVEY",
    ] {
        assert!(parse(s, &r).is_ok(), "{s}");
    }
}

#[test]
fn strict_parse_rejects_out_of_order() {
    for s in [
        "TS//NOFORN//TK",
        "TS//NF//SAR-EXAMPLE",
        "TS//SAR-EXAMPLE//TK",
        "TS//FGI//SAR-EXAMPLE",
        "TS//NOFORN//CNWDI",
        "TS//FGI//TK",
        "TS//CNWDI//TK",
    ] {
        assert!(matches!(err(s), MarkingError::OutOfOrder(_)), "{s}");
    }
    assert!(parse("TS//TK//SAR-EXAMPLE//CNWDI//FGI//NOFORN", &reg()).is_ok());
}

#[test]
fn max_upgrades_by_aggregation() {
    let ts = p("TS//TK");
    let s_nf = p("S//NOFORN");
    let m = s_nf.max(&ts);
    assert_eq!(m.level(), Level::TopSecret);
    assert_eq!(m.to_string(), "TS//TK//NF");
    assert_eq!(aggregate([&s_nf, &ts]).unwrap(), m);
    // Adapted: CUI is orthogonal. TS//TK + CUI keeps the CUI block but renders as TS//TK.
    let with_cui = ts.max(&p("CUI"));
    assert_eq!(with_cui.to_string(), "TS//TK");
    assert!(with_cui.cui().is_some());
    assert_ne!(with_cui, ts);
}

#[test]
fn sci_systems_slash_separated_and_sorted() {
    assert_eq!(p("TS//TK/HCS").to_string(), "TS//HCS/TK");
    assert_eq!(p("TS//TK").max(&p("TS//HCS")).to_string(), "TS//HCS/TK");
    // Adapted: Meridian's comma form `TK,HCS` is not CAPCO.
    assert!(err("TS//TK,HCS").code().starts_with("M-"));
}

#[test]
fn sci_slash_form_round_trips() {
    let m = p("TS//SI/TK//NOFORN");
    assert_eq!(m.banner(), "TOP SECRET//SI/TK//NOFORN");
    assert_eq!(p(&m.banner()), m);
}

#[test]
fn same_program_slices_roll_up_into_one_sar() {
    let agg = aggregate(&[
        p("TS//SI//NF"),
        p("S//SAR-EXAMPLE-THREE//NF"),
        p("TS//TK//SAR-EXAMPLE-TWO//NF"),
    ])
    .unwrap();
    assert_eq!(
        agg.banner(),
        "TOP SECRET//SI/TK//SAR-EXAMPLE-THREE-TWO//NOFORN"
    );
    let agg = aggregate(&[
        p("TS//SAR-EXAMPLE"),
        p("TS//SAR-EXAMPLE-FOUR A1"),
        p("TS//SAR-EXAMPLE-FOUR A2-ONE"),
    ])
    .unwrap();
    assert_eq!(agg.to_string(), "TS//SAR-EXAMPLE-FOUR A1 A2-ONE");
}

#[test]
fn noforn_beats_rel_to_and_rel_lists_intersect() {
    let rel = p("S//REL TO USA,GBR,AUS");
    let rel2 = p("S//REL TO USA,GBR");
    let nf = p("S//NOFORN");
    assert_eq!(rel.max(&rel2).banner(), "SECRET//REL TO USA,GBR");
    assert_eq!(rel.max(&nf).banner(), "SECRET//NOFORN");
    assert_eq!(nf.max(&rel).banner(), "SECRET//NOFORN");
    assert_eq!(
        p("S//REL TO USA,CAN").max(&rel2).banner(),
        "SECRET//REL TO USA"
    );
}

#[test]
fn capco_order_on_display() {
    let m = p("TS//TK//SAR-EXAMPLE//CNWDI//FGI//NOFORN");
    assert_eq!(m.to_string(), "TS//TK//SAR-EXAMPLE//CNWDI//FGI//NF");
    assert_eq!(
        m.banner(),
        "TOP SECRET//TK//SAR-EXAMPLE//CNWDI//FGI//NOFORN"
    );
}

#[test]
fn rel_to_lists_render_usa_first_then_trigraphs_then_tetragraphs() {
    assert_eq!(
        p("S//REL TO NZL,FVEY,GBR,USA").banner(),
        "SECRET//REL TO USA,GBR,NZL,FVEY"
    );
}

// ───────────────────── Part 2: §4.1.1 fail-open fixes, now closed ─────────────────────

#[test]
fn fix1_empty_input_is_refused_not_unclassified() {
    for s in ["", "   ", "()", "( )"] {
        assert_eq!(err(s), MarkingError::Empty, "{s:?}");
    }
    assert_eq!(err("S//"), MarkingError::EmptyToken);
}

#[test]
fn fix2_no_register_fallback() {
    // `parse` takes the register as a required argument; there is no global default.
    // An empty register knows no controls, so anything beyond a bare level fails closed.
    let empty = Registers::new(
        0,
        Compartments::new(),
        Compartments::new(),
        BTreeSet::new(),
        BTreeMap::new(),
        BTreeSet::new(),
    )
    .unwrap();
    assert!(parse("TS", &empty).is_ok());
    assert!(matches!(
        parse("TS//TK", &empty),
        Err(MarkingError::UnknownToken(_))
    ));
    assert!(matches!(
        parse("S//REL TO USA", &empty),
        Err(MarkingError::UnknownCountry(_))
    ));
    assert!(matches!(
        parse("TS//SAR-EXAMPLE", &empty),
        Err(MarkingError::UnknownSar(_))
    ));
}

#[test]
fn fix3_fgi_and_aea_designators_are_checked() {
    assert_eq!(
        err("S//FGI-ZZZ"),
        MarkingError::UnknownCountry("ZZZ".into())
    );
    assert_eq!(err("S//FGI-GB"), MarkingError::InvalidCountry("GB".into()));
    assert!(matches!(err("TS//CNWDI/X"), MarkingError::UnknownToken(_)));
    assert!(matches!(
        err("TS//RD-SIGMA 14"),
        MarkingError::UnknownToken(_)
    ));
}

#[test]
fn fix4_unknown_caveats_are_refused_and_dissem_set_grew() {
    assert_eq!(
        err("TS//BANANA"),
        MarkingError::UnknownToken("BANANA".into())
    );
    assert_eq!(
        err("S//NF//FOUO-ISH"),
        MarkingError::UnknownToken("FOUO-ISH".into())
    );
    let m = p("S//IMCON//NOFORN//PROPIN//RELIDO//LIMDIS//EXDIS//NODIS");
    assert_eq!(m.to_string(), "S//IMC//NF//PR//RELIDO//DS//XD//ND");
    assert_eq!(p(&m.banner()), m);
}

#[test]
fn fix5_equality_hash_and_encoding_ignore_input_order() {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let hash = |m: &Marking| {
        let mut h = DefaultHasher::new();
        m.hash(&mut h);
        h.finish()
    };
    let pairs = [
        ("S//REL TO USA,GBR", "S//REL TO GBR,USA"),
        ("S//REL TO USA,GBR,GBR", "S//REL TO USA,GBR"),
        ("TS//TK/SI", "TS//SI/TK"),
        ("S//OC//NF", "S//NF//OC"),
        ("TS//SI-G EFGH ABCD", "TS//SI-G ABCD EFGH"),
    ];
    for (a, b) in pairs {
        let (a, b) = (p(a), p(b));
        assert_eq!(a, b);
        assert_eq!(hash(&a), hash(&b));
        assert_eq!(a.canonical_bytes().unwrap(), b.canonical_bytes().unwrap());
    }
}

#[test]
fn fix6_cui_is_orthogonal_and_encoding_is_versioned() {
    let cui = p("CUI");
    assert_eq!(cui.level(), Level::Unclassified);
    assert_eq!(cui.cui(), Some(&CuiBlock::default()));
    assert_eq!(cui.to_string(), "CUI");
    let cats = p("CUI//SP-PRVCY/CTI");
    assert_eq!(cats.to_string(), "CUI//CTI/SP-PRVCY");
    assert_eq!(
        err("CUI//SP-NOPE"),
        MarkingError::UnknownToken("SP-NOPE".into())
    );
    // Level discriminants and the format byte are pinned.
    let b = p("TS").canonical_bytes().unwrap();
    assert_eq!((b[0], b[1]), (1, 3));
    assert_eq!(Level::Unclassified as u8, 0);
}

#[test]
fn fix7_sci_is_structured() {
    let m = p("TS//SI-G ABCD EFGH/TK");
    let expected: Compartments = BTreeMap::from([
        (
            "SI".to_string(),
            BTreeMap::from([(
                "G".to_string(),
                BTreeSet::from(["ABCD".to_string(), "EFGH".to_string()]),
            )]),
        ),
        ("TK".to_string(), BTreeMap::new()),
    ]);
    assert_eq!(m.sci(), &expected);
    assert_eq!(m.to_string(), "TS//SI-G ABCD EFGH/TK");
    assert_eq!(
        err("TS//SI-G WXYZ"),
        MarkingError::UnknownSci("SI-G WXYZ".into())
    );
    // Access to SI-G implies SI; access to SI does not imply SI-G.
    let r = reg();
    let si_g = clearance(Level::TopSecret, &["SI-G"]);
    assert!(dominates(&si_g, &p("TS//SI//NF"), &r).is_ok());
    assert!(dominates(&si_g, &p("TS//SI-G//NF"), &r).is_ok());
    let gap = dominates(&si_g, &p("TS//SI-G ABCD//NF"), &r).unwrap_err();
    assert_eq!(gap.sci, tree(&["SI-G ABCD"]));
    let si = clearance(Level::TopSecret, &["SI"]);
    assert_eq!(
        dominates(&si, &p("TS//SI-G//NF"), &r).unwrap_err().sci,
        tree(&["SI-G"])
    );
}

#[test]
fn fix8_rel_to_with_unmarked_classified_part_becomes_noforn() {
    let rel = p("S//REL TO USA,GBR");
    // TODO-verify against CAPCO (§4.1.1 item 8).
    assert_eq!(rel.max(&p("S")).to_string(), "S//NF");
    assert_eq!(p("C").max(&rel).to_string(), "S//NF");
    // An unclassified part carries no foreign-disclosure restriction.
    assert_eq!(rel.max(&p("U")).to_string(), "S//REL USA,GBR");
    // Two unmarked classified parts stay unmarked (implicitly not releasable).
    assert_eq!(p("S").max(&p("C")).to_string(), "S");
}

#[test]
fn fix9_errors_are_typed_with_stable_codes() {
    assert_eq!(err("").code(), "M-001");
    assert_eq!(err("TS//BANANA").code(), "M-004");
    assert_eq!(err("TS//NF//TK").code(), "M-005");
    assert!(err("TS//BANANA").to_string().starts_with("M-004: "));
}

// ─────────────────── Locked §4.1 changes not covered above ───────────────────

#[test]
fn noforn_and_rel_to_cannot_coexist() {
    assert_eq!(err("S//NF//REL TO USA,GBR"), MarkingError::NofornWithRelTo);
    assert_eq!(
        err("S//REL TO USA//REL TO USA,GBR"),
        MarkingError::MultipleRelTo
    );
}

#[test]
fn controls_require_a_classified_level() {
    for s in ["U//TK", "U//SAR-EXAMPLE", "U//RD", "U//FGI"] {
        assert_eq!(err(s), MarkingError::ControlsRequireClassified, "{s}");
    }
}

#[test]
fn canonical_decoding_is_strict() {
    let r = reg();
    let m = p("TS//SI-G ABCD//SAR-EXAMPLE-FOUR A1//FGI-GBR//OC//REL TO USA,GBR");
    let b = m.canonical_bytes().unwrap();
    assert_eq!(Marking::from_canonical(&b, &r).unwrap(), m);

    let mut v2 = b.clone();
    v2[0] = 2;
    assert_eq!(
        Marking::from_canonical(&v2, &r),
        Err(MarkingError::UnsupportedEncoding(2))
    );
    assert_eq!(
        Marking::from_canonical(&b[..b.len() - 1], &r),
        Err(MarkingError::Truncated)
    );
    let mut trailing = b.clone();
    trailing.push(0);
    assert_eq!(
        Marking::from_canonical(&trailing, &r),
        Err(MarkingError::NonCanonical)
    );
    assert_eq!(
        Marking::from_canonical(&[], &r),
        Err(MarkingError::Truncated)
    );

    // Same REL TO list in non-sorted order: decodes to the same set, fails re-encoding.
    let sorted = p("S//REL TO USA,GBR").canonical_bytes().unwrap();
    let tail = sorted.len() - 1 - 2 * 5; // strip 2 × (u16 len + 3 bytes) and the cui flag
    let mut swapped = sorted[..tail].to_vec();
    swapped.extend([0, 3, b'U', b'S', b'A', 0, 3, b'G', b'B', b'R', 0]);
    assert_eq!(
        Marking::from_canonical(&swapped, &r),
        Err(MarkingError::NonCanonical)
    );

    // Bytes that are valid structure but name something the register doesn't know.
    let other = Registers::new(
        1,
        Compartments::new(),
        Compartments::new(),
        BTreeSet::from([c("USA")]),
        BTreeMap::new(),
        BTreeSet::new(),
    )
    .unwrap();
    assert!(matches!(
        Marking::from_canonical(&b, &other),
        Err(MarkingError::UnknownSci(_))
    ));
}

#[test]
fn canonical_lengths_are_checked_not_truncated() {
    let mut m = p("TS");
    for i in 0..=u16::MAX as u32 {
        m.sci.insert(format!("S{i}"), BTreeMap::new());
    }
    assert_eq!(m.canonical_bytes(), Err(MarkingError::TooLarge));
}

#[test]
fn aggregate_of_nothing_is_an_error() {
    assert_eq!(aggregate(&[]), Err(MarkingError::EmptyAggregate));
}

// ───────────────────────── Part 3: dominance and within ─────────────────────────

#[test]
fn dominates_reports_every_gap_at_once() {
    let r = reg();
    let mut c = clearance(Level::Secret, &["TK"]);
    c.citizenship = Country::new("GBR").unwrap();
    let m = p("TS//SI/TK//SAR-EXAMPLE//RD//FGI//OC//NF");
    let s = dominates(&c, &m, &r).unwrap_err();
    assert_eq!(s.level, Some(Level::TopSecret));
    assert_eq!(s.sci, tree(&["SI"]));
    assert_eq!(s.sap, tree(&["EXAMPLE"]));
    assert_eq!(s.aea, BTreeSet::from([Aea::Rd]));
    assert!(s.fgi);
    assert_eq!(s.dissem, BTreeSet::from([Dissem::Orcon]));
    assert_eq!(
        s.releasability,
        Some(Releasability::To(BTreeSet::from([Country::usa()])))
    );
}

#[test]
fn rel_to_collectives_expand_for_dominance() {
    let r = reg();
    let mut gbr = clearance(Level::Secret, &[]);
    gbr.citizenship = c("GBR");
    assert!(dominates(&gbr, &p("S//REL TO USA,FVEY"), &r).is_ok());
    assert!(dominates(&gbr, &p("S//REL TO USA,GBR"), &r).is_ok());
    assert!(dominates(&gbr, &p("S//REL TO USA,AUS"), &r).is_err());
    assert!(dominates(&gbr, &p("S//NF"), &r).is_err());
    // Implicit: a classified marking with no foreign-disclosure control is US-only.
    assert!(dominates(&gbr, &p("S"), &r).is_err());
    assert!(dominates(&gbr, &p("U"), &r).is_ok());
}

#[test]
fn grants_needed_for_restricting_dissem_but_not_relido() {
    let r = reg();
    let mut c = clearance(Level::Secret, &[]);
    assert!(dominates(&c, &p("S//RELIDO"), &r).is_ok());
    assert!(dominates(&c, &p("S//OC"), &r).is_err());
    c.dissem_grants.insert(Dissem::Orcon);
    assert!(dominates(&c, &p("S//OC"), &r).is_ok());
}

#[test]
fn cui_categories_need_grants() {
    let r = reg();
    let mut c = clearance(Level::Unclassified, &[]);
    assert!(dominates(&c, &p("CUI"), &r).is_ok());
    assert_eq!(
        dominates(&c, &p("CUI//SP-PRVCY"), &r).unwrap_err().cui,
        BTreeSet::from(["SP-PRVCY".to_string()])
    );
    c.cui.insert("SP-PRVCY".into());
    assert!(dominates(&c, &p("CUI//SP-PRVCY"), &r).is_ok());
}

#[test]
fn within_room_ceilings() {
    let ceiling = p("TS//SI-G/TK//REL TO USA,GBR");
    assert!(p("TS//SI-G//REL TO USA,GBR").within(&ceiling));
    assert!(p("S//TK//REL TO USA,GBR,AUS").within(&ceiling));
    assert!(p("U").within(&ceiling));
    assert!(
        !p("TS//SI-G ABCD//REL TO USA,GBR").within(&ceiling),
        "sub-compartment above ceiling"
    );
    assert!(
        !p("TS//HCS//REL TO USA,GBR").within(&ceiling),
        "system above ceiling"
    );
    assert!(
        !p("TS//TK//NF").within(&ceiling),
        "NOFORN would reach GBR members"
    );
    assert!(
        !p("S").within(&ceiling),
        "unmarked classified is not releasable (item 8)"
    );
    assert!(
        !p("S//REL TO USA,GBR//OC").within(&ceiling),
        "ORCON not covered by ceiling"
    );
    assert!(p("TS//TK//NF").within(&p("TS//TK//NF")));
}

#[test]
fn shortfall_reads_as_a_sentence() {
    let s = dominates(
        &clearance(Level::Secret, &["SI"]),
        &p("TS//SI/TK//NF"),
        &reg(),
    )
    .unwrap_err();
    assert_eq!(s.to_string(), "missing level TS; SCI TK");
}
