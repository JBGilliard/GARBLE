//! Strict CAPCO parser. Ported from Meridian `parse_inner` / `parse_token`
//! (marking.rs:535–603, 728–846) with the lenient paths removed: no empty-as-U,
//! no `Caveat::Other`, no register fallback, no legacy `SCI/` and `SAP/` prefixes,
//! no comma-separated SCI.

use std::collections::BTreeSet;

use crate::{
    Aea, Compartments, Country, CuiBlock, Dissem, Fgi, Level, Marking, MarkingError, Registers,
    tree_union, validate,
};

/// CAPCO slot order: CLASSIFICATION // SCI // SAR // AEA // FGI // DISSEM.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Slot {
    CuiCategories,
    Sci,
    Sar,
    Aea,
    Fgi,
    Dissem,
}

enum Token {
    Sci(Compartments),
    Sar(Compartments),
    Aea(Vec<Aea>),
    Fgi(Fgi),
    Dissem(Dissem),
    RelTo(BTreeSet<Country>),
}

impl Token {
    fn slot(&self) -> Slot {
        match self {
            Self::Sci(_) => Slot::Sci,
            Self::Sar(_) => Slot::Sar,
            Self::Aea(_) => Slot::Aea,
            Self::Fgi(_) => Slot::Fgi,
            Self::Dissem(_) | Self::RelTo(_) => Slot::Dissem,
        }
    }
}

/// Parse a portion (`TS//SI-G ABCD//NF`) or banner (`TOP SECRET//SI-G ABCD//NOFORN`)
/// marking. Fails closed on anything it does not fully understand.
pub fn parse(input: &str, reg: &Registers) -> Result<Marking, MarkingError> {
    let s = input.trim();
    let s = s
        .strip_prefix('(')
        .and_then(|x| x.strip_suffix(')'))
        .unwrap_or(s)
        .trim();
    if s.is_empty() {
        return Err(MarkingError::Empty);
    }
    let upper = s.to_ascii_uppercase();
    let mut segs = upper.split("//").map(str::trim);
    let head = segs.next().unwrap_or_default();

    let mut m = Marking::unclassified();
    if head == "CUI" {
        m.cui = Some(CuiBlock::default());
    } else {
        m.level = Level::parse(head).ok_or_else(|| MarkingError::UnknownLevel(head.to_owned()))?;
    }

    let mut last = Slot::CuiCategories;
    for (i, seg) in segs.enumerate() {
        if seg.is_empty() {
            return Err(MarkingError::EmptyToken);
        }
        // `CUI//CAT/CAT`: the category list may only follow the CUI head directly.
        if i == 0 && m.cui.is_some() && seg.split('/').all(|c| reg.cui().contains(c)) {
            if let Some(cui) = &mut m.cui {
                cui.categories = seg.split('/').map(str::to_owned).collect();
            }
            continue;
        }
        let tok = parse_token(seg, reg)?;
        let slot = tok.slot();
        if slot < last {
            return Err(MarkingError::OutOfOrder(seg.to_owned()));
        }
        last = slot;
        match tok {
            Token::Sci(t) => tree_union(&mut m.sci, &t),
            Token::Sar(t) => tree_union(&mut m.sap, &t),
            Token::Aea(a) => m.aea.extend(a),
            Token::Fgi(f) => m.fgi = crate::lattice::fgi_max(m.fgi.take(), Some(f)),
            Token::Dissem(d) => {
                m.dissem.insert(d);
            }
            Token::RelTo(list) => {
                if m.rel_to.replace(list).is_some() {
                    return Err(MarkingError::MultipleRelTo);
                }
            }
        }
    }
    validate(&m, reg)?;
    Ok(m)
}

fn parse_token(t: &str, reg: &Registers) -> Result<Token, MarkingError> {
    if t == "SAR" || t == "SAP" {
        return Err(MarkingError::BareSar);
    }
    if t == "SCI" {
        return Err(MarkingError::BareSci);
    }
    if let Some(rest) = t.strip_prefix("SAR-") {
        if rest.contains('/') {
            return Err(MarkingError::SarSlash(t.to_owned()));
        }
        return Ok(Token::Sar(parse_tree(rest)?));
    }
    if t == "FGI" {
        return Ok(Token::Fgi(Fgi::Concealed));
    }
    if let Some(code) = t.strip_prefix("FGI-") {
        // TODO-verify: CAPCO's acknowledged-FGI form (`FGI DEU GBR`) vs Meridian's `FGI-GBR`.
        return Ok(Token::Fgi(Fgi::Countries(BTreeSet::from([Country::new(
            code,
        )?]))));
    }
    match t {
        "RD" => return Ok(Token::Aea(vec![Aea::Rd])),
        "FRD" => return Ok(Token::Aea(vec![Aea::Frd])),
        "CNWDI" => return Ok(Token::Aea(vec![Aea::Cnwdi])),
        "RD-CNWDI" => return Ok(Token::Aea(vec![Aea::Rd, Aea::Cnwdi])),
        _ => {}
    }
    if let Some(d) = Dissem::from_token(t) {
        return Ok(Token::Dissem(d));
    }
    if let Some(list) = t.strip_prefix("REL TO").or_else(|| t.strip_prefix("REL ")) {
        let mut out = BTreeSet::new(); // sorted and deduped by construction
        for c in list.split(',').map(str::trim).filter(|c| !c.is_empty()) {
            out.insert(Country::new(c)?);
        }
        if out.is_empty() {
            return Err(MarkingError::RelToEmpty);
        }
        return Ok(Token::RelTo(out));
    }
    // SCI: `SYS[-COMP[ SUB…]]…` control systems separated by `/`. Decided by the
    // register, so a typo is an unknown token rather than a silently accepted caveat.
    let first_sys = t.split(['/', '-', ' ']).next().unwrap_or_default();
    if reg.knows_sci_system(first_sys) {
        let mut tree = Compartments::new();
        for part in t.split('/') {
            tree_union(&mut tree, &parse_tree(part.trim())?);
        }
        return Ok(Token::Sci(tree));
    }
    Err(MarkingError::UnknownToken(t.to_owned()))
}

/// `SYS-COMP SUB SUB-COMP2 SUB` → {SYS: {COMP: {SUB, SUB}, COMP2: {SUB}}}.
pub(crate) fn parse_tree(s: &str) -> Result<Compartments, MarkingError> {
    let malformed = || MarkingError::MalformedCompartment(s.to_owned());
    let mut pieces = s.split('-');
    let sys = pieces.next().unwrap_or_default();
    if !is_name(sys) {
        return Err(malformed());
    }
    let mut comps = std::collections::BTreeMap::new();
    for piece in pieces {
        let mut words = piece.split_whitespace();
        let comp = words.next().filter(|w| is_name(w)).ok_or_else(malformed)?;
        let subs: &mut BTreeSet<String> = comps.entry(comp.to_owned()).or_default();
        for w in words {
            if !is_name(w) {
                return Err(malformed());
            }
            subs.insert(w.to_owned());
        }
    }
    Ok(Compartments::from([(sys.to_owned(), comps)]))
}

fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}
