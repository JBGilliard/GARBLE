//! Canonical encoding (format 1). This becomes a wire and log format in `proto`,
//! so it is versioned, length-checked (Meridian cast with `as u8` / `as u16`), and
//! decoding is strict: bytes must re-encode identically.
//!
//! ```text
//! u8  format = 1
//! u8  level
//! tree sci, tree sap          tree = u16 n, n × (str system, u16 m, m × (str comp, u16 k, k × str sub))
//! u16 n, n × u8 aea
//! u8  fgi: 0 none | 1 concealed | 2 countries (u16 n, n × str)
//! u16 n, n × u8 dissem
//! u8  rel: 0 | 1 (u16 n, n × str)
//! u8  cui: 0 | 1 (u16 n, n × str)
//! str = u16 len, bytes        all lists in BTreeSet order; integers big-endian
//! ```

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Aea, Compartments, Country, CuiBlock, Dissem, Fgi, Level, Marking, MarkingError, Registers,
    validate,
};

const FORMAT: u8 = 1;

impl Marking {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MarkingError> {
        let mut w = Vec::new();
        w.push(FORMAT);
        w.push(self.level as u8);
        put_tree(&mut w, &self.sci)?;
        put_tree(&mut w, &self.sap)?;
        put_len(&mut w, self.aea.len())?;
        w.extend(self.aea.iter().map(|a| *a as u8));
        match &self.fgi {
            None => w.push(0),
            Some(Fgi::Concealed) => w.push(1),
            Some(Fgi::Countries(cs)) => {
                w.push(2);
                put_strs(&mut w, cs.iter().map(Country::as_str), cs.len())?;
            }
        }
        put_len(&mut w, self.dissem.len())?;
        w.extend(self.dissem.iter().map(|d| *d as u8));
        match &self.rel_to {
            None => w.push(0),
            Some(r) => {
                w.push(1);
                put_strs(&mut w, r.iter().map(Country::as_str), r.len())?;
            }
        }
        match &self.cui {
            None => w.push(0),
            Some(c) => {
                w.push(1);
                put_strs(
                    &mut w,
                    c.categories.iter().map(String::as_str),
                    c.categories.len(),
                )?;
            }
        }
        Ok(w)
    }

    /// Decode and re-validate against `reg`. Rejects any byte string that is not
    /// exactly what `canonical_bytes` would produce.
    pub fn from_canonical(bytes: &[u8], reg: &Registers) -> Result<Marking, MarkingError> {
        let mut r = Reader(bytes);
        let format = r.u8()?;
        if format != FORMAT {
            return Err(MarkingError::UnsupportedEncoding(format));
        }
        let level = Level::from_u8(r.u8()?).ok_or(MarkingError::NonCanonical)?;
        let sci = r.tree()?;
        let sap = r.tree()?;
        let mut aea = BTreeSet::new();
        for _ in 0..r.u16()? {
            let v = r.u8()?;
            aea.insert(
                Aea::ALL
                    .into_iter()
                    .find(|a| *a as u8 == v)
                    .ok_or(MarkingError::NonCanonical)?,
            );
        }
        let fgi = match r.u8()? {
            0 => None,
            1 => Some(Fgi::Concealed),
            2 => Some(Fgi::Countries(r.countries()?)),
            _ => return Err(MarkingError::NonCanonical),
        };
        let mut dissem = BTreeSet::new();
        for _ in 0..r.u16()? {
            let v = r.u8()?;
            dissem.insert(
                Dissem::ALL
                    .into_iter()
                    .find(|d| *d as u8 == v)
                    .ok_or(MarkingError::NonCanonical)?,
            );
        }
        let rel_to = match r.u8()? {
            0 => None,
            1 => Some(r.countries()?),
            _ => return Err(MarkingError::NonCanonical),
        };
        let cui = match r.u8()? {
            0 => None,
            1 => Some(CuiBlock {
                categories: r.strs()?.into_iter().collect(),
            }),
            _ => return Err(MarkingError::NonCanonical),
        };
        let m = Marking {
            level,
            sci,
            sap,
            aea,
            fgi,
            dissem,
            rel_to,
            cui,
        };
        validate(&m, reg)?;
        if m.canonical_bytes()? != bytes {
            return Err(MarkingError::NonCanonical);
        }
        Ok(m)
    }
}

fn put_len(w: &mut Vec<u8>, n: usize) -> Result<(), MarkingError> {
    let n = u16::try_from(n).map_err(|_| MarkingError::TooLarge)?;
    w.extend_from_slice(&n.to_be_bytes());
    Ok(())
}

fn put_str(w: &mut Vec<u8>, s: &str) -> Result<(), MarkingError> {
    put_len(w, s.len())?;
    w.extend_from_slice(s.as_bytes());
    Ok(())
}

fn put_strs<'a>(
    w: &mut Vec<u8>,
    it: impl Iterator<Item = &'a str>,
    n: usize,
) -> Result<(), MarkingError> {
    put_len(w, n)?;
    it.into_iter().try_for_each(|s| put_str(w, s))
}

fn put_tree(w: &mut Vec<u8>, t: &Compartments) -> Result<(), MarkingError> {
    put_len(w, t.len())?;
    for (sys, comps) in t {
        put_str(w, sys)?;
        put_len(w, comps.len())?;
        for (comp, subs) in comps {
            put_str(w, comp)?;
            put_strs(w, subs.iter().map(String::as_str), subs.len())?;
        }
    }
    Ok(())
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], MarkingError> {
        if self.0.len() < n {
            return Err(MarkingError::Truncated);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, MarkingError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, MarkingError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn str(&mut self) -> Result<String, MarkingError> {
        let n = usize::from(self.u16()?);
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| MarkingError::NonCanonical)
    }
    fn strs(&mut self) -> Result<Vec<String>, MarkingError> {
        (0..self.u16()?).map(|_| self.str()).collect()
    }
    fn countries(&mut self) -> Result<BTreeSet<Country>, MarkingError> {
        self.strs()?.iter().map(|s| Country::new(s)).collect()
    }
    fn tree(&mut self) -> Result<Compartments, MarkingError> {
        let mut t = Compartments::new();
        for _ in 0..self.u16()? {
            let sys = self.str()?;
            let mut comps = BTreeMap::new();
            for _ in 0..self.u16()? {
                let comp = self.str()?;
                comps.insert(comp, self.strs()?.into_iter().collect());
            }
            t.insert(sys, comps);
        }
        Ok(t)
    }
}
