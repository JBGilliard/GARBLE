use std::fmt;

/// Every way a marking can be refused. Each variant has a stable code (`code()`)
/// that `policy` denials and the UI carry, so callers match on the variant, not the text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MarkingError {
    /// Empty input. Meridian parsed this as UNCLASSIFIED; GARBLE refuses it.
    Empty,
    EmptyToken,
    UnknownLevel(String),
    /// A token that is not a typed CAPCO control. Meridian accepted these as `Caveat::Other`.
    UnknownToken(String),
    OutOfOrder(String),
    BareSci,
    BareSar,
    SarSlash(String),
    /// Malformed `SYS-COMP SUB` structure.
    MalformedCompartment(String),
    UnknownSci(String),
    UnknownSar(String),
    InvalidCountry(String),
    UnknownCountry(String),
    RelToEmpty,
    /// CAPCO REL TO lists always name USA.
    RelToWithoutUsa,
    MultipleRelTo,
    NofornWithRelTo,
    /// SCI, SAR, AEA and FGI require a classified level.
    ControlsRequireClassified,
    UnknownCuiCategory(String),
    InvalidRegister(String),
    /// A count or length that does not fit the canonical encoding.
    TooLarge,
    UnsupportedEncoding(u8),
    Truncated,
    /// Bytes that decode but are not the canonical encoding (unsorted, duplicated, trailing).
    NonCanonical,
    EmptyAggregate,
}

impl MarkingError {
    /// Stable code for logs and UI denial objects. Never reuse a retired code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "M-001",
            Self::EmptyToken => "M-002",
            Self::UnknownLevel(_) => "M-003",
            Self::UnknownToken(_) => "M-004",
            Self::OutOfOrder(_) => "M-005",
            Self::BareSci => "M-006",
            Self::BareSar => "M-007",
            Self::SarSlash(_) => "M-008",
            Self::MalformedCompartment(_) => "M-009",
            Self::UnknownSci(_) => "M-010",
            Self::UnknownSar(_) => "M-011",
            Self::InvalidCountry(_) => "M-012",
            Self::UnknownCountry(_) => "M-013",
            Self::RelToEmpty => "M-014",
            Self::RelToWithoutUsa => "M-015",
            Self::MultipleRelTo => "M-016",
            Self::NofornWithRelTo => "M-017",
            Self::ControlsRequireClassified => "M-018",
            Self::UnknownCuiCategory(_) => "M-019",
            Self::InvalidRegister(_) => "M-020",
            Self::TooLarge => "M-021",
            Self::UnsupportedEncoding(_) => "M-022",
            Self::Truncated => "M-023",
            Self::NonCanonical => "M-024",
            Self::EmptyAggregate => "M-025",
        }
    }
}

impl fmt::Display for MarkingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.code())?;
        match self {
            Self::Empty => f.write_str("empty marking; every message must be marked"),
            Self::EmptyToken => f.write_str("empty token between '//'"),
            Self::UnknownLevel(s) => write!(f, "unknown classification level '{s}'"),
            Self::UnknownToken(s) => write!(f, "unknown or unsupported CAPCO token '{s}'"),
            Self::OutOfOrder(s) => write!(
                f,
                "CAPCO order is CLASSIFICATION // SCI // SAR // AEA // FGI // DISSEM; '{s}' is out of order"
            ),
            Self::BareSci => {
                f.write_str("bare SCI is not a control; use the designator (TK, not SCI)")
            }
            Self::BareSar => f.write_str("SAR requires a program identifier (SAR-<pid>)"),
            Self::SarSlash(s) => write!(f, "SAR uses hyphens, not slashes: '{s}'"),
            Self::MalformedCompartment(s) => write!(f, "malformed compartment structure '{s}'"),
            Self::UnknownSci(s) => write!(f, "SCI control '{s}' is not in the register"),
            Self::UnknownSar(s) => write!(f, "SAR program '{s}' is not in the register"),
            Self::InvalidCountry(s) => write!(f, "'{s}' is not a trigraph or tetragraph"),
            Self::UnknownCountry(s) => {
                write!(f, "country or collective '{s}' is not in the register")
            }
            Self::RelToEmpty => f.write_str("REL TO requires at least one country"),
            Self::RelToWithoutUsa => f.write_str("REL TO must include USA"),
            Self::MultipleRelTo => f.write_str("more than one REL TO in one marking"),
            Self::NofornWithRelTo => f.write_str("NOFORN and REL TO cannot both apply"),
            Self::ControlsRequireClassified => {
                f.write_str("SCI, SAR, AEA and FGI controls require a classified level")
            }
            Self::UnknownCuiCategory(s) => write!(f, "CUI category '{s}' is not in the register"),
            Self::InvalidRegister(s) => write!(f, "invalid register: {s}"),
            Self::TooLarge => f.write_str("marking too large to encode"),
            Self::UnsupportedEncoding(v) => write!(f, "unsupported canonical encoding format {v}"),
            Self::Truncated => f.write_str("canonical bytes truncated"),
            Self::NonCanonical => f.write_str("bytes are not the canonical encoding"),
            Self::EmptyAggregate => f.write_str("cannot aggregate zero markings"),
        }
    }
}

impl std::error::Error for MarkingError {}
