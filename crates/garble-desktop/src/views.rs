//! What crosses the webview boundary (architecture §7.1). Strings and numbers only:
//! no keys, no MLS state, no raw credentials, and markings arrive already rendered.

use client::{Denied, IntegrityAlert};
use markings::{Level, Marking};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Colors {
    pub bg: &'static str,
    pub fg: &'static str,
}

/// A marking as the user sees it. Also the banner: the high-water mark is a marking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MarkingView {
    pub portion: String,
    pub banner: String,
    pub level: &'static str,
    pub colors: Colors,
}

impl MarkingView {
    pub fn of(m: &Marking) -> Self {
        Self {
            portion: m.portion(),
            banner: m.banner(),
            level: m.level().portion(),
            colors: colors(m),
        }
    }
}

// The usual DoD banner colors. A UI convention, not CAPCO; TODO-verify against the
// site's style guide before anyone relies on yellow meaning "SCI".
fn colors(m: &Marking) -> Colors {
    match m.level() {
        Level::Unclassified => Colors {
            bg: "#007a33",
            fg: "#ffffff",
        },
        Level::Confidential => Colors {
            bg: "#0033a0",
            fg: "#ffffff",
        },
        Level::Secret => Colors {
            bg: "#c8102e",
            fg: "#ffffff",
        },
        Level::TopSecret if !m.sci().is_empty() => Colors {
            bg: "#f7ea48",
            fg: "#000000",
        },
        Level::TopSecret => Colors {
            bg: "#ff8c00",
            fg: "#000000",
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsgId {
    pub room: String,
    pub seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Message,
    Ack,
    /// Received, refused by this client's policy check. The body is never shown.
    Quarantined,
    /// Membership and ceiling changes, shown inline.
    Notice,
}

#[derive(Debug, Clone, Serialize)]
pub struct MessageView {
    pub id: MsgId,
    pub kind: Kind,
    pub sender: String,
    pub mine: bool,
    /// Set on messages and acks. Everything else has no marking and no say in the banner.
    pub marking: Option<MarkingView>,
    /// Message body, quarantine reason or notice text.
    pub text: String,
    pub forwarded_from: Option<String>,
    /// For an ack: the stream position it acknowledges, if we have that message.
    pub of: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Pass as `anchor` to get the page before this one. `None`: this is the start.
    pub older: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoomSummary {
    pub room: String,
    pub ceiling: MarkingView,
    pub members: Vec<String>,
    pub stewards: Vec<String>,
    pub unread: u64,
    pub last_seq: u64,
    pub held: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Verdict {
    Permit,
    /// Parses, but the room or the sender's attributes refuse it.
    Deny {
        code: String,
        reason: String,
    },
    /// Doesn't parse.
    Invalid {
        code: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct MarkingCheck {
    pub parsed: Option<MarkingView>,
    pub decision: Verdict,
}

#[derive(Debug, Clone, Serialize)]
pub struct WatermarkSpec {
    pub text: String,
    pub seed: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum InclusionView {
    Proven {
        size: u64,
        root: String,
    },
    /// The reader isn't cleared to see that log entry. It exists; they can't read it.
    Withheld,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub id: u64,
    pub at: u64,
    pub actor: String,
    pub room: String,
    pub event: String,
    pub decision: String,
    pub code: Option<String>,
    pub detail: String,
    pub marking: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DenialDetail {
    pub audit: String,
    pub entry: Option<LogLine>,
    pub inclusion: InclusionView,
}

/// A refusal on its way to the inspector. No `audit` means nothing logged it.
#[derive(Debug, Clone, Serialize)]
pub struct Denial {
    pub room: String,
    pub by: String,
    pub code: Option<String>,
    pub reason: String,
    pub audit: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CredentialState {
    Active { until: u64 },
    Expired { since: u64 },
    NotEnrolled,
}

/// Every command's error. A policy refusal is data, not a string (§7.1).
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UiError {
    Denied {
        by: String,
        code: String,
        reason: String,
        audit: String,
    },
    /// The DS's log failed a check. Sending is off; reading carries on.
    Integrity {
        reason: String,
    },
    Failed {
        message: String,
    },
}

impl From<anyhow::Error> for UiError {
    fn from(e: anyhow::Error) -> Self {
        if let Some(d) = e.downcast_ref::<Denied>() {
            return Self::Denied {
                by: d.by.into(),
                code: d.code.clone(),
                reason: d.reason.clone(),
                audit: d.audit.clone(),
            };
        }
        if let Some(IntegrityAlert(reason)) = e.downcast_ref::<IntegrityAlert>() {
            return Self::Integrity {
                reason: reason.clone(),
            };
        }
        Self::Failed {
            message: format!("{e:#}"),
        }
    }
}

impl UiError {
    pub fn failed(message: impl Into<String>) -> Self {
        Self::Failed {
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marking(s: &str) -> Marking {
        markings::parse(s, &markings::Registers::sample()).expect("parses")
    }

    #[test]
    fn refusals_stay_structured() {
        let e: anyhow::Error = Denied {
            by: "DS",
            code: "P-004".into(),
            reason: "no".into(),
            audit: "L-9".into(),
        }
        .into();
        let v = serde_json::to_value(UiError::from(e)).expect("serializes");
        assert_eq!(
            v,
            serde_json::json!({"kind":"denied","by":"DS","code":"P-004","reason":"no","audit":"L-9"})
        );
    }

    #[test]
    fn alerts_and_noise_are_told_apart() {
        let alert: anyhow::Error = IntegrityAlert("fork".into()).into();
        assert!(matches!(UiError::from(alert), UiError::Integrity { .. }));
        let other = anyhow::anyhow!("connection refused");
        assert!(matches!(UiError::from(other), UiError::Failed { .. }));
    }

    #[test]
    fn colors_follow_level_and_sci() {
        let c = |s| MarkingView::of(&marking(s)).colors.bg;
        assert_eq!(c("U"), "#007a33");
        assert_eq!(c("S//NF"), "#c8102e");
        assert_eq!(c("TS//NF"), "#ff8c00");
        assert_eq!(c("TS//SI//NF"), "#f7ea48");
    }
}
