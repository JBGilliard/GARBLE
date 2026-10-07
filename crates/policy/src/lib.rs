//! The only place access decisions are made (architecture §3, §4.4.1).
//!
//! Pure and deterministic: no I/O, no clock, no randomness, no crypto. Callers pass
//! *verified* inputs; time enters as `Subject::as_of`. The same code runs in clients
//! and in the delivery service.
//!
//! ponytail: covers Create, Add, Remove, Send, ReadArchive and ReadLog. Policy changes, cards and proposal
//! allow-listing (§4.4.2) come with the features that need them.

use std::fmt;

use markings::{Clearance, Marking, Registers, Shortfall, dominates};

pub const POLICY_VERSION: u32 = 1;

/// Someone acting, or being acted on, with attributes already signature-checked.
#[derive(Debug, Clone)]
pub struct Subject {
    pub user: String,
    pub clearance: Clearance,
    /// Attribute credential expiry, seconds since the Unix epoch.
    pub valid_until: u64,
    /// Decision time, seconds since the Unix epoch.
    pub as_of: u64,
}

pub enum Resource<'a> {
    Room {
        ceiling: &'a Marking,
        stewards: &'a [String],
        /// The room's records custodian, if its policy names one.
        custodian: Option<&'a str>,
        records_officers: &'a [String],
        registers: &'a Registers,
    },
    /// The audit log: not a room, since user events live in it too. Only
    /// `Action::ReadLog` applies.
    Log { registers: &'a Registers },
}

pub enum Action<'a> {
    Create,
    /// The invitee's own check on a Welcome (idea-v1 §1a, check 4): refuse to join a
    /// room you aren't cleared for, however you were added.
    Join,
    Add {
        joiner: &'a Subject,
    },
    /// Remove `target`: a deliberate act by a steward (debrief, clearance loss,
    /// compromise, cleanup). Expiry alone suspends, it never removes (idea-v1 §1).
    Remove {
        target: &'a str,
    },
    Send {
        marking: &'a Marking,
    },
    /// Ask the custodian to open the room's archive. The permit is what gets logged;
    /// the custodian still needs its offline key to act on it.
    ReadArchive,
    /// Read an audit-log entry carrying `marking` (idea-v1 §1: no world-readable log).
    ReadLog {
        marking: &'a Marking,
    },
    /// Change the room ceiling. Raising it (or moving it sideways) requires every
    /// member to be cleared for the new one; lowering it doesn't.
    SetCeiling {
        new: &'a Marking,
        members: &'a [Subject],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Permit,
    Deny(DenyReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DenyReason {
    ClearanceShortfall {
        user: String,
        shortfall: Box<Shortfall>,
    },
    AttributesExpired {
        user: String,
        at: u64,
    },
    AboveCeiling {
        marking: String,
        ceiling: String,
    },
    NotSteward {
        user: String,
    },
    SapRoomsUnsupported,
    NoCustodian,
    NotRecordsOfficer {
        user: String,
    },
    /// The caller paired an action with a resource it doesn't apply to. A bug, and
    /// denied rather than guessed at.
    ResourceMismatch,
}

impl DenyReason {
    /// Stable code carried by log entries and UI denial objects.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ClearanceShortfall { .. } => "P-001",
            Self::AttributesExpired { .. } => "P-002",
            Self::AboveCeiling { .. } => "P-003",
            Self::NotSteward { .. } => "P-004",
            Self::SapRoomsUnsupported => "P-005",
            Self::NoCustodian => "P-006",
            Self::NotRecordsOfficer { .. } => "P-007",
            Self::ResourceMismatch => "P-008",
        }
    }
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The code travels separately (`code()`), so it is not repeated here.
        match self {
            Self::ClearanceShortfall { user, shortfall } => {
                write!(f, "{user} is not cleared: {shortfall}")
            }
            Self::AttributesExpired { user, at } => {
                write!(f, "{user}'s attributes expired at {at}")
            }
            Self::AboveCeiling { marking, ceiling } => {
                write!(f, "{marking} is above the room ceiling {ceiling}")
            }
            Self::NotSteward { user } => write!(f, "{user} is not a steward of this room"),
            Self::SapRoomsUnsupported => f.write_str("SAP rooms are not supported in v1"),
            Self::NoCustodian => f.write_str("the room names no records custodian"),
            Self::NotRecordsOfficer { user } => {
                write!(f, "{user} is not a records officer of this room")
            }
            Self::ResourceMismatch => f.write_str("action does not apply to this resource"),
        }
    }
}

pub fn decide(subject: &Subject, resource: &Resource, action: &Action) -> Decision {
    match check(subject, resource, action) {
        Ok(()) => Decision::Permit,
        Err(reason) => Decision::Deny(reason),
    }
}

fn check(subject: &Subject, resource: &Resource, action: &Action) -> Result<(), DenyReason> {
    let Resource::Room {
        ceiling,
        stewards,
        custodian,
        records_officers,
        registers,
    } = resource
    else {
        let (Resource::Log { registers }, Action::ReadLog { marking }) = (resource, action) else {
            return Err(DenyReason::ResourceMismatch);
        };
        valid(subject)?;
        return cleared(subject, marking, registers);
    };
    // Expiry suspends (idea-v1 §1). It refuses every act except joining: a suspended
    // invitee may join, and the DS withholds content until it refreshes.
    if !matches!(action, Action::Join) {
        valid(subject)?;
    }
    match action {
        Action::Create => {
            steward(subject, stewards)?;
            if custodian.is_none() {
                return Err(DenyReason::NoCustodian);
            }
            if !ceiling.sap().is_empty() {
                return Err(DenyReason::SapRoomsUnsupported);
            }
            cleared(subject, ceiling, registers)
        }
        Action::ReadArchive => {
            if !records_officers.contains(&subject.user) {
                return Err(DenyReason::NotRecordsOfficer {
                    user: subject.user.clone(),
                });
            }
            cleared(subject, ceiling, registers)
        }
        Action::Join => cleared(subject, ceiling, registers),
        Action::ReadLog { .. } => Err(DenyReason::ResourceMismatch),
        Action::Add { joiner } => {
            steward(subject, stewards)?;
            valid(joiner)?;
            cleared(joiner, ceiling, registers)
        }
        Action::Remove { .. } => steward(subject, stewards),
        Action::SetCeiling { new, members } => {
            steward(subject, stewards)?;
            if !new.sap().is_empty() {
                return Err(DenyReason::SapRoomsUnsupported);
            }
            if !new.within(ceiling) {
                // Clearance, not freshness: a suspended member is still a member.
                members
                    .iter()
                    .try_for_each(|m| cleared(m, new, registers))?;
            }
            Ok(())
        }
        Action::Send { marking } => {
            if !marking.within(ceiling) {
                return Err(DenyReason::AboveCeiling {
                    marking: marking.portion(),
                    ceiling: ceiling.portion(),
                });
            }
            cleared(subject, marking, registers)
        }
    }
}

fn valid(s: &Subject) -> Result<(), DenyReason> {
    if s.as_of < s.valid_until {
        Ok(())
    } else {
        Err(DenyReason::AttributesExpired {
            user: s.user.clone(),
            at: s.valid_until,
        })
    }
}

fn steward(s: &Subject, stewards: &[String]) -> Result<(), DenyReason> {
    if stewards.contains(&s.user) {
        Ok(())
    } else {
        Err(DenyReason::NotSteward {
            user: s.user.clone(),
        })
    }
}

fn cleared(s: &Subject, m: &Marking, reg: &Registers) -> Result<(), DenyReason> {
    dominates(&s.clearance, m, reg).map_err(|shortfall| DenyReason::ClearanceShortfall {
        user: s.user.clone(),
        shortfall,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use markings::{Country, parse};

    fn reg() -> Registers {
        Registers::sample()
    }

    fn who(user: &str, access: &str, valid_until: u64) -> Subject {
        let access = parse(access, &reg()).unwrap();
        Subject {
            user: user.into(),
            clearance: Clearance::covering(&access, Country::usa()),
            valid_until,
            as_of: 100,
        }
    }

    fn room<'a>(ceiling: &'a Marking, stewards: &'a [String], reg: &'a Registers) -> Resource<'a> {
        Resource::Room {
            ceiling,
            stewards,
            custodian: Some("records"),
            records_officers: &[],
            registers: reg,
        }
    }

    #[test]
    fn add_refuses_joiner_missing_a_compartment() {
        let (r, ceiling) = (reg(), parse("TS//SI/TK//NF", &reg()).unwrap());
        let stewards = ["alice".to_string()];
        let alice = who("alice", "TS//SI/TK//NF", 200);
        let bob = who("bob", "TS//SI//NF", 200);
        let carol = who("carol", "TS//SI/TK//NF", 200);
        let res = room(&ceiling, &stewards, &r);
        let Decision::Deny(DenyReason::ClearanceShortfall { user, shortfall }) =
            decide(&alice, &res, &Action::Add { joiner: &bob })
        else {
            panic!("bob should be refused");
        };
        assert_eq!(user, "bob");
        assert_eq!(shortfall.to_string(), "missing SCI TK");
        assert_eq!(
            decide(&alice, &res, &Action::Add { joiner: &carol }),
            Decision::Permit
        );
        // Only stewards add.
        assert!(matches!(
            decide(&carol, &res, &Action::Add { joiner: &alice }),
            Decision::Deny(DenyReason::NotSteward { .. })
        ));
    }

    #[test]
    fn expired_attributes_deny_everything() {
        let (r, ceiling) = (reg(), parse("S", &reg()).unwrap());
        let stewards = ["alice".to_string()];
        let stale = who("alice", "TS", 100); // valid_until == as_of: expired
        let res = room(&ceiling, &stewards, &r);
        for action in [Action::Create, Action::Send { marking: &ceiling }] {
            assert!(matches!(
                decide(&stale, &res, &action),
                Decision::Deny(DenyReason::AttributesExpired { .. })
            ));
        }
    }

    #[test]
    fn send_checks_ceiling_then_sender() {
        let (r, ceiling) = (reg(), parse("TS//SI/TK//NF", &reg()).unwrap());
        let res = room(&ceiling, &[], &r);
        let alice = who("alice", "TS//SI//NF", 200);
        let ok = parse("TS//SI//NF", &r).unwrap();
        let above = parse("TS//HCS//NF", &r).unwrap();
        let not_cleared = parse("TS//TK//NF", &r).unwrap();
        assert_eq!(
            decide(&alice, &res, &Action::Send { marking: &ok }),
            Decision::Permit
        );
        assert!(matches!(
            decide(&alice, &res, &Action::Send { marking: &above }),
            Decision::Deny(DenyReason::AboveCeiling { .. })
        ));
        assert!(matches!(
            decide(
                &alice,
                &res,
                &Action::Send {
                    marking: &not_cleared
                }
            ),
            Decision::Deny(DenyReason::ClearanceShortfall { .. })
        ));
    }

    #[test]
    fn invitee_refuses_a_room_above_its_clearance() {
        let (r, ceiling) = (reg(), parse("TS//SI/TK//NF", &reg()).unwrap());
        let res = room(&ceiling, &[], &r);
        assert!(matches!(
            decide(&who("bob", "TS//SI//NF", 200), &res, &Action::Join),
            Decision::Deny(DenyReason::ClearanceShortfall { .. })
        ));
        assert_eq!(
            decide(&who("carol", "TS//SI/TK//NF", 200), &res, &Action::Join),
            Decision::Permit
        );
        // Expired but cleared: joins (suspended), it isn't refused.
        assert_eq!(
            decide(&who("dave", "TS//SI/TK//NF", 100), &res, &Action::Join),
            Decision::Permit
        );
    }

    #[test]
    fn raising_the_ceiling_needs_every_member_cleared() {
        let (r, ceiling) = (reg(), parse("TS//SI//NF", &reg()).unwrap());
        let stewards = ["alice".to_string()];
        let res = room(&ceiling, &stewards, &r);
        let alice = who("alice", "TS//SI/TK//NF", 200);
        let higher = parse("TS//SI/TK//NF", &r).unwrap();
        let lower = parse("S//NF", &r).unwrap();
        let carol_tk = [who("carol", "TS//SI/TK//NF", 200)];
        let bob_no_tk = [who("bob", "TS//SI//NF", 200)];
        let set = |new, members| Action::SetCeiling { new, members };
        assert_eq!(
            decide(&alice, &res, &set(&higher, &carol_tk)),
            Decision::Permit
        );
        assert!(matches!(
            decide(&alice, &res, &set(&higher, &bob_no_tk)),
            Decision::Deny(DenyReason::ClearanceShortfall { .. })
        ));
        assert_eq!(
            decide(&alice, &res, &set(&lower, &bob_no_tk)),
            Decision::Permit
        );
        assert!(matches!(
            decide(&bob_no_tk[0], &res, &set(&lower, &[])),
            Decision::Deny(DenyReason::NotSteward { .. })
        ));
    }

    #[test]
    fn only_stewards_remove() {
        let (r, ceiling) = (reg(), parse("TS//SI/TK//NF", &reg()).unwrap());
        let stewards = ["alice".to_string()];
        let res = room(&ceiling, &stewards, &r);
        let alice = who("alice", "TS//SI/TK//NF", 200);
        let carol = who("carol", "TS//SI/TK//NF", 200);
        let remove = Action::Remove { target: "dave" };
        assert_eq!(decide(&alice, &res, &remove), Decision::Permit);
        assert!(matches!(
            decide(&carol, &res, &remove),
            Decision::Deny(DenyReason::NotSteward { .. })
        ));
        // A steward whose own attributes expired is suspended too.
        let stale = who("alice", "TS//SI/TK//NF", 100);
        assert!(matches!(
            decide(&stale, &res, &remove),
            Decision::Deny(DenyReason::AttributesExpired { .. })
        ));
    }

    #[test]
    fn create_needs_a_custodian() {
        let (r, ceiling) = (reg(), parse("S", &reg()).unwrap());
        let stewards = ["alice".to_string()];
        let alice = who("alice", "S", 200);
        let mut res = room(&ceiling, &stewards, &r);
        assert_eq!(decide(&alice, &res, &Action::Create), Decision::Permit);
        let Resource::Room { custodian, .. } = &mut res else {
            unreachable!()
        };
        *custodian = None;
        assert_eq!(
            decide(&alice, &res, &Action::Create),
            Decision::Deny(DenyReason::NoCustodian)
        );
    }

    #[test]
    fn archive_reads_need_a_cleared_records_officer() {
        let (r, ceiling) = (reg(), parse("TS//SI/TK//NF", &reg()).unwrap());
        let officers = ["olga".to_string(), "otto".to_string()];
        let res = Resource::Room {
            ceiling: &ceiling,
            stewards: &[],
            custodian: Some("records"),
            records_officers: &officers,
            registers: &r,
        };
        let read = Action::ReadArchive;
        assert_eq!(
            decide(&who("olga", "TS//SI/TK//NF", 200), &res, &read),
            Decision::Permit
        );
        // Listed, but not cleared for the room: the archive holds everything in it.
        assert!(matches!(
            decide(&who("otto", "TS//SI//NF", 200), &res, &read),
            Decision::Deny(DenyReason::ClearanceShortfall { .. })
        ));
        // Cleared, but not listed.
        assert!(matches!(
            decide(&who("carol", "TS//SI/TK//NF", 200), &res, &read),
            Decision::Deny(DenyReason::NotRecordsOfficer { .. })
        ));
        assert!(matches!(
            decide(&who("olga", "TS//SI/TK//NF", 100), &res, &read),
            Decision::Deny(DenyReason::AttributesExpired { .. })
        ));
    }

    #[test]
    fn log_entries_need_clearance_for_their_marking() {
        let r = reg();
        let res = Resource::Log { registers: &r };
        let tk = parse("TS//SI/TK//NF", &r).unwrap();
        let si = parse("TS//SI//NF", &r).unwrap();
        let read = |who: &Subject, m| decide(who, &res, &Action::ReadLog { marking: m });
        assert_eq!(
            read(&who("olga", "TS//SI/TK//NF", 200), &tk),
            Decision::Permit
        );
        assert_eq!(
            read(&who("olga", "TS//SI/TK//NF", 200), &si),
            Decision::Permit
        );
        assert!(matches!(
            read(&who("bob", "TS//SI//NF", 200), &tk),
            Decision::Deny(DenyReason::ClearanceShortfall { .. })
        ));
        // Suspended readers get nothing, same as every other act.
        assert!(matches!(
            read(&who("olga", "TS//SI/TK//NF", 100), &si),
            Decision::Deny(DenyReason::AttributesExpired { .. })
        ));
        // Mismatched pairings are denied, not guessed at.
        let ceiling = si.clone();
        let room = room(&ceiling, &[], &r);
        let alice = who("alice", "TS//SI//NF", 200);
        assert_eq!(
            decide(&alice, &room, &Action::ReadLog { marking: &si }),
            Decision::Deny(DenyReason::ResourceMismatch)
        );
        assert_eq!(
            decide(&alice, &res, &Action::Create),
            Decision::Deny(DenyReason::ResourceMismatch)
        );
    }

    #[test]
    fn sap_rooms_refused_in_v1() {
        let r = reg();
        let ceiling = parse("TS//SAR-EXAMPLE//NF", &r).unwrap();
        let stewards = ["alice".to_string()];
        let alice = who("alice", "TS//SAR-EXAMPLE//NF", 200);
        assert_eq!(
            decide(&alice, &room(&ceiling, &stewards, &r), &Action::Create),
            Decision::Deny(DenyReason::SapRoomsUnsupported)
        );
    }
}
