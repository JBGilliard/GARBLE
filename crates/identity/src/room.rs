//! Room rules shared by the DS and every client, so both sides evaluate the same
//! evidence with the same `policy::decide` (§5.3).

use anyhow::{Context, Result, bail, ensure};
use markings::{Marking, Registers};
use openmls::prelude::{
    Ciphersuite, Credential, CredentialType, Extension, Extensions, GroupContext, LeafNode,
    LeafNodeIndex, PublicGroup, StagedCommit, UnknownExtension,
};
use policy::{Action, Decision, Resource, Subject, decide};
use proto::{
    ATTRIBUTES_EXT, AppAad, AttributeCredential, CIPHERSUITE, CustodianRef, GARBLE_CREDENTIAL,
    HandshakeAad, ROOM_POLICY_EXT, RoomPolicy, WIRE_VERSION,
};

use crate::TrustBundle;

/// How far a signed decision time may be from the verifier's clock.
pub const MAX_SKEW_SECS: u64 = 300;

pub fn ciphersuite() -> Result<Ciphersuite> {
    Ciphersuite::try_from(CIPHERSUITE)
        .map_err(|_| anyhow::anyhow!("ciphersuite 0x{CIPHERSUITE:04X}"))
}

/// The user ID inside a GARBLE MLS credential.
pub fn user_of(c: &Credential) -> Result<String> {
    ensure!(
        c.credential_type() == CredentialType::Other(GARBLE_CREDENTIAL),
        "not a GARBLE credential"
    );
    Ok(String::from_utf8(c.serialized_content().to_vec())?)
}

/// Attribute binding (idea-v1 §1, open question Q11): the hybrid. A member's signed
/// attributes ride in their leaf, signed by the member, from the moment they join, so
/// the adder can't substitute someone else's. Refreshed attributes travel by
/// directory and AAD, and every check requires their key to match the actor's leaf.
pub fn attributes_extension(cred: &AttributeCredential) -> Result<Extensions<LeafNode>> {
    Ok(Extensions::single(Extension::Unknown(
        ATTRIBUTES_EXT,
        UnknownExtension(proto::encode(cred)?),
    ))?)
}

/// Who a leaf is: user, signing key, and the attributes it joined with. Fails unless
/// the attributes name this user and this key.
#[derive(Clone)]
pub struct LeafIdentity {
    pub user: String,
    pub key: Vec<u8>,
    pub attributes: AttributeCredential,
}

pub fn leaf_identity(leaf: &LeafNode) -> Result<LeafIdentity> {
    let user = user_of(leaf.credential())?;
    let key = leaf.signature_key().as_slice().to_vec();
    let ext = leaf
        .extensions()
        .unknown(ATTRIBUTES_EXT)
        .with_context(|| format!("{user}'s leaf carries no attributes"))?;
    let attributes: AttributeCredential = proto::decode(&ext.0)?;
    ensure!(
        attributes.body.user == user,
        "leaf attributes are for {}",
        attributes.body.user
    );
    ensure!(
        attributes.body.key.0 == key,
        "leaf attributes are bound to another key"
    );
    Ok(LeafIdentity {
        user,
        key,
        attributes,
    })
}

/// What a commit does, as every verifier sees it from the same public tree.
pub struct CommitView {
    pub committer: String,
    pub committer_key: Vec<u8>,
    pub added: Vec<LeafIdentity>,
    pub removed: Vec<String>,
    /// The room rules after the commit, when it changes them.
    pub new_rules: Option<RoomRules>,
    /// Everyone in the room after the commit, judged by their leaf attributes.
    pub members_after: Vec<LeafIdentity>,
}

impl CommitView {
    /// Build the view of `staged` (committed by leaf `committer`) against `group`, the
    /// tree before the commit. The DS and every member call this same function.
    pub fn of(
        group: &PublicGroup,
        staged: &StagedCommit,
        committer: LeafNodeIndex,
        trust: &TrustBundle,
    ) -> Result<Self> {
        let leaf = group
            .leaf(committer)
            .context("committer is not in the tree")?;
        let added: Vec<LeafIdentity> = staged
            .add_proposals()
            .map(|p| leaf_identity(p.add_proposal().key_package().leaf_node()))
            .collect::<Result<_>>()?;
        let removed_idx: Vec<LeafNodeIndex> = staged
            .remove_proposals()
            .map(|p| p.remove_proposal().removed())
            .collect();
        let removed = removed_idx
            .iter()
            .map(|i| {
                user_of(
                    group
                        .leaf(*i)
                        .context("removed leaf not in tree")?
                        .credential(),
                )
            })
            .collect::<Result<_>>()?;
        let mut members_after = Vec::new();
        for m in group.members().filter(|m| !removed_idx.contains(&m.index)) {
            members_after.push(leaf_identity(group.leaf(m.index).context("member leaf")?)?);
        }
        let changed = staged.group_context().extensions() != group.group_context().extensions();
        let new_rules = changed
            .then(|| RoomRules::read(staged.group_context().extensions(), trust))
            .transpose()?;
        Ok(Self {
            committer: user_of(leaf.credential())?,
            committer_key: leaf.signature_key().as_slice().to_vec(),
            members_after: members_after
                .into_iter()
                .chain(added.iter().map(LeafIdentity::clone))
                .collect(),
            added,
            removed,
            new_rules,
        })
    }
}

pub struct RoomRules {
    pub ceiling: Marking,
    pub stewards: Vec<String>,
    pub custodian: Option<CustodianRef>,
    pub records_officers: Vec<String>,
    registers: Registers,
}

impl RoomRules {
    pub fn read(ext: &Extensions<GroupContext>, trust: &TrustBundle) -> Result<Self> {
        let ext = ext
            .unknown(ROOM_POLICY_EXT)
            .context("room has no policy extension")?;
        let p: RoomPolicy = proto::decode(&ext.0)?;
        ensure!(p.v == WIRE_VERSION, "room policy version {}", p.v);
        let registers = trust.registers();
        let ceiling = Marking::from_canonical(&p.ceiling.0, &registers)?;
        Ok(Self {
            ceiling,
            stewards: p.stewards,
            // A half-filled slot is no slot.
            custodian: p
                .custodian
                .filter(|c| !c.id.is_empty() && !c.archive_key.0.is_empty()),
            records_officers: p.records_officers,
            registers,
        })
    }

    fn resource(&self) -> Resource<'_> {
        Resource::Room {
            ceiling: &self.ceiling,
            stewards: &self.stewards,
            custodian: self.custodian.as_ref().map(|c| c.id.as_str()),
            records_officers: &self.records_officers,
            registers: &self.registers,
        }
    }

    pub fn check_join(&self, me: &Subject) -> Decision {
        decide(me, &self.resource(), &Action::Join)
    }

    pub fn check_create(&self, creator: &Subject) -> Decision {
        decide(creator, &self.resource(), &Action::Create)
    }

    pub fn check_read_archive(&self, reader: &Subject) -> Decision {
        decide(reader, &self.resource(), &Action::ReadArchive)
    }

    /// Judge a commit. Joiners and the roster are judged on the attributes in their
    /// own leaves; the committer on the fresh credential it puts in the AAD, which
    /// must be bound to its leaf key.
    /// ponytail: commits that only update keys pass; stewards can't be changed yet.
    pub fn check_commit(
        &self,
        trust: &TrustBundle,
        view: &CommitView,
        aad: &[u8],
        now: u64,
    ) -> Result<Decision> {
        if view.added.is_empty() && view.removed.is_empty() && view.new_rules.is_none() {
            return Ok(Decision::Permit);
        }
        let aad: HandshakeAad = proto::decode(aad).context("handshake AAD")?;
        ensure!(aad.v == WIRE_VERSION, "handshake AAD version {}", aad.v);
        ensure!(
            aad.decided_at.abs_diff(now) <= MAX_SKEW_SECS,
            "decision time outside skew window"
        );
        let cred = aad
            .evidence
            .iter()
            .find(|c| c.body.user == view.committer && c.body.key.0 == view.committer_key)
            .context("no attributes for the committer bound to its key")?;
        let committer = trust.verify(cred, aad.decided_at)?;
        let joiners: Vec<Subject> = view
            .added
            .iter()
            .map(|j| trust.verify(&j.attributes, aad.decided_at))
            .collect::<Result<_>>()?;
        let members: Vec<Subject> = view
            .members_after
            .iter()
            .map(|m| trust.verify(&m.attributes, aad.decided_at))
            .collect::<Result<_>>()?;
        let mut actions: Vec<Action> = joiners
            .iter()
            .map(|joiner| Action::Add { joiner })
            .collect();
        actions.extend(view.removed.iter().map(|target| Action::Remove { target }));
        if let Some(new) = &view.new_rules {
            ensure!(
                new.stewards == self.stewards,
                "changing stewards is not supported yet"
            );
            ensure!(
                new.custodian == self.custodian && new.records_officers == self.records_officers,
                "changing the custodian or records officers is not supported yet"
            );
            actions.push(Action::SetCeiling {
                new: &new.ceiling,
                members: &members,
            });
        }
        for action in &actions {
            if let deny @ Decision::Deny(_) = decide(&committer, &self.resource(), action) {
                return Ok(deny);
            }
        }
        Ok(Decision::Permit)
    }

    /// Do `s`'s attributes still cover the room? False after a debrief or clearance
    /// loss; the DS then asks the room's steward to remove them.
    pub fn still_cleared(&self, s: &Subject) -> bool {
        markings::dominates(&s.clearance, &self.ceiling, &self.registers).is_ok()
    }

    /// Does the decrypted `envelope` (canonical bytes, as received) match the hash the
    /// sender signed into the AAD? Separate from `check_message`: the DS never sees an
    /// envelope, and a composer preview doesn't have one yet.
    pub fn check_envelope(aad: &AppAad, envelope: &[u8]) -> Result<()> {
        ensure!(
            crate::archive::sha384(envelope)? == aad.envelope.0,
            "envelope doesn't match the hash in its AAD"
        );
        Ok(())
    }

    /// An application message: its AAD and the sender's attribute credential.
    pub fn check_message(
        &self,
        trust: &TrustBundle,
        aad: &AppAad,
        sender: &AttributeCredential,
        sender_key: &[u8],
    ) -> Result<(Marking, Decision)> {
        ensure!(aad.v == WIRE_VERSION, "message AAD version {}", aad.v);
        ensure!(
            sender.body.key.0 == sender_key,
            "sender's attributes are bound to another key"
        );
        if sender.body.user != aad.sender {
            bail!(
                "credential is for {}, message claims {}",
                sender.body.user,
                aad.sender
            );
        }
        let subject = trust.verify(sender, aad.sent_at)?;
        let marking = Marking::from_canonical(&aad.marking.0, &self.registers)?;
        let d = decide(
            &subject,
            &self.resource(),
            &Action::Send { marking: &marking },
        );
        Ok((marking, d))
    }
}

#[cfg(test)]
mod tests {
    use proto::{Bytes, Envelope, Precedence, TEXT_PLAIN};

    use super::*;

    fn envelope(body: &str) -> Envelope {
        Envelope {
            v: WIRE_VERSION,
            msg_id: Bytes(vec![7; 16]),
            content_type: TEXT_PLAIN.into(),
            precedence: Precedence::Routine,
            body: Bytes(body.into()),
            reply_to: None,
            audience: vec![],
            cosignatures: vec![],
            forwarded_from: None,
        }
    }

    fn aad_for(e: &Envelope) -> AppAad {
        AppAad {
            v: WIRE_VERSION,
            sender: "alice".into(),
            marking: Bytes(vec![1]),
            sent_at: 0,
            blobs: vec![],
            archive: None,
            envelope: Bytes(crate::archive::envelope_hash(e).unwrap()),
        }
    }

    #[test]
    fn a_receiver_holds_the_envelope_to_the_hash_in_the_aad() {
        let sent = envelope("hello");
        let aad = aad_for(&sent);
        let bytes = proto::encode(&sent).unwrap();
        RoomRules::check_envelope(&aad, &bytes).unwrap();

        // Different text, and a different msg_id: neither passes for the signed one.
        let other = proto::encode(&envelope("goodbye")).unwrap();
        assert!(RoomRules::check_envelope(&aad, &other).is_err());
        let mut reid = sent.clone();
        reid.msg_id = Bytes(vec![8; 16]);
        assert!(RoomRules::check_envelope(&aad, &proto::encode(&reid).unwrap()).is_err());

        // An AAD that never committed to an envelope matches nothing.
        let bare = AppAad {
            envelope: Bytes(vec![]),
            ..aad
        };
        assert!(RoomRules::check_envelope(&bare, &bytes).is_err());
    }
}
