# GARBLE — v10 Vision

**The GARBLE Protocol: a DoW/IC-wide secure messaging standard**

Status: north-star vision document. This is the end state (v10), where GARBLE is the standard chat layer across the Department of War, the Intelligence Community, and the defense industrial base. It is deliberately ambitious. It is NOT the build plan — see `GARBLE_v1.md` for what gets built first. When the coding agent drifts into research or scope that doesn't serve the mission, this document and the v1 doc are the things to check against.

> **Revision note (2026-10-06):** incorporates a Palantir-side technical review. Changes: four-point enforcement with hard-freeze fork handling (§3); credential expiry suspends rather than auto-Removes, with attribute-carrying MLS credentials (§5); the marking engine is specified as a property-tested algebra (§6); per-message audience / tearlines pinned to HPKE-to-subset (§7); the records custodian holds no standing key and is one-per-enclave (§11); transparency-log entries inherit classification (§11); external-framing register discipline added (§17).

---

## 0. One-line definition

GARBLE is an end-to-end encrypted, post-quantum, marking-aware group messaging **protocol** (with a reference implementation in Rust) for classified and controlled government networks. It enforces need-to-know cryptographically against the operator and every insider, makes every message attributable and auditable, and runs unmodified from a CUI chat between two sailors to an unacknowledged TS//SCI SAP program.

## 1. The thesis (why it exists)

- **Signal protects users *from* the operator** (deniability, minimal metadata). **Government messaging needs the opposite accountability**: every message attributable and signed (NIST SP 800-53 **AU-10**), retained under records law (**DoDI 8170.01**, **44 U.S.C. 2911**), and auditable by insider-threat investigators (**ICD 503 §D.3.e**).
- **Existing government chat (ChatSurfer, Mattermost) enforces need-to-know only in the server**, so any sysadmin can bypass it. The privileged insider is the real threat — Snowden was a sysadmin.
- **"Signalgate" (2025) was not a crypto failure**: an uncleared person was added to a group, messages auto-deleted against records law, on unmanaged devices. GARBLE makes the first failure impossible at the protocol layer.
- **Thesis:** same confidentiality as Signal, opposite accountability, with need-to-know enforced cryptographically against the operator. A person without the right clearance and compartments *cannot* be added to a room; client and server both refuse, and the refusal is logged.
- **What it is NOT:** not a Type 1 product, not a replacement for link encryptors (TACLANE). The fabric is already encrypted; GARBLE is defense-in-depth against insiders and the operator. One deployment per security fabric; it never crosses domains itself.

## 2. The range it must span

The single hardest design constraint: **one protocol, both ends of the spectrum.**

| | Low end | High end |
|---|---|---|
| Example | Two sailors, CUI, on NIPR | A TS//SCI SAR USAP program |
| Network | NIPR, intermittent satellite | Isolated SAP enclave |
| Membership | Loose, org directory | Program access roster only |
| Room existence | Public within the org | Classified (unacknowledged) |
| Admin | Unit IT | Program security officer (PSO) |
| Device | Ordinary DoD mobile | Accredited workstation in a SCIF/SAPF |

Everything below is shaped by having to serve both without forking the protocol.

## 3. Threat model (v10)

**Defends against:**
- The operator (delivery-service admins, infrastructure staff) — cannot read content or alter membership policy.
- The over-cleared insider — holding high clearance ≠ access to every room; compartments gate cryptographically.
- A compromised delivery service — can delay/drop/observe metadata, cannot forge membership or read plaintext.
- The departing/debriefed user — removed everywhere at once; loses all future content.
- Nation-state adversary (MSS-tier) — attacks the endpoint, supply chain, parsers, and metadata, not the crypto primitives. Design assumes the adversary has read all the source.

**Explicitly does NOT defend against (documented, not hidden):**
- A fully compromised cleared endpoint while in use (screen is readable; mitigations are watermarking + UAM, not prevention).
- The accredited fabric itself / physical SCIF security (inherited).
- A malicious cleared member leaking content they're authorized to see (deterred via watermarking + attribution, not prevented).

**Trusted-for (per component):** clients trusted for key custody + policy enforcement; delivery service trusted for ordering + availability only; records custodian trusted for retention **but holds no standing key** (§11); attribute authority trusted for issuing truthful credentials.

**The enforcement is four-point, and the member-side check is the load-bearing one.** An under-cleared add is refused at: (1) the adder's client, which won't build the Commit; (2) the DS, which won't sequence it; (3) *every existing member's client*, which validates each incoming Commit against `policy` — this is what defeats a malicious DS colluding with a malicious member, since neither is trusted; (4) the invitee's client, which checks the Welcome against its own clearance. When the DS sequences a Commit honest members reject, the group has **forked**, and GARBLE treats that as the collusion attack it exists to defeat: the room **hard-freezes** (no sends from anyone), raises an alarm, and logs the conflicting Commits. It does not keep passing traffic through a detected integrity failure. (Rejected alternative: soft-flag and continue — easier to use, but it means operating through exactly the failure the system claims to prevent.)

## 4. Cryptographic foundation

- **MLS (RFC 9420)** group messaging via OpenMLS.
- **Ciphersuite:** pure CNSA 2.0 — `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87` (ML-KEM-1024, AES-256-GCM, SHA-384, ML-DSA-87). No hybrid, no X-Wing. (Ref: `draft-ietf-mls-pq-ciphersuites`, CNSSP-15, CNSA 2.0.)
- **Crypto provider:** libcrux for dev; a validated (FIPS 140-3) provider behind a `fips` feature for production.
- **All handshakes as `PublicMessage`** so the delivery service can inspect and reject membership changes against policy (RFC 9420 §6, §16.11). DS keeps public group state to verify signatures; holds Welcomes until the Commit is sequenced.
- **No deniability.** Every message signed and attributable (**AU-10**).
- **Post-quantum now** because of harvest-now-decrypt-later: adversaries collect classified ciphertext today to break later. Confidentiality (ML-KEM) is the urgent half; signature PQ matters less near-term.

## 5. Identity & access

- **Authoritative attribute sources:** DISS (DoD clearances), Scattered Castles (IC), SAP access rosters, DoD/IC PKI (CAC/PIV, SIPR tokens), personnel systems.
- **CAC/PIV at enrollment** to sign an attestation binding the user's software/HSM-held ML-DSA key (fielded cards can't do ML-DSA yet; SP 800-78-6 is draft).
- **Short-lived signed attribute credentials** (hours). Expiry is the primary revocation mechanism — satisfies **ICD 503** continuous-verification / Zero Trust (NSM-8). **Expiry suspends, it does not auto-Remove:** MLS doesn't expire members on its own, and kicking an offline edge user out of every room every few hours would break the EMCON/edge story below. An expired member's sends are rejected by `policy`; they rejoin the active set by presenting a fresh credential (grace-and-refresh). An actual MLS `Remove` is a separate, deliberate act (debrief, clearance loss, compromise). Attributes bind into the member's MLS credential (custom credential type carrying the signed attribute set) so other members can verify them in check (3) above.
- **Read-on / debrief as first-class workflows.** PSO reads a person onto a program → they appear in its rooms. Debrief → MLS Remove from every room carrying that access, new epoch, future content denied. (Does not claw back already-seen history.)
- **Two-person integrity (2PI)** for the most sensitive actions: adding a member to a SAP room, raising a ceiling, approving an export. Two authorized signers required.
- **Temporary need-to-know** grants that auto-expire at mission end.
- **Machine principals** — sensors, systems, AI agents hold credentials + attributes exactly like people (see §12).

## 6. The marking & policy engine

- **`markings` crate** (GARBLE's own, adapted from Meridian's `marking.rs`; copied, not a shared dependency). Full CAPCO: classification levels, SCI controls, SAP (`SAR-<program>`), AEA (RD/FRD/CNWDI), FGI, dissemination (NOFORN, ORCON, REL TO, RSEN, FISA, etc.), CUI as an orthogonal category.
- Fixes carried from research: typed errors, strict mode (reject unknown caveats — fail closed), REL TO sorted+deduped on parse, versioned+checked canonical encoding, `Clearance` type + `dominates(&Clearance, &Marking)`.
- **The marking logic is an algebra, not a single ordering,** and it's property-tested as one: classification level is a total order; SCI/SAP controls are set inclusion; REL TO combines by intersection with NOFORN overriding; ORCON/FGI/RSEN carry their own deny-unless-granted semantics; CUI is orthogonal to level. The high-water-mark **join** must be associative, commutative, idempotent, and `dominates` consistent with it. (License-check Meridian's `marking.rs` before copying; public value lists only, never real program names.)
- **`policy` crate:** pure, deterministic `decide(subject, resource, action) -> Permit | Deny(reason)`, no I/O. Same code in client and DS. Covers **AC-3(3)** (mandatory access control), **AC-4** (flow enforcement), **AC-16** (attribute binding), **AC-24/25** (access-decision function / reference monitor).
- **Fail closed everywhere:** unknown marking, expired attribute, missing register, unverifiable credential → deny.
- **Interop:** marking data sourced from IC ISM value lists; messages/attachments exportable as TDF objects (EDH/ARH access rights). Enables cross-domain guard inspection.

## 7. Messaging features built for military/IC use

- **Precedence:** ROUTINE / PRIORITY / IMMEDIATE / FLASH. FLASH overrides do-not-disturb, demands timed acknowledgment, escalates on silence.
- **Signed acknowledgments** — cryptographic "roger," non-repudiation of *receipt* (not just send).
- **Structured messages:** USMTF/templates — SPOTREP, SALUTE, 9-line MEDEVAC, etc. Render as forms, machine-parseable so downstream systems can act.
- **Zulu time everywhere; MGRS/grid coords → map pins.**
- **Marking-aware relay/forward:** marking travels with forwarded content; forwarding above the destination ceiling is refused (**AC-4**).
- **Per-message audience within a room:** a NOFORN message in a FVEY room encrypts only to US members.
- **Tearlines:** a message can carry a higher-classified body + a lower REL TO tearline; each member sees what they're cleared for, no retyping.
- Threads, pins, per-room "current assessment," reactions-as-acks.

> **Mechanism note (per-message audience + tearlines).** MLS encrypts to the whole group's epoch secret, so "only the US members read this" needs more than an envelope field. Two options: **HPKE-to-subset** (encrypt the restricted payload directly to the specific members' keys) or **linked subgroups** (a US-only shadow group behind the FVEY room). GARBLE reserves the **HPKE-to-subset** slot in the v1 wire format as the default — it's the lighter mechanism. Subgroups are added later only for the narrower case where a subset needs full forward secrecy *among themselves*. This is a wire-format decision, which is why the slot is reserved in v1 even though the feature ships later.

## 8. The operations console (UI synthesis)

**Signal's clarity × Palantir Workshop's density × the classified-network aesthetic.** Not Discord/Slack (those are browse-first social tools). This is an **ops console** — dense, multi-pane, keyboard-first, built to monitor many streams at once (closer to a Bloomberg terminal's chat × a power IRC client).

- Top & bottom **classification banners** showing the live high-water mark of what's on screen (updates as you scroll), color-coded.
- **Marking chip on every message**; composer won't send without a marking or above ceiling.
- Tiled **multi-room** views; **watches** (client-side keyword/entity alerts — must be client-side under E2EE, which conveniently means alert rules never reach the server).
- **Incidents:** one timeline aggregating relevant messages across many rooms.
- **Shift handover** notes; per-room triage priority.
- **Denials are inspectable objects** (reason + audit-log entry ID), never error toasts.
- **On-screen identity watermark** (leak tracing — rendered per viewer, content never altered per recipient).
- Command palette; everything keyboard-reachable.

## 9. Fabric reach & the tactical edge

- **Deployments:** NIPR (CUI), SIPR, JWICS, SAP enclaves, mission-partner environments (NATO/FVEY), tactical edge (ships, ops centers, aircraft).
- **Edge hubs:** a ship runs its own delivery service; chat survives satellite dropout; syncs to shore on reconnect (store-and-forward in-protocol).
- **EMCON mode:** under emissions control, clients queue silently, transmit nothing.
- **Bandwidth-aware mode:** defer attachments, compress; matters because PQ keys/signatures are heavy on constrained links.
- **Cross-domain ready:** machine-readable markings (ISM/TDF) let accredited guards inspect/transfer; GARBLE is the easiest system to put a guard in front of. GARBLE never crosses domains itself.
- **Classified mobile:** via NSA CSfC on hardened phones (SECRET); CUI on ordinary DoD mobile.

## 10. Spill prevention & response

- **Pre-send checks:** client scans outgoing text against dirty-word/codeword registers for terms the room isn't cleared for — catches spills *before* send. Almost nothing does this today.
- **Spill workflow:** flag → quarantine → purge on every client → rotate keys → log. One action vs. a week of manual cleanup.
- **Compromise response:** revoke a lost device, rotate a room's keys, or burn a room entirely.

## 11. Records, audit, investigations

- **Records custodian:** visible member of every group for retention (**AU-11**), legal holds, records schedules; FOIA/eDiscovery exports retaining markings. **No disappearing-message feature, ever** (records law). **But the custodian holds no standing key** — a member sitting in every room holding every archive key would *be* the privileged insider this whole system exists to eliminate, and it's the first thing a reviewer flags. Instead: messages are re-encrypted to the custodian endpoint per room; reading the archive is a deliberate, fully-logged, **two-person-integrity** action gated by the same `policy` crate. **Hard rule: one custodian per enclave/program, never a global one.** The custodian is thus a demonstration that `policy` governs even the operator, rather than an exception to it.
- **Declassification support:** declassify-on dates + classification-guide refs on messages; expired items queue for downgrade review.
- **Transparency log:** append-only, RFC 6962 hashing, C2SP tlog-tiles layout, ML-DSA-signed checkpoints, witness cosignatures (custodian + ISSM tooling as witnesses). Logs handshake events (with policy decision + reason) and per-message `(ciphertext hash, sender, epoch, timestamp)`. Never plaintext. (**AU-9/9(3), AU-10**.) **Log entries carry the classification of what they describe** — `(sender, epoch, timestamp)` is a who-talked-to-whom-and-when graph, and for an unacknowledged room a log entry reveals the room *exists*. Reading the log is itself access-controlled by `policy`; a global world-readable log is a metadata leak and is not permitted.
- **Insider-threat / UAM feed** (ICD 503 §D.3.e) + watermarking.

## 12. AI as a cleared member

The feature that fits where Palantir is going, and the hardest to retrofit — so the protocol reserves room for it now.

- An **AI agent is a room member with attributes**, bound by the same `policy` as a person. It reads only what its credentials allow; every action is signed and logged.
- Use cases: shift summaries, coalition translation, marking suggestions ("this reads like SECRET//NOFORN"), incident-timeline assembly, structured-message extraction.
- **The differentiator:** most "AI in classified" bolts the model on *outside* the access controls. GARBLE puts it *inside* them — the model is just another principal under the reference monitor.

## 13. Voice & video

- **SFrame (RFC 9605)** media encryption keyed from the MLS group.
- Push-to-talk for tactical users; **gateways to radio nets**.
- Small-team voice/video calls. All media carries the room's marking + policy.
- (Deferred past v1 — but the protocol reserves the key-derivation slot so it drops in without redesign.)

## 14. Adoption & administration

- **XMPP gateway** bridging existing ChatSurfer-era rooms during migration — nobody switches overnight; this is what makes adoption possible.
- **Policy as code:** org-wide rules ("all J2 rooms default to SECRET//REL FVEY"), room templates.
- **Continuous ATO (cATO):** OSCAL component definitions (one per deployable), each implemented control linked to the code + test that satisfies it; assessment results generated in CI. (**NIST SP 800-37**, **DoDI 8510.01** type authorization.)
- **Federation** across hubs within a fabric, shaped to map onto IETF **MIMI** later. Never across fabrics.

## 15. Compliance frameworks referenced

- **NIST SP 800-53 Rev 5** (AC-3/3.3, AC-4, AC-16, AC-24/25, AU-2/3/6/9/10/11/12, IA-2/5, SC-8/12/13/16/17/23/28, SI-7, SA-24) — control catalog.
- **NIST SP 800-37 Rev 2** — RMF; GARBLE feeds Implement + Assess via OSCAL.
- **ICD 503** (25 Oct 2024) — IC IT authorization, Zero Trust, user-attributable audit, reciprocity.
- **ICD 501** — responsibility to provide/discover; discovery cards.
- **IC-ITD / ISM / TDF / EDH-ARH** — marking data + object encoding for interop & cross-domain.
- **DoDM 5205.07 Vols 1–4** — SAP security (access rosters, indoctrination/debrief, marking).
- **JSIG** — SAP RMF tailoring; SAP-specific control parameters.
- **DoDI 8500.01 / 8510.01** — DoD cybersecurity + RMF; CNSSI 1253 + Classified Information Overlay; eMASS; type authorization.
- **DoDI 8170.01 / 44 U.S.C. 2911** — electronic records; legal basis for the records custodian and no-auto-delete.
- **CNSSP-15 / CNSA 2.0** — approved algorithms; 1 Jan 2027 compliance pressure for new NSS.
- **NSM-8** — Zero Trust mandate.
- **NSA CSfC** — commercial solutions for classified (mobile).

## 16. What stays true from v1 to v10

The protocol primitives chosen in v1 must not need breaking changes to reach this vision. Reserve protocol room now for: tearlines / per-message audience (via HPKE-to-subset), precedence, signed acks, structured messages, machine principals, SFrame media keying, store-and-forward/edge sync, member-side Commit validation + fork handling, attribute-carrying MLS credentials, and per-entry log classification. These are the expensive-to-retrofit ones. Everything else can be added as features over a stable wire format. The one constraint no reservation can paper over is the **size of ML-DSA-87** (~4.6 KB signatures, ~2.6 KB public keys) — it binds the edge/EMCON story, so keep signed objects lean from the start.

## 17. External framing (register discipline)

This document and `GARBLE_v1.md` are the **internal north star** and are deliberately maximal — their job is to force v1 decisions against the full vision. In **public** (repo README, interviews, demo writeups), present GARBLE as **a reference design / proposed standard**, never as "the DoW/IC-wide standard." The ambitious register is right for planning; the modest register is right for an audience, where overclaiming reads as naïve. Keep the two separate: don't sand the ambition out of this doc, and don't carry this doc's maximal framing into a README.