# GARBLE — v1 Scope

**The buildable first slice of the GARBLE Protocol**

Status: build target. This is what gets written first. It is a thin but *complete* vertical slice of `GARBLE_v10_vision.md` — real end to end, not a mock. The discipline: every v1 feature is genuinely usable, and every v1 protocol decision leaves room for the v10 features without a breaking change. When in doubt, cut a feature but keep the protocol slot.

> **Revision note (2026-10-06):** incorporates a Palantir-side technical review. Changes: enforcement is now specified as a four-point check with defined fork handling (§1a); credential expiry *suspends* rather than *removes* (§1, identity); the records custodian is redesigned so it holds no standing key (§1, records); tearline/subset reservation pinned to HPKE-to-subset, not subgroups (§2); marking-algebra property tests made explicit (§4); transparency-log entries inherit the classification of what they describe (§1, audit). Build order is now milestoned v0.1–v0.4 (§0a).

---

## 0. Goal of v1

A working, demonstrable GARBLE where:
- Two or more people on separate machines chat in real time through an untrusted delivery service.
- Rooms have a classification ceiling; messages carry portion markings.
- A user whose attributes don't dominate a room's ceiling **cannot be added** — the add is refused at four independent points (§1a), and the denial is logged.
- Every message is signed, attributable, and recorded in an append-only audit log.
- It runs on your own machine / Tailscale / a cheap VPS — no SIPRNet or air-gap needed to develop or demo.

**The money demo:** you hold `TS//SI`, your friend holds `SECRET`; you create a `TS//SI` room and try to add him; his client, the server, and every existing member's client all refuse, and the denial lands in the audit log with a reason. That is Signalgate failing to happen, on your own setup. Record it.

## 0a. Build order (milestones — each independently demoable)

Carved out of the review. v1 is too large to build in one pass; each milestone is a standalone portfolio artifact.

- **v0.1 — the core + money demo.** `markings`, `policy`, `proto`, and the CLI against a local DS. Deliver the money demo in a terminal and record it. Includes the four-point enforcement (§1a) and fork handling, because that's the actual security claim. This alone is a strong portfolio piece and the thing to show first.
- **v0.2 — audit.** Transparency log with verifiable inclusion + consistency proofs, ML-DSA-signed checkpoints, and signed acknowledgments.
- **v0.3 — the console.** Tauri desktop client: banners, marking chips, inspectable denials, on-screen watermark. This is where it *looks* impressive.
- **v0.4 — hardening + compliance.** Attachments (client-encrypted blob store), the OSCAL stub, and fuzzing of the marking parser and wire decoder.

The §1 scope below is the union of these; the §4 definition-of-done items map onto the milestone that delivers them.

## 1. In scope (v1)

**Crypto & protocol**
- MLS via OpenMLS, ciphersuite `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87` (provisional code point 0x0907) as a single named constant so the IANA re-number is a one-line change.
- **Prerequisite spike (do this before any `core` code):** stand up a "hello world" MLS group on this exact ciphersuite with OpenMLS + libcrux. Confirm which crypto provider actually signs ML-DSA-87 for 0x0907 and whether it's on a release or only `main`. If it isn't supported, you're writing a crypto provider first, and the whole schedule changes — so find out on day one.
- **Plan for signature size.** ML-DSA-87 signatures are ~4.6 KB and public keys ~2.6 KB. Every signed message and every KeyPackage is heavy. It's fine on a LAN/VPS, but note it now because it's the binding constraint on the edge/EMCON story later. Don't sign anything you don't need to.
- libcrux crypto provider (the `fips` provider is a v-later feature).
- All handshakes as `PublicMessage`; DS rejects `PrivateMessage` handshakes, keeps public group state, evaluates every Add/Commit, holds Welcomes until the Commit is sequenced.
- Versioned wire format from the very first message (`proto` crate).

**Identity & policy**
- Enrollment with a **mock attribute issuer** (the `AttributeIssuer` trait with a dev implementation). No real CAC/DISS integration yet — but issued credentials are already short-lived + signed, so the shape is real.
- **Attribute binding into MLS:** decide and document how clearance/compartment attributes bind into the member's MLS credential so *other members* can verify them — a custom MLS credential type carrying the signed attribute set (preferred), or an X.509 extension. v1 picks one; this is a wire-format decision, not a later tweak.
- **Expiry suspends, it does not auto-remove.** MLS does not expire members on its own, and a hard Remove-on-expiry would kick an edge user offline for 12 hours out of every room — which contradicts the EMCON/edge story in the vision. So: an expired credential makes a member's messages **rejected by policy** (they can't send, and their sends are dropped) and gives them a **grace-and-refresh** path (re-present a fresh credential to rejoin the active set). An actual MLS `Remove` is a separate, deliberate act (debrief, clearance loss, compromise), committed by the room's admin client. Open item still: who commits routine cleanup Removes for members long-expired — admin client on a timer in v1; revisit for scale.

- `markings` crate: full CAPCO parse/render adapted from Meridian, **with the fixes** (typed errors, strict mode, REL TO sort+dedupe, versioned+checked canonical encoding, CUI orthogonal), plus `Clearance` + `dominates()`.
- `policy` crate: pure `decide(subject, resource, action) -> Permit | Deny(reason)`; same code client + DS. v1 actions: `add_member`, `send_message`, `create_room`, `set_ceiling`.
- Fail closed everywhere.

**Rooms & messaging**
- Rooms with a classification ceiling (set at creation).
- DMs = two-person rooms (one primitive, not two).
- Text messages with a required portion marking ≤ ceiling; composer refuses otherwise.
- **Signed acknowledgments** (the "roger") — included in v1 because it's a protocol primitive that's painful to add later.
- File attachments: client-side encrypted, content-addressed blob store; server never sees plaintext.
- Marking-aware relay between rooms (refuse forward above destination ceiling).

**Audit**
- Append-only transparency log: RFC 6962 hashing + C2SP tlog-tiles layout + ML-DSA-signed checkpoints. (Witness cosigning is v-later; the format supports it.)
- Logs handshake events (with policy decision + reason) and per-message `(ciphertext hash, sender, epoch, timestamp)`. Never plaintext.
- **Log entries inherit the classification of what they describe.** `(sender, epoch, timestamp)` reveals who talked to whom and when; for an unacknowledged room, a log entry reveals the room *exists*. So every log entry carries a marking, and reading the log is itself access-controlled by `policy`. A global, world-readable log is a metadata leak and is not allowed. (In v1, since SAP rooms are refused, this is mostly a single-ceiling log — but build the field now.)

**Records**
- Records custodian present in every room by default — **but it holds no standing key to anything.** A custodian that sat in every room holding every archive key would *be* the privileged insider the whole thesis exists to eliminate, and a reviewer spots that in ten seconds. Instead: the custodian is an archive endpoint that receives messages re-encrypted to it per room; reading the archive is a deliberate, fully-logged action gated by the same `policy` crate (and, past v1, two-person integrity). **Hard rule: one custodian per enclave/program, never a global one.** v1 builds the per-room re-encryption path and the logged-read gate; 2PI on archive read is v-later but named in the threat model now.
- No disappearing-message feature at all (set the precedent now).
- On removal: clients purge local history best-effort and log that they did (documented as unenforceable against a malicious client).

**Clients**
- **CLI/TUI** first — proves the core, doubles as the admin/bot interface.
- **Tauri desktop** app — primary human client; keys live in the native Rust process. Banners, marking chips, inspectable denials, on-screen watermark.

## 1a. Who refuses an under-cleared add (the actual enforcement)

"His client and the server refuse" is too loose. Real enforcement is four independent checks, and the security claim rests on all four:

1. **The adder's client** refuses to build the Commit in the first place (`policy` says the invitee's attributes don't dominate the room ceiling).
2. **The DS** refuses to sequence the Commit (it runs the same `policy` on the `PublicMessage` handshake).
3. **Every existing member's client** checks each incoming Commit against `policy` and rejects a bad one. *This is the check that matters* — it's what defeats a malicious DS colluding with a malicious member, because neither the adder nor the DS is trusted.
4. **The invitee's client** checks the Welcome against its own clearance and refuses to join a room it shouldn't be in.

**When checks disagree (the fork), v1 hard-freezes.** If the DS sequences a Commit that honest members reject (check 3 fires after checks 1–2 were bypassed or colluded), the group has forked: honest members are on one branch, the DS/bad actor on another. This is exactly the collusion scenario GARBLE exists to defeat, so the room does **not** keep passing traffic. On fork detection: **freeze the room (no sends accepted from anyone), raise an alarm, and write the fork event to the transparency log with the conflicting Commits.** An admin clears it after investigation.

- *Rejected alternative — soft-flag* (alarm + log but let traffic continue on the members' agreed branch): easier to live with, but it means the system keeps operating through a detected integrity failure, which undercuts the "cryptographic need-to-know against the operator" thesis. If GARBLE's whole claim is that it stops exactly this, it can't shrug and carry on when it happens. Freeze is the honest default. (Flip this only with a deliberate reason; it's a wire-observable behavior.)

Fork handling is a v0.1 concern even though it looks advanced — it's the interesting half of the security claim, and the wire format + member-side Commit validation have to anticipate it from the first line.

## 2. Explicitly OUT of scope for v1 (but protocol-reserved)

Reserve the wire slot; don't build the feature.

| Deferred feature | Protocol reservation needed in v1 |
|---|---|
| Tearlines / per-message audience | envelope allows a payload encrypted to a **subset via HPKE-to-members**, not just the group epoch secret. **Decision:** reserve the HPKE-to-subset slot, *not* linked subgroups. Subgroups (a US-only shadow group behind a FVEY room) double group-management and multiply epochs; HPKE-to-subset is the lighter mechanism to leave room for now, and subgroups can be added later for the narrower case where a subset needs full forward secrecy *among themselves*. Either way this is a v1 wire-format decision because it changes the envelope. |
| Precedence (FLASH etc.) | a precedence field in the envelope (v1 sends ROUTINE only) |
| Structured messages (USMTF) | a typed-body/content-type field (v1 uses `text/plain`) |
| Voice/video (SFrame) | nothing in v1, but don't foreclose MLS exporter-secret use |
| Machine principals / AI member | credential + attribute model is principal-type-agnostic |
| Edge hubs / store-and-forward / EMCON | DS interface written so a queue/relay can sit behind it |
| Federation (MIMI) | room policy expressed in a GroupContext extension, MIMI-shaped |
| Web client | none — desktop + CLI only; web is a later, lower-assurance tier |
| Real CAC / DISS / Scattered Castles | `AttributeIssuer` trait — swap the mock for real later |
| FIPS-validated crypto | crypto provider behind a trait; `fips` feature later |
| SAP (unacknowledged) rooms | `SAR-` markings **parse** in v1, but SAP rooms are **refused** |
| Cross-domain / ISM-TDF export | markings already machine-readable; exporter is later |
| Spill pre-send checks | composer already inspects markings; dirty-word register is later |
| Two-person integrity | single-signer in v1; signature set in the envelope can hold >1. (2PI on custodian archive read is the first place it lands past v1.) |

## 3. v1 crate layout (reference impl)

Functional core / imperative shell. Pure crates have no I/O; traits at every seam a real deployment swaps.

- `markings` — CAPCO types, parse/render, canonical encoding, `Clearance`, `dominates()`. **Pure.**
- `policy` — `decide(...)`. **Pure.** Depends on `markings`.
- `proto` — versioned wire types, message envelope, handshake framing.
- `core` — MLS group state (OpenMLS), key storage behind a `KeyStore` trait (file store for dev; PIV/HSM later), `AttributeIssuer` trait (mock for dev), member-side Commit validation + fork detection.
- `server` — delivery service (routes ciphertext, enforces `policy` on `PublicMessage` handshakes, sequences commits, holds Welcomes, freezes a forked room), transparency log, blob store, records-custodian endpoint.
- `cli` — TUI client + admin (the admin is who clears a frozen room and commits cleanup Removes).
- `desktop` — Tauri app (Rust core + frontend); specify the core↔frontend boundary (keys never cross it).

Dependency direction: `markings` ← `policy` ← `core`/`server` ← `cli`/`desktop`; `proto` shared by `core`/`server`.

## 4. v1 definition of done

1. Two machines, separate networks, chat through a DS on a VPS/Tailscale. *(v0.1)*
2. Room ceiling enforced at all four points of §1a; under-cleared add refused; denial logged with reason. *(v0.1)*
3. A forged/colluded Commit the DS accepts is rejected by honest members, the room freezes, and the fork event is logged. *(v0.1)*
4. Marking algebra property-tested *(v0.1)* — see §4a; parser fuzzed *(v0.4)*.
5. Every message signed; audit log verifiable (inclusion + consistency proofs check out); log entries carry a marking. *(v0.2)*
6. Signed ack round-trips. *(v0.2)*
7. File send/receive with server holding only ciphertext. *(v0.4)*
8. Records custodian present, holds no standing key, archive read is logged and policy-gated; no message deletion path exists. *(v0.1 gate, v0.4 archive path)*
9. OSCAL component definition stub: at least AC-3(3), AC-4, AU-10 mapped to the code + test that implements each. *(v0.4)*

## 4a. The marking algebra is not a simple ordering — test it as an algebra

`dominates()` and the banner high-water mark are different operations over different structures, and this is exactly the kind of rigor a reviewer rewards:

- **Classification level** is a total ordering (`U < C < S < TS`).
- **SCI / SAP controls** are set inclusion (you need ⊇ of the required compartments).
- **REL TO** combines by **intersection** of country lists; **NOFORN overrides** REL TO entirely.
- **ORCON, FGI, RSEN** each have their own special-case semantics (default: deny unless explicitly granted).
- **CUI** is orthogonal to level, not a point on it.

Write explicit property tests for the algebra:
- the **join** (high-water aggregation) is associative, commutative, and idempotent;
- `dominates` is consistent with the join (if `a` dominates `b` and `c`, it dominates `join(b,c)`);
- round-trip: `parse(render(m)) == m` for all generated markings;
- canonical encoding is permutation-invariant (the REL TO fix: `REL TO USA,GBR` and `REL TO GBR,USA` encode identically).

## 5. Hard rules carried from the vision

- **Fail closed.** Unknown marking / expired attribute / missing register / unverifiable credential → deny.
- **Same `policy` code client and server** — and on *every existing member's client* (§1a check 3). Client-side enforcement defeats a malicious DS; member-side enforcement defeats a malicious DS colluding with a member; server-side gives the operator accountability + fast rejects.
- **No deniability, no auto-delete** — attribution and records are the point.
- **No privileged insider, including our own custodian** — the records custodian holds no standing key; even the archive is under `policy`.
- **Post-quantum from message one** (harvest-now-decrypt-later).
- **Don't break the wire format** to reach v10 — that's what §2's reservations protect. The size cost of ML-DSA-87 (§1) is the one physical constraint that reservation can't paper over; keep signed objects lean.

## 6. Key references (for the agent, indexed in-repo)

Convert the relevant *sections* to markdown in-repo; do not dump whole PDFs (an agent indexing 500 pages of 800-53 drowns).

- RFC 9420 (MLS) — §6 (PublicMessage/handshake), §12 (Commit/proposal processing — for member-side validation + fork handling), §14 (Welcome ordering), §16.9/16.11 (DS policy).
- `draft-ietf-mls-pq-ciphersuites` — ciphersuite 0x0907 definition.
- RFC 9180 (HPKE) — for the tearline/subset reservation (encrypt-to-members).
- RFC 6962 / C2SP tlog-tiles + signed-note — transparency log.
- NIST SP 800-53 Rev 5 — AC-3(3), AC-4, AC-16, AU-9/10 (only these sections for v1).
- IC ISM — marking value lists (source of truth for `markings` data). **Public value lists only; never real program names, even in examples or tests.**
- Meridian `marking.rs` — reference to adapt (copy, don't depend); **check its license before copying**; carry the REL TO fix.

Full framework list lives in `GARBLE_v10_vision.md §15`; v1 only needs the slices above.

## 7. External framing (for README / interviews, not this doc)

This doc and `GARBLE_v10_vision.md` are the *internal* north star and are deliberately maximal. In public — the repo README, an interview, a demo writeup — present GARBLE as **a reference design / proposed standard**, not as "the DoW/IC-wide standard." The humble register is the credible one externally; overclaiming reads as naïve. Keep the two registers separate: planning docs stay ambitious, public materials stay modest.