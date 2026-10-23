# GARBLE — v2 Scope

**The second slice: say less to fewer people, and make no single person enough**

Status: build target. v1 (`idea-v1.md`) is built: four-point enforcement, fork freeze, the transparency log, acks, forwarding, files, the custodian archive, the console. v2 is confidentiality and integrity hardening. It spends the protocol slots v1 reserved for per-message audience and cosignatures, and pays down the production stand-ins v1 named. Same discipline as v1: every feature genuinely usable, nothing that forecloses `ideav-10.md`, and when in doubt cut the feature and keep the slot. Ops traffic (precedence, forms, spill checks) is v3: `idea-v3.md`.

> **Revision note (2026-10-13):** incorporates a review.
> - Restricted portions get an explicit forward-secrecy bound and a slot ceiling, above which a portion needs a linked subgroup (§1, v2.1).
> - Audience composition is called out as DS-visible metadata (§1a).
> - The archive-bloat and bulk-export cost of k-of-n is recorded (§1, v2.2).
> - v1's post-quantum claim is qualified by provider (§1, crypto).
> - Ops traffic is cut to v3.

---

## 0. Goal of v2

A GARBLE where:
- A message in a coalition room can carry a **NOFORN portion only US members can decrypt** and a REL TO tearline everyone sees. One message, no retyping, and the DS can read neither.
- **No single person can raise a room's ceiling or open the archive.** Two authorized signers, both checked by every member (or by every key holder), both logged.
- The stand-ins are gone: canonical TLS wire encoding, encrypted client state, TLS to the DS, libcrux crypto.

**The v2 demo:** a `TS//SI//REL TO USA, GBR` room with a US analyst, a US steward and a GBR liaison.
1. The analyst sends one message: a `TS//SI//NF` portion to the US members and a `TS//SI//REL TO USA, GBR` tearline to everyone. The liaison's client renders the tearline and a "restricted portion" chip, and its banner reflects what it saw. The DS logs both markings and can open neither.
2. The analyst tries a portion above the room's slot ceiling. It's refused: that tier needs a subgroup, not a slot.
3. The steward tries to raise the ceiling to `TS//SI/TK`. With one signature, every member's client rejects the commit; with a second steward's approval, it goes through.
4. A records officer asks to open the archive. One officer's share opens nothing; two do, and both requests are in the log.

## 0a. Build order (milestones — each independently demoable)

Wire changes go first, so the new fields land in the final encoding instead of being migrated twice.

- **v2.0 — the foundations.** `tls_codec` wire format (wire v2) with canonical signed bytes; a new log origin for the new leaf encoding; the envelope hash in `AppAad` (closes Q17); SQLCipher client state; TLS to the DS; the libcrux provider. Nothing new is visible to users, and every v1 demo still passes on top of it.
- **v2.1 — tearlines and per-message audience.** HPKE-to-subset in `Envelope.audience`, a dedicated and rotated audience key in each leaf, the slot ceiling, member-side recipient checks, per-viewer banners.
- **v2.2 — two-person integrity.** Approvals on handshakes (ceiling raises; optionally adds), and k-of-n archive opening that replaces the single archive key (closes Q16).

## 1. In scope (v2)

**Wire format and storage (v2.0)**
- **`proto` moves from JSON to `tls_codec`**, `WIRE_VERSION = 2`. Every signed or hashed structure gets one canonical byte form: `AttributeBody`, `LogEntry` leaves, `AppAad`, `HandshakeAad` and approvals. The `serde_json` "deterministic by field order" ponytails are deleted. JSON stays only for the HTTP API bodies around the TLS-encoded objects.
- **This breaks the v1 wire format, deliberately and once.** v1 has no deployments and no records to carry, and every structure is versioned, so a v1 peer refuses v2 bytes instead of misreading them. It's the last wire break the plan allows; everything after is additive under §2.
- **The log gets a new origin.** A Merkle tree can't change its leaf encoding mid-tree. The DS starts a fresh log (new signed-note origin) at wire v2. The v1 log is closed with a final checkpoint and stays verifiable read-only.
- **`AppAad` carries the envelope hash:** SHA-384 of the canonical envelope. The random `msg_id` inside makes the hash safe to expose. Receivers check it, and the custodian checks it on opening, so a sender can no longer archive a different message from the one members received (Q17).
- **Client state in SQLCipher**, one file per device, keyed by `KeyStore`. OpenMLS storage, messages, the credential cache, the pinned checkpoint, acks and quarantines all move in. `state.json` and the plaintext MLS dump go away (Q14, Q15). One purge path: delete the room's rows and the MLS group.
- **TLS to the DS** (TLS 1.3 via rustls). Use a post-quantum key exchange where the provider offers one, and log the negotiated group at startup. Don't claim CNSA 2.0 for the transport until it's pure ML-KEM-1024. Tailscale stops being a requirement.

**Crypto (v2.0)**
- **What v1 actually is:** post-quantum from message one, on 0x0907 (ML-KEM-1024, ML-DSA-87), running on `openmls_rust_crypto`. That's RustCrypto's ML-KEM/ML-DSA: neither formally verified nor validated (Q1). The external phrasing until v2.0 lands is "post-quantum (CNSA 2.0 suite) on an unverified provider". It is not "libcrux", and not "validated".
- **libcrux provider for 0x0907.** Re-check at milestone start: if a published `openmls_libcrux_crypto` supports ML-DSA-87, adopt it. Otherwise write a small GARBLE `OpenMlsCrypto` provider over `libcrux-ml-dsa` and `libcrux-ml-kem` (Q1 option c). Either way, `CIPHERSUITE` stays the only place the suite is named. Both providers run the full test suite in CI for one milestone before the RustCrypto one is dropped.
- **`fips` stays a trait-ready feature, not a claim.** Evaluate a validated module (aws-lc-rs FIPS is the candidate). Adopt it only if its validated boundary covers ML-KEM-1024, ML-DSA-87, AES-256-GCM and SHA-384 together. Otherwise record the gap and keep libcrux.

**Tearlines and per-message audience (v2.1)**
- **Mechanism: HPKE-to-subset, as reserved in v1 §2.** An `AudienceSlot` carries:
  - its own portion marking and a recipient list;
  - one AES-256-GCM ciphertext under a random content key;
  - that key HPKE-wrapped to each recipient.
- **Each member publishes a dedicated audience key** (ML-KEM-1024 HPKE) in a new leaf extension (`0xF0A3`), signed by its leaf signature. The MLS leaf `encryption_key` is **not** reused, because that would be cross-protocol key reuse with the TreeKEM path.
- **The tearline is the MLS message itself.** `AppAad.marking` is the tearline marking everyone can read. Each slot's marking must be within the room ceiling, and the sender must be cleared for it. `AppAad` gains `audience: [{ marking, recipients }]`, so the DS checks and logs every slot's marking and audience without seeing content.
- **Every recipient must be cleared for its slot**, checked at all the usual points:
  - the sender's client;
  - the DS, from the attribute credentials it holds;
  - **every receiving client**, which judges every named recipient from the attributes in their leaf.

  A slot naming an uncleared recipient makes the whole message a quarantine, not a partial render. Same thesis as v1 §1a check 3: neither the sender nor the DS is trusted to pick the audience.
- **Forward secrecy: slots are weaker than the MLS body, so the doc says so and policy bounds it.**
  - **The gap.** A slot's content key is per message, but opening it depends on the recipient's audience private key. Compromising that key exposes every slot sealed to it since it last rotated. The MLS body around the slot ratchets per message. Left alone, that inverts the protection: the NOFORN portion, the more sensitive part of the message, would have weaker forward secrecy than the REL TO tearline beside it.
  - **Bound the window.** Each member's audience key rotates on every leaf Update, and at least every `audience_key_max_age`. That's a room parameter, default 24 h: a client whose key is older commits an Update before it next sends. Old private keys are kept for a short grace for in-flight messages (default 1 h) and then deleted. A slot sealed to a deleted key is shown as undecryptable, not retried. So a slot's forward-secrecy window is `max_age + grace`, stated in the threat model and shown in the room's details.
  - **Bound what may use a slot.** `RoomPolicy` gains `slot_ceiling`: the highest marking a slot may carry. Above it, a restricted portion **must** go in a linked subgroup (a separate MLS group of just that audience, with full per-message forward secrecy). v2 doesn't build subgroups, so above the slot ceiling, policy refuses the send (fail closed). Rooms without a `slot_ceiling` allow no slots at all.
  - That makes subgroups "required for the top tier", not "later, for forward secrecy". The deferral now has a policy edge, not a hope that nobody asks.
- **The custodian is an implicit recipient of every slot.** The archive copy seals the whole envelope with the slots decrypted. Records law doesn't care that the GBR member couldn't read it.
- **Rendering:** a member sees the portions it can open, and its banner is the high-water mark of *what it sees*, not of the message. A member who isn't in a slot sees an explicit "restricted portion (not for you)" chip, not silence: hiding that something was withheld is worse than saying so.
- **Size:** each recipient costs an ML-KEM-1024 ciphertext (1,568 bytes). A 20-person NOFORN slot adds ~31 KB. That's acceptable on a LAN and binding at the edge, so the composer shows the size.
- Unblocks Q4's consequence: a plain `S` portion in a REL TO room becomes a NOFORN slot by default, instead of a denial (if the slot ceiling allows it).

**Two-person integrity (v2.2)**
- **Room policy names which acts need two signers**: `two_person: { set_ceiling, add, read_archive }`. `set_ceiling` (raise) and `read_archive` are on by default. `add` is off by default; it lands with SAP rooms later.
- **Handshake approvals:**
  - `HandshakeAad` gains `approvals`. Each one is a second steward's ML-DSA-87 signature over `(room, epoch, digest of the proposals, decided_at)`.
  - `policy` gets the approvals as verified inputs, and requires the configured number of **distinct** stewards, the committer counting as one.
  - The DS checks it, and every member checks it. A one-signer ceiling raise sequenced by a colluding DS is a fork, and freezes the room like any other.
- **Collecting the second signature** goes through a DS mailbox (`approval-request` → `approve`). Both are logged. The approval travels in the commit, not in the mailbox, so a lost mailbox loses nothing.
- **Archive opening becomes k-of-n.**
  - The archive copy is sealed under a random content key, and that key is split with Shamir k-of-n.
  - Each share is HPKE-sealed to a different records officer's archive key; `RoomPolicy.custodian` names the n keys and k.
  - Opening needs k officers, **each** presenting their own DS-logged `ReadArchive` permit with their share: k independent permit checks, and no single key that opens anything.
  - The "no standing key" rule from v1 now holds cryptographically, not by procedure (Q16).
- **The cost, recorded now rather than discovered at v2.2:**
  - *Storage.* Every message carries n share ciphertexts (1,568 bytes each) on top of its ML-DSA-87 signature. At the default 2-of-3 that's ~4.7 KB of shares per message, before any slots.
  - *Bulk export* (FOIA, eDiscovery, a date-range pull). A permit can cover a room and a date range, so each officer's tool unwraps its shares for the whole range in one pass. The human cost is k approvals per export, not per message. The machine cost is n×k ML-KEM decapsulations per message, which is fast but not free at millions of messages.
  - *Alternative if size bites:* one archive key per (room, day), split once a day, with messages sealed to it. That cuts the per-message overhead to near zero, at the price of a day's granularity per opening. v2 builds per-message; revisit with measurements.
  - Default to 2-of-3, and keep n small.

## 1a. Threat model additions

- **Slots have update-granularity forward secrecy**, bounded by `audience_key_max_age + grace`. Anything that needs better goes above `slot_ceiling` and so needs a subgroup.
- **The composition of a restricted audience is visible to the DS.** `AppAad.audience` names the recipients so the DS can check and log the slot, so the DS learns exactly who is in the US-only subset of each message. That's intended for a coalition room, where membership and nationality are already known to the operator. But for some rooms, *who is in the inner group* is itself the sensitive fact. Those rooms shouldn't use slots: use a separate room, or a subgroup once it exists. The room-creation UI says this when a slot ceiling is set.
- **Log entries for slotted messages carry the highest slot marking**, so who may read the entry follows the most sensitive thing it describes (v1 §1, log classification).

## 2. Explicitly OUT of scope for v2 (but protocol-reserved)

Reserve the slot; don't build the feature.

| Deferred feature | What v2 must keep open |
|---|---|
| Ops traffic: precedence/FLASH, structured forms, spill pre-send checks | v3 (`idea-v3.md`); precedence is already in the envelope, content type already typed |
| Linked subgroups | **required above `slot_ceiling`**; `AudienceSlot` is versioned, so a slot type can name a subgroup instead of recipients |
| Spill *response* (flag → quarantine → purge everywhere → rotate → log) | purge is already one path (SQLCipher); rotation is an empty commit |
| SAP (unacknowledged) rooms, discovery cards, access requests | `SAR-` still parses, rooms still refused; `two_person.add` already exists for them |
| Edge: store-and-forward, EMCON, DS persistence, witnesses | signed-note checkpoints already accept cosignatures |
| Machine principals / AI member | credentials remain principal-type-agnostic |
| Original-sender provenance on forwards (Q14) | `cosignatures` stays reserved on the envelope |
| Voice/video (SFrame), federation (MIMI), web client, real CAC/DISS | unchanged from v1 §2 |
| Pure ML-KEM-1024 TLS, validated `fips` module | provider trait and TLS config stay swappable; record what's negotiated |

## 3. Crate changes

No new crates unless forced. Pure stays pure.

- `markings` — nothing new.
- `policy` — new verified inputs: approvals on `SetCeiling` / `Add`, `Send` with audience slots and the slot ceiling, `ReadArchive` shares. New deny reasons for missing approvals, uncleared recipient, slot above slot ceiling, and slots in a room without one. **Still pure.**
- `proto` — the `tls_codec` switch, `AudienceSlot` v2, `Approval`, `slot_ceiling` and `audience_key_max_age` in `RoomPolicy`, the envelope hash.
- `identity` — the audience-key leaf extension.
- `client` — HPKE-to-subset, audience-key rotation and deletion, the approval flow, SQLCipher storage.
- `ds` — audience, slot-ceiling and approval checks, the approval mailbox, TLS, a new log origin.
- `custodian` — k-of-n share opening, range permits.
- `garble-desktop` — slots and "restricted portion" chips, forward-secrecy and audience-visibility notes in room details, approvals in the denial inspector.

## 4. v2 definition of done

1. Every v1 demo passes on wire v2. The v1 log is closed and still verifies, and the v2 log starts fresh. *(v2.0)*
2. Client state is encrypted at rest; the DS runs over TLS; CI runs both crypto providers until the switch. *(v2.0)*
3. An archive copy that doesn't match its message's envelope hash is detected by the custodian on opening. *(v2.0)*
4. A NOFORN slot in a REL TO room: GBR can't decrypt it, sees that a portion was withheld, and gets a banner from what it saw. A slot naming an uncleared recipient is refused by the sender's client and the DS, and quarantined by every receiving client. *(v2.1)*
5. A slot above the room's slot ceiling is refused at the sender's client, the DS and receivers. An audience key past `max_age + grace` is gone from the client store, and a slot sealed to it doesn't open. *(v2.1)*
6. A one-signer ceiling raise is refused at all points, and a colluded one freezes the room. A two-signer raise succeeds. *(v2.2)*
7. One officer's share opens nothing; k shares open the copy; a range permit exports a date range in one pass per officer; every share request is logged and policy-gated. *(v2.2)*
8. OSCAL rows added for AC-4(1)/AC-16 (slots), AC-5 and AU-9(5)/AC-3(2) (two-person integrity), and SC-28(1) (SQLCipher). Fuzz targets cover the new `tls_codec` decoders. *(per milestone)*

## 5. Hard rules carried forward

Every rule in `idea-v1.md` §5 still holds, plus:
- **Receivers judge the audience.** The sender and the DS propose who gets a slot; every receiving client checks it.
- **The most sensitive portion never gets the weakest protection.** Above the slot ceiling there are no slots, and the slot forward-secrecy window is stated, not implied.
- **No single signer for an irreversible widening.** A ceiling raise or an archive opening is never one person's act.
- **One wire break, now.** The v2.0 encoding switch is the last breaking change; everything after is additive.
- **Every KEM ciphertext is ~1.5 KB.** Slots and shares multiply them. Show the size in the composer, and keep n small.
