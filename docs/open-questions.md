# Open questions

Design problems found while building. `docs/architecture.md` is unchanged; each item says what the code does in the meantime.

## Q1. The pinned libcrux provider can't run our ciphersuite *(blocks `client` and `ds` crypto)*

`openmls_libcrux_crypto` 0.4.0 on crates.io rejects 0x0907: `supports()` accepts only Ed25519 signatures. The ML-DSA support that §11.1 found is on `main` only (see `docs/spike-results.md`). That contradicts the locked "libcrux provider first".

- **Now:** the pin is in place as instructed (`openmls_libcrux_crypto = "0.4"`, PQ feature on), and `client` and `ds` depend on it, but nothing uses it yet. The spike ran on `openmls_rust_crypto` 0.6.0, which accepts 0x0907. That provider uses the RustCrypto `ml-dsa` 0.1 crate and `hpke-rs-rust-crypto`: neither formally verified nor validated.
- **Options:**
  - (a) Use `openmls_rust_crypto` until libcrux ships a release.
  - (b) Take openmls `main` as a git dependency. That conflicts with the "0.9" pin, and cargo-deny would need the git source allowed.
  - (c) Write a small GARBLE `OpenMlsCrypto` provider over `libcrux-ml-dsa` and `libcrux-ml-kem` directly. That's the same work as the planned `fips` provider, just a different backend.
- **Recommendation:** (a) for development and (c) before any pilot. Also ask OpenMLS when the next libcrux provider release is due.
- A related gotcha: `openmls_rust_crypto` accepts 0x0907 in `supports()` but leaves it out of `supported_ciphersuites()`. Never negotiate suites from that list. Use the single `CIPHERSUITE` constant.

## Q2. DS-proposed Removes must reach every member, not just the custodian

The spike showed that a member can't process a commit that covers a proposal it hasn't already received (`InvalidCommit(MissingProposal)`). §5.6 and §5.7 draw the DS sending its external Remove only to the custodian. It has to be fanned out to the whole room, the target included, before anyone commits it.

- **Now:** nothing built depends on this. Fix the diagrams when the spec is next edited.

## Q3. `markings` API differs from the §4.1 signatures

| §4.1 says | Built | Why |
|---|---|---|
| `dominates(&Clearance, &Marking)` | `dominates(&Clearance, &Marking, &Registers) -> Result<(), Box<Shortfall>>` | REL TO collectives (`FVEY`) need register data to expand. `Box` because `Shortfall` is large (clippy `result_large_err`) |
| `max(...) -> Result<Marking, _>` | `max(...) -> Marking` | Two valid markings always combine into a valid one. A property test checks this |
| `parse(s, reg, Mode)` | `parse(s, reg)` | §4.1.1 drops lenient parsing, so there's only one mode |
| `SciControl { system, compartments: BTreeSet<SciCompartment> }` | `Compartments = BTreeMap<system, BTreeMap<compartment, BTreeSet<sub>>>` | A map can't hold the same system twice with different contents. SCI and SAR share the type |
| `Clearance.dissem_grants` covers FGI | Separate `Clearance.fgi: bool` | FGI isn't a dissem control in the model |

## Q4. Stricter-than-Meridian grammar: confirm these are wanted

Each of these is now refused (with a test):
- REL TO without `USA`. This is a CAPCO rule, and the `within`/`max` algebra relies on it.
- Meridian's legacy `SCI/TK` and `SAP/X` prefixes.
- Comma-separated SCI (`TK,HCS`).
- `RD-FRD`, which isn't a CAPCO marking.
- Two REL TO tokens in one marking.
- NOFORN together with REL TO.
- SCI, SAR, AEA or FGI on an UNCLASSIFIED marking.

**Consequence of item 8:** a plain `S` message is *not* `within` a `S//REL TO USA,GBR` room, because an unmarked classified portion counts as not releasable. The composer will need to require a foreign-disclosure control in REL TO rooms, or the UI will produce many denials.

## Q5. CAPCO details marked `TODO-verify` in the code

- **Item 8 roll-up** (`lattice.rs`): REL TO combined with an unmarked classified part becomes NOFORN.
- **FGI:** the acknowledged form (`FGI-GBR`, copied from Meridian, vs CAPCO's `FGI GBR DEU`), and whether concealed FGI dominates acknowledged FGI.
- **REL TO:** the separator (`,` vs `, `) and the portion abbreviation `REL`.
- **Dissem controls:** the set and display order, and the portion abbreviations (IMC, PR, DS, XD, ND).
- **RELIDO:** it only rolls up when every part carries it.
- **CUI on classified markings:** it's kept in the data but not rendered (DoDI 5200.48). There's also no text grammar for classified + CUI in v1.

## Q6. Unmaintained build-time dependency under libcrux

`proc-macro-error2` (RUSTSEC-2026-0173, unmaintained, no safe upgrade) comes in via `hax-lib` under the libcrux crates. It's a compile-time proc macro only. It's ignored in `deny.toml` with a reason. Revisit when libcrux updates, or if Q1 moves off libcrux.

## Q7. Dissem grant semantics

`dominates` requires an explicit grant for every dissem control except NOFORN (handled by releasability) and RELIDO (restricts no one). Basic CUI needs no grant; named CUI categories each need one. Is that right for HVSACO, WAIVED, FISA, PROPIN, EXDIS, NODIS and LIMDIS? The issuer will need to emit these grants.

## Q8. `Clearance` has no canonical encoding yet

§4.2's `AttributeCredential` signs a `Clearance`, so `Clearance` needs a versioned canonical encoding like `Marking`'s. That's deferred to the `proto`/`identity` work. It probably belongs in `markings`, next to `Marking`'s.

## Q9. Registers may themselves be classified

Strict validation requires every SCI and SAR sub-compartment to be in the register. Real sub-compartment names can be classified, which makes the register, and so the trust bundle, classified at the fabric level. That fits one deployment per fabric, but the trust-bundle handling in §4.3 should say so.

## Q10. Removal path (resolved by idea-v1)

`idea-v1.md` §1: expiry suspends; `Remove` is a deliberate steward act. Built that way: the DS sends removal requests only for debriefs (attributes no longer cover the room), only the room's steward acts on them, and long-expired members are removed by the steward's `cleanup`. MLS external proposals from the DS aren't used.

- **Gap:** a debriefed member stays in the MLS tree until the steward syncs. Until then only the DS withholds content (§5.7's documented trade-off). Rooms with several stewards shorten that window.

## Q11. Attribute binding into MLS (decided: hybrid)

`idea-v1.md` §1 asks for attributes bound into the member's MLS credential so other members can verify them. Built as a hybrid:

- **At join:** each KeyPackage leaf carries the issuer-signed `AttributeCredential` in a private-use leaf extension (`0xF0A2`), signed by the member's own leaf signature. The adder's client, the DS and every existing member judge a joiner on *those* attributes, so an adder can't substitute anyone else's. The DS also rejects an enrollment whose leaf attributes differ from the credential presented.
- **On refresh:** fresh credentials go to the DS directory, and committers put theirs in the handshake AAD. Every check requires the credential's bound key to equal the actor's leaf signature key, so a credential can't be borrowed.
- **Why not update the leaf on every refresh:** credentials last hours, so that would mean an Update commit per room per user every few hours. With expiry suspending rather than removing, the directory path keeps refreshes cheap.
- **Revisit if:** members must verify a *current* credential with the DS offline. That needs leaf updates, or store-and-forward of the directory.

## Q12. What "an admin clears a frozen room" means (decided: close it)

`idea-v1.md` §1a says that after a fork, an admin clears the room after investigating. After a fork, the DS's MLS state includes the bad commit and the honest members' state doesn't, and a commit can't be un-merged. So `clear-fork` lets a steward record the finding and **close** the room permanently; the steward then recreates it with its honest members.

- **Reopening in place** would need the DS to keep pre-commit snapshots and roll back. That's possible later, but it means trusting the DS's rollback, which is exactly what the fork just called into question.
- **`--simulate-malicious`** on the DS skips its commit policy check. It exists only so the money demo can show checks 3 and 4 working without checks 1 and 2. Never deploy with it.

## Q13. signed-note has no signature type for ML-DSA-87

`tlog` signs checkpoints as C2SP signed notes, whose key ID is `SHA-256(name || 0x0A || type || public key)[..4]`. The spec assigns no type byte to ML-DSA-87, so `tlog::SIG_TYPE_ML_DSA_87` is a provisional `0xA7`, kept in that one place like `CIPHERSUITE`.

- **Consequence:** only GARBLE verifiers read these notes today, and a registered byte changes every key ID. Fine while the log is dev-only; settle it before any outside witness cosigns.
- **Related (architecture §12 item 5):** leaves and nodes are SHA-256, per RFC 6962, not a CNSA 2.0 hash.
- **Hash tiles are world-readable to any session.** Hashes alone reveal nothing about content, but leaf hashes allow guess-and-check of an entry whose fields a reader can predict (event, room, id, timestamp). Entries themselves are gated by marking; the tile layout means the tree's shape and size are not.

## Q14. Forwarded provenance is the forwarder's word

`Envelope.forwarded_from` names the original room, message ID and sender, but nothing in the envelope is signed by that sender: the MLS signature is the forwarder's. A receiver sees "alice says this came from bob in ops".

- **The marking is not at risk.** The forwarder's own `Send` check runs against the destination's ceiling, and receivers re-run it. The claim at risk is attribution.
- **Fix when it matters:** carry the original MLS message (or the sender's signature over the envelope) inside the forward. It's bigger and leaks the source room's epoch; the reserved `cosignatures` slot is the other route.
- **Related:** clients keep sent and received text in `state.json` (plaintext, like the MLS dump) so `ack` and `forward` can refer back to it. SQLCipher replaces it.

## Q15. The desktop app's dependency tree and what it doesn't do yet

- **Unmaintained build-time dependency.** On Linux Tauri pulls gtk-rs 0.18, which uses `proc-macro-error` (RUSTSEC-2024-0370, no safe upgrade). Compile-time only, ignored in `deny.toml`. It goes away when Tauri moves off GTK3. `Zlib` joined the license allowlist for the same tree.
- **Quarantines have no audit reference.** A message the receiving client refuses is shown and offered to the denial inspector, but the client doesn't report receive-side refusals to the DS (§5.3 covers sends, adds and joins), so there's no log entry to prove. The inspector says so.
- **Join refusals** reach the inspector as the client's formatted string, not as code and audit ref, because `Event::JoinRefused` carries only text.
- **Not in the app yet:** enrollment and credential refresh (the app opens a home made by `garble init`/`enroll`), and any persistence of acks, quarantines and notices across restarts. Text messages come back from the client's store.
- **Watermark** carries the user and a per-run seed, not a device ID; the client has no device notion yet (§7.5).

## Q16. The archive key's holder can skip the permit

The custodian opens an archive only against a DS-logged `ReadArchive` permit (a log entry, its inclusion proof, a checkpoint signed by the log key, a listed records officer, under 15 minutes old, single use). That is procedure enforced by the `garble-custodian` binary, not by cryptography: whoever holds the ML-KEM-1024 private key can decrypt every sealed copy directly, with no permit and no log entry.

- **Now:** the key is a hex file given to `garble-custodian read --key`, and `issuer init` writes a dev copy to `archive-private.hex`. In a deployment it's generated and sealed offline by the custodian; the issuer shouldn't see it.
- **The permit is a bearer artifact.** The custodian can't tell whether the person presenting it is the officer it names. The short window and single use limit the damage; they don't remove it.
- **Fix:** two-person integrity on archive reads: split the key (or run a threshold KEM) so opening needs two officers' shares, and have the shares check the permit. That also covers the "no standing key" rule in `idea-v1` §1, which today is met only in the sense that the custodian binary holds no key at rest.
- **Related:** the custodian trusts the DS for completeness. A DS that withholds an archive entry isn't noticed. Cross-checking against the `archive` hash on each message's log entry needs the custodian cleared to read the log.

## Q17. A malicious sender can archive a copy that differs from what members received

The sender seals the archive copy, and nothing lets anyone else see inside it. The copy's SHA-384 is in the MLS-signed `AppAad` and in the message's log entry, so it's bound to *that message*, but the DS can't open it, members can't compare it, and the custodian can't see the real message. A sender can archive different text, a different marking, or garbage; the custodian reports a copy that doesn't open instead of skipping it, but a well-formed lie opens fine.

- **Not at risk:** what members received, and the log. The marking policy runs on the MLS message, not the copy.
- **Fix, cheapest first:** put a hash of the envelope in `AppAad` (the random `msg_id` inside it makes the hash safe to expose) and have receivers check it and the custodian check it on opening; or make the custodian an MLS member so it sees the same ciphertext (the architecture's original design, §5.9).
- **Related:** a copy is sealed before its message is sent. If the send is then refused, the sealed copy stays in DS memory and is never archived; the custodian only ever receives copies tied to a sequenced message.

## Q18. Attachments: limits and what isn't built

- **Stored in DS memory, whole.** Blobs are capped at 32 MiB each (`proto::MAX_BLOB`; files are encrypted and sent in one piece) and are lost on a DS restart, like everything but the log. Chunked upload, resume and a `BlobStore` on disk come with the SQLite store.
- **Who can fetch.** Current members of the room it was uploaded to, with a current credential and no removal pending, plus the custodian. A removed member loses access with membership, but anything they already downloaded stays downloaded.
- **Content addressing is per upload.** The same ciphertext uploaded to another room, by another sender or under another marking is refused (`B-002`). Keys are random per file, so only a copied blob hits this.
- **Markings.** A blob is uploaded under the marking of the message it precedes, decided by the same policy as that send, and the message must carry the same marking (`B-001` otherwise). The marking gates upload and log visibility; read access to the bytes is the key in the message.
- **Forwarding a file isn't supported.** The blob belongs to the source room. Moving it means fetching, re-encrypting and re-uploading into the destination under that room's check; `forward` refuses files until that's built.
- **Receivers only see a line.** A file message reads as `[file] name (N bytes)` in `read` and in the desktop feed; `garble fetch ROOM SEQ` downloads it. The file's name comes from the sender and is reduced to its last path component on fetch; fetch never overwrites.
- **Blobs are checked, not trusted:** the receiver verifies the DS's bytes against the SHA-384 in the signed message, and AES-GCM fails on any change.

