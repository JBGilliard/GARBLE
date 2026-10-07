# GARBLE: scoped research pass

Date: 2026-10-04. Scope and budget per the brief. No subagents were used, and no code was written.

Legend: **(unverified)** marks a claim from background knowledge that I did not confirm against a source in this pass. Treat it as a lead, not a citation.

---

## 1. Meridian reuse

Files read: `README.md`, root `Cargo.toml`, `crates/lexicon-core/Cargo.toml`, `crates/lexicon-core/src/marking.rs` (1,277 lines, about 430 of them tests). I grepped for call sites but did not read them.

### What GARBLE can take directly

`marking.rs` is already close to a standalone crate.

- **Dependencies:** only `serde`, `serde_json`, `std`, and a single use of `crate::error::Error` inside `SciRegister::bundled()`. No crypto, no SQLite, no ledger.
- **Typed model:** `Level`, `Caveat` (NOFORN, ORCON, FISA, RSEN, REL TO, HVSACO, WAIVED, Other), `CompartmentKind` (SCI, SAP, RD-FRD, CNWDI, FGI), `Compartment`, `Marking`.
- **Parser:** strict CAPCO ordering (`CLASSIFICATION // SCI // SAR // AEA // FGI // DISSEM`), plus a lenient `from_stored` mode for legacy rows. It rejects bare `SCI`, enforces `SAR-<pid>` hyphenation, and validates REL TO against ISO 3166-1 alpha-3.
- **Rendering:** both portion (`TS//TK//NF`) and banner (`TOP SECRET//TK//NOFORN`) forms.
- **Aggregation:** `Marking::max` / `aggregate` do high-water-mark roll-up. NOFORN beats REL TO, REL TO lists intersect, and same-program SAR slices merge. GARBLE needs exactly this to compute a room's effective marking from its messages and attachments, and to check that a message marking stays under the room ceiling.
- **Canonical encoding:** `canonical_bytes()` gives a deterministic encoding suitable for signing.
- **Registers:** `SciRegister` and `CountryRegister` are pluggable, and `parse_with` lets callers inject them.
- **Tests:** about 30 good ones that come along with the code.

The README also lists a Merkle tree, Ed25519/ML-DSA event signatures behind a `pq` feature, and an AWS-LC FIPS 140-3 path behind `fips`. These are relevant to GARBLE's audit log (§5) and crypto (§3), but I did not read them because they were out of scope.

### What needs refactoring for a shared `markings` crate

1. **Move it.** Create `crates/markings` (or a separate repo that both projects consume as a git dependency). Replace the one `crate::error::Error` use with a local error type.
2. **Typed errors.** Every error is currently a `String`. GARBLE's `policy` crate needs to match on the failure (unknown designator vs. ordering vs. REL TO), so add a `MarkingError` enum.
3. **Register data paths.** The `include_str!("../../lexicon-pools/data/...")` lines reach into a sibling crate. Move the sample `sci_register.json` and `iso3166_alpha3.txt` behind a non-default `sample-registers` feature. GARBLE must load accreditor-supplied registers at runtime, ideally signed. In production, the parser should fail closed if no register is loaded instead of silently using the sample.
4. **Add dominance.** This is the biggest gap. Meridian answers "what is the marking of this aggregate?" GARBLE has to answer "may this person see something marked X?" That needs a separate `Clearance`/`Attributes` type (level, SCI/SAP accesses, nationality/citizenship, possibly a device tier) and a `dominates(&Attributes, &Marking) -> Decision`, defined as:
   - level ≥
   - compartments ⊇
   - NOFORN ⇒ U.S. person
   - REL TO ⇒ nationality ∈ list
   - FGI, ORCON and RSEN need defined semantics (likely "deny unless explicitly granted")

   Put the type and `dominates` in `markings`, and keep the room/membership logic in `policy`.
5. **Fail closed on unknown tokens.** `Caveat::Other` is accepted at parse time with only a warning. That is fine for a naming register but fail-open for access control. GARBLE needs a strict mode that rejects `Other`.
6. **REL TO canonicalization bug.** `parse_rel_countries` does not sort, and `canonical_bytes` / `PartialEq` use list order. So `S//REL TO USA,GBR` and `S//REL TO GBR,USA` are unequal and hash differently. (Inferred from reading the code; I did not run it.) That breaks signature comparison. Sort, and dedupe, on parse.
7. **Silent truncation.** `canonical_bytes` casts counts with `as u8` and lengths with `as u16`. Make these checked. Also version the encoding (a leading format byte), because it becomes a wire format in `proto`.
8. **Sub-structure lives in strings.** SAR sub-compartments (`QSV-PER A1`) and SCI sub-compartments are encoded inside the `designator` string. For dominance ("does access to SAR-QSV-HOL imply SAR-QSV?"), parse them into a structure. SCI sub-compartment forms (e.g. `SI-G XXXX`) do not appear to be modeled; check them against the current CAPCO register **(unverified)**.
9. **CUI ordering.** `Level` orders `Unclassified < Cui < Confidential`. CUI is not a classification level and can coexist with classified markings. That order is acceptable for ceiling math but wrong as a general model. Decide before it ossifies.
10. **Later, not now:** map to IC ISM attributes (`ism:classification`, `ism:SCIcontrols`, `ism:disseminationControls`, `ism:releasableTo`) for interop (see §2, IC-ITD). Classification-authority blocks (Classified By / Derived From / Declassify On) are not modeled; records exports may need them.

**Effort estimate:** items 1–3 and 5–7 are mechanical. Item 4, dominance plus a `Clearance` type, is the real design work, and it belongs to GARBLE.

---

## 2. Frameworks: what each requires of GARBLE

### JSIG (DoD Joint Special Access Program Implementation Guide)

Not reachable in this pass. Searches turned up only third-party mirrors, so everything below is **(unverified)**.

- JSIG is the SAP community's tailoring of SP 800-53 / CNSSI 1253. Any GARBLE room carrying a `SAR-` compartment makes the deployment a SAP information system. Authorization then runs through the SAP authorizing-official chain, not the normal DoD AO.
- It sets SAP-specific values for 800-53 parameters, such as audit review frequency, session lock, banner text and retention. GARBLE should therefore expose those as configurable parameters (OSCAL `set-parameters`), not hard-code them.
- Data transfer and removable media are tightly controlled (assured file transfer, reviewer approval). GARBLE's attachment export and any "download transcript" feature must route through a reviewable path, or be off by default.
- SAP access must come from the program's access roster, not self-assertion. SAR attributes in GARBLE credentials must be issued by an attribute authority fed from the SAP access system.

### NIST SP 800-37 Rev. 2 (RMF)

- The seven steps (Prepare, Categorize, Select, Implement, Assess, Authorize, Monitor) are the deployer's job. GARBLE, as a product, feeds **Implement** (control implementation statements: the OSCAL component definition, §6) and **Assess** (repeatable test evidence tied to control IDs).
- **Common-control and inheritance accounting.** Each control must be marked as provided by GARBLE, inherited from the enclave (physical, personnel, boundary), or hybrid / customer-configured. Ambiguity here is what slows ATOs.
- **Authorization boundary.** Define it now as clients + delivery service (DS) + transparency log + blob store + records custodian. Future federation to another DS is an interconnection with its own agreement, not part of the boundary.
- **Monitor.** Each release needs a security impact analysis, an SBOM and a signed artifact. Meridian's `docs/SCRM.md` and `docs/PROVENANCE.md` patterns transfer directly.

### NIST SP 800-53 Rev. 5 (current release 5.2.0, 27 Aug 2025)

Release 5.2.0 added SA-15(13), SA-24 and SI-2(7) and revised SI-7(12), all focused on software update integrity ([NIST](https://csrc.nist.gov/News/2025/nist-releases-revision-to-sp-800-53-controls)). The catalog is available in OSCAL.

Controls GARBLE should implement *in code* (✚ = added to the starting list):

| Control | Why / how in GARBLE |
|---|---|
| AC-3, ✚AC-3(3) | AC-3 is the core. AC-3(3) *mandatory* access control is the precise fit: room ceiling plus clearance dominance, enforced by both client and DS, which users cannot override. |
| AC-4, ✚AC-4(1)? | Flow enforcement: a message marked above the room ceiling is refused. AC-4(1)-style flow control by security attributes **(verify enhancement number)**. |
| AC-16, ✚AC-16(5) | AC-16 binds markings to messages, rooms and members. AC-16(5) covers attribute display, i.e. banners and portion marks in clients. |
| ✚AC-2 | Membership lifecycle. A debrief or clearance loss must trigger MLS Remove across all affected rooms. |
| ✚AC-6 | Least privilege. Sysadmins operate the DS but are not group members, which is the whole thesis. |
| ✚AC-21 | Information sharing decisions: the discovery card → access request → owner approval flow. |
| ✚AC-24 / ✚AC-25 | AC-24 makes the access decision a distinct, auditable function (the pure `policy` crate). AC-25 reference monitor: a small, tamper-evident policy point. Claim it only if the code earns it. |
| AU-2, ✚AU-3, ✚AU-12 | AU-2 defines the events (membership change, policy denial, marking change, export, key change). AU-3 sets record contents. AU-12 covers generation. |
| ✚AU-6 | Provide review tooling. The site does the reviewing. |
| AU-9, ✚AU-9(3) | Protect audit information with cryptographic protection. The Merkle log plus signed checkpoints is the implementation. |
| AU-10, ✚AU-10(1) | AU-10 non-repudiation comes from MLS signatures logged with hashes. AU-10(1) associates identities with the information. |
| ✚AU-11 | Retention, delivered through the records custodian member. The value is site-set. |
| IA-2, ✚IA-2(1)(2), ✚IA-2(12) | MFA for privileged and non-privileged users. IA-2(12) means accepting PIV credentials (CAC). |
| ✚IA-5(2) | PKI-based authentication: path validation to DoD/IC roots. |
| SC-8, ✚SC-8(1) | Transmission confidentiality via cryptography: MLS plus TLS. |
| SC-12, ✚SC-12(3) | Key establishment and management; asymmetric keys. |
| SC-13 | Use the CNSA 2.0 suite. Note that "NSA-approved" is the deployer's determination. |
| ✚SC-16, ✚SC-16(1) | Transmission of security attributes, with integrity: the marking travels signed inside MLS content. This is an underused control that fits GARBLE well. |
| ✚SC-17 | PKI certificates. |
| ✚SC-23 | Session authenticity. |
| SC-28, ✚SC-28(1) | Protection at rest with cryptography: client stores, blob store. |
| ✚SI-7, SI-7(1)(6)(15), ✚SI-7(12) | Software integrity and code authentication. These matter most for the web tier (§4) and the updater. |
| ✚SA-24 | Design for cyber resiliency (new in 5.2.0). Cheap to document. |

**Dropped or left to the deployer:** PE, PS, MP, most of CM, SC-7 (boundary) and CP are inherited from the enclave. IA-8 (non-organizational users) and AU-16 (cross-organizational audit) wait until federation.

### ICD 503 (current version 25 Oct 2024)

This version supersedes the 2015 one ([ODNI PDF](https://archive.dni.gov/files/documents/ICD/ICD-503.pdf)). It applies to anything that processes SCI, so it covers any JWICS GARBLE deployment.

- **Zero Trust per NSM-8:** "eliminates implicit trust and instead requires continuous verification based on real-time information" (§D.1.b(3)). Attributes must be re-checked periodically, and pushed when revoked. Checking only at join is not enough.
- **User-attributable audit (§D.3.e):** "Community Shared Resources that generate user attributable audit records" must satisfy insider-threat investigative requirements, validated with CI/insider-threat offices. Design the audit schema with user activity monitoring consumers in mind, not just sysadmins.
- **Authorization per security fabric** ("Top Secret, Secret, or Unclassified", §D.2.d). One GARBLE deployment per fabric, and no cross-fabric features. Cross-domain is someone else's accredited product.
- **Reciprocity (§D.4):** IC elements accept each other's assessments, and Five Eyes authorizations, testing only "configuration differences". A reusable assessment package (OSCAL plus test evidence) is valuable for that reason.
- **Supply chain** risk is integral and managed under ICD 731. SBOMs, `cargo-deny` and vendoring are the inputs (Meridian already does this).

### ICD 501 / IC-ITD

- ICD 501 makes information stewards carry a "responsibility to provide" and authorized personnel a "responsibility to discover" and to request ([FAS mirror](https://irp.fas.org/dni/icd/icd-501.pdf)). That is the policy basis for discovery cards: making a room's *existence* discoverable is an expected behavior, not a leak.
- "Discoverable" is not "accessible." The card reveals that a room exists, its topic and its steward, and the steward adjudicates the request. Disputes escalate outside the system **(unverified: exact dispute path in ICD 501 / ICPG 501.2)**.
- The card itself needs a marking, and it may only be shown to users who dominate the card's marking. The policy must enforce that the card marking ≤ the room ceiling, and must flag that names and topics can themselves be classified (aggregation).
- **IC-ITD tech specs** ([ODNI CIO](https://www.dni.gov/index.php/who-we-are/organizations/ic-cio/ic-technical-specifications/trusted-data-format)): ISM is the canonical XML encoding of the markings Meridian models. EDH/ARH carry access rights. TDF (latest public V2021-NOV) wraps objects with their metadata. GARBLE should (a) take its CVE value lists from ISM, not hand-curated JSON, and (b) export transcripts and attachments as TDF objects. ARH's last public release is V3 (2013); the public versions are dated.

### DoDM 5205.07 Vols 1–4 (DoD SAP Security Manual)

Not fetched. Details below are **(unverified)**.

- **Vol 1 (General Procedures):** program access is granted per program by the program security office, and access rosters are authoritative. GARBLE's SAR attributes must come from that roster, and roster removal must propagate.
- **Vol 2 (Personnel Security):** indoctrination and debriefing. A debrief must trigger removal from every room carrying that SAR, followed by a new epoch so the debriefed member loses future content. MLS gives this cleanly, but it does not claw back history the member already saw.
- **Vol 3 (Physical Security):** inherited. SAP clients run only in accredited spaces, which fits the "no mobile" decision.
- **Vol 4 (Marking):** `SAR-<program identifier>`, HVSACO and WAIVED handling. Meridian's grammar already follows this. Verify against the current Vol 4 text before claiming conformance.

### DoDI 8500.01 (Cybersecurity)

Not fetched. Details below are **(unverified)**.

- **DoD PKI for identity.** CAC on NIPR, SIPR token on SIPRNet. GARBLE's enrollment must accept both.
- **IA-enabled products:** evaluated under NIAP / CNSSP 11. GARBLE has no obvious Protection Profile. The closest is the Application Software PP **(unverified)**. Expect this to come up at acquisition.
- **STIG/SRG compliance.** The Application Security and Development STIG will be applied to GARBLE's code and deployment. Read it before writing the DS.
- **Classified data needs NSA-approved crypto (CNSSP 15).** The key framing: on SIPR/JWICS, links are already protected by Type 1 encryptors. GARBLE's E2EE is defense in depth against *insiders and the operator*, not the primary transmission protection. Say this explicitly so nobody expects GARBLE to replace a TACLANE.

### DoDI 8510.01 (RMF for DoD Systems, 2022)

Not fetched. Details below are **(unverified)**.

- **Categorization** via CNSSI 1253 plus overlays; the Classified Information Overlay applies. Registration in eMASS.
- **Type authorization** for software deployed identically at many sites. This is the right model for GARBLE: one type ATO, with sites inheriting it and authorizing their local configuration.
- **Continuous ATO** is possible with mature DevSecOps evidence: CI-produced assessment results mapped to controls. This is another reason the OSCAL file and its tests should be generated in CI.
- SAP systems follow DoDM 5205.07 / JSIG instead.

### One framework not on the list that you should add

**DoDI 8170.01 and 44 U.S.C. 2911** (electronic messaging records). Official business on a non-official messaging account must be forwarded to an official account within 20 days. Auto-delete that destroys records violates records law. AWS markets Wickr's retention against 8170.01 ([AWS](https://aws.amazon.com/blogs/publicsector/us-government-agencies-can-communicate-collaborate-securely-with-aws-wickr)). This is the legal basis for the records custodian, and for making disappearing messages unavailable by design.

---

## 3. Crypto stack

### The target suite exists

[draft-ietf-mls-pq-ciphersuites-06](https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/) is dated July 2026 and is in WG Last Call. It defines **TBD11 `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87`**: ML-KEM-1024, AES-256-GCM, SHA-384 and ML-DSA-87. That is exactly the CNSA 2.0 algorithm set.

The draft defines no CNSA 2.0 profile and does not mention CNSA. Code points are still TBD until IANA assigns them.

### OpenMLS support

`openmls/traits/src/types.rs` on `main` ([GitHub](https://github.com/openmls/openmls/blob/main/traits/src/types.rs)) has:

- `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 = 0x0907`, the provisional code point for TBD11
- an older `..._SHA512_MLDSA87 = 0x0906`
- X-Wing suites

All of these sit behind the `draft-ietf-mls-pq-ciphersuites` Cargo feature. Hybrid P-384 suites (TBD5) are commented out for lack of an implementation.

Earlier, OpenMLS shipped X-Wing (`0x004D`) for harvest-now-decrypt-later (HNDL) protection ([Cryspen](https://cryspen.com/post/pq-openmls/)).

**Not verified:** which OpenMLS crypto provider (`openmls_libcrux_crypto` or `openmls_rust_crypto`) actually implements ML-DSA-87 signing for 0x0907, and whether a crates.io release (vs. `main`) includes it. This is the first thing to check when coding starts.

### libcrux

`libcrux-ml-kem` is formally verified with hax/F*, covers all three parameter sets, and has portable, AVX2 and NEON backends ([docs.rs](https://docs.rs/libcrux-ml-kem)). The project describes its crates as pre-release (<0.1) and asks users to contact the maintainers before production use.

Caution: Symbolic Software reported FIPS 204 violations in libcrux's ML-DSA runtime code. It also found a wrong spec that made the AVX2 proofs unsound. Fixes were merged on 4 March 2026 ([Symbolic Software](https://symbolic.software/blog/2026-03-23-crucible)). "Formally verified" is not "validated": libcrux is not a FIPS 140-3 CMVP module.

### How close to CNSA 2.0 can we get today?

- **Algorithms: fully.** TBD11 is a match.
- **Pure, not hybrid.** NSA "will not require NSS developers to use hybrid certified products for security purposes" ([PQShield summary of the CNSA 2.0 FAQ](https://pqshield.com/nsa-releases-update-to-cnsa-2-0/)). The X-Wing suites rely on X25519/Ed25519, which are not CNSA algorithms. Use pure TBD11.
- **Timeline pressure.** Per CNSSP 15 as reported, new NSS acquisitions must be CNSA 2.0 compliant from 1 Jan 2027 ([postquantum.com](https://postquantum.com/cnsa-2-0/complete-guide/)), secondary source. Algorithm agility is therefore table stakes.
- **Validation: no.** "Compliant" needs validated modules. Meridian already routes through AWS-LC FIPS. Whether AWS-LC's validated boundary covers ML-KEM-1024 and ML-DSA-87 today is **(unverified)**. A plausible path is to keep libcrux for development and put an AWS-LC-backed OpenMLS crypto provider behind a `fips` feature, mirroring Meridian.
- **The authentication gap: CAC/PIV can't do ML-DSA.** NIST's PQC updates to PIV (SP 800-78-6 and SP 800-73-6) are *initial working drafts* from June 2026, with a dual-stack model ([NIST](https://csrc.nist.gov/News/2026/pqc-updates-to-piv-standards-working-drafts)). Fielded cards are years out. So the MLS ML-DSA-87 signature key must live in software or an HSM, bound to the person by a credential issued at CAC-authenticated enrollment. The CAC signs (ECDSA/RSA) an attestation over the ML-DSA public key. This is acceptable: quantum forgery of signatures is not an HNDL threat, and confidentiality (ML-KEM) is the urgent half.

### RFC 9420: can the DS inspect and reject handshakes? Yes, with caveats.

From [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420):

- **§6:** "Applications MUST use PrivateMessage to encrypt application messages and SHOULD use PrivateMessage to encode handshake messages, but they MAY transmit handshake messages encoded as PublicMessage objects in cases where it is necessary for the Delivery Service to examine such messages."
- **§16.11:** "a DS could enforce a policy that only certain members are allowed to perform these operations… a DS could help ensure that only clients with certain types of credentials are admitted."

Caveats GARBLE must design around:

1. **The DS cannot check `membership_tag`.** It needs `membership_key`, which is a group secret (§6.2). The DS *can* verify the sender's signature, but only if it tracks the group's public ratchet-tree state. GARBLE's DS must therefore keep a public view of each group.
2. **Reject PrivateMessage handshakes.** The DS must reject any handshake sent as PrivateMessage. `wire_format` is visible, so this is enforceable. Room policy should be pinned in a GroupContext extension plus `required_capabilities` (§11.1), so clients enforce the same rule.
3. **Hold Welcomes until the Commit is accepted.** The Welcome is encrypted, but the Add proposal's KeyPackage (credential plus attributes) is inside the PublicMessage Commit, which is what the DS evaluates. Per §14, Welcome "MUST NOT be delivered… until it's clear that the Commit has been accepted". The DS is the natural sequencer.
4. **A compromised DS can drop or delay but not forge** (§16.9). Client-side policy enforcement is what stops a malicious DS from *admitting* someone. Both sides enforcing it is the right call.
5. **Membership metadata is visible to the DS** (§16.4). For GARBLE that is a feature (accountability), but the DS and its log are then classified at the fabric level.

### MIMI

[draft-ietf-mimi-protocol-06](https://datatracker.ietf.org/doc/html/draft-ietf-mimi-protocol-06) is dated April 2026 and expires October 2026. It is not an RFC. It uses MLS with a hub-provider model plus room policy. **Implication:** GARBLE's DS maps naturally onto a MIMI hub. Encode room policy so it could later be expressed as MIMI room policy, but build no federation now.

---

## 4. Clients

### PIV/CAC via PKCS#11 from Tauri: feasible

The Tauri backend is native Rust. It can load the platform PKCS#11 module (OpenSC, or vendor middleware such as ActivClient on Windows) through the `cryptoki` crate **(unverified: crate maturity and current API)**. The webview never touches the card, and PIN entry stays in native code.

Practical constraints:

- PIV keys are RSA or ECC P-256/P-384 only, so they are not post-quantum (§3).
- Each card signature requires the PIN and takes noticeable time.
- Middleware differs per OS.

**Recommendation:** use the CAC for enrollment, plus optionally for rare high-value actions (room creation, ceiling changes, export approval). Do not use it per message. Key storage behind a trait, as planned, is the right seam.

### Integrity of web-delivered E2EE code

- **Deployed approaches:** Meta Code Verify and FPF's WEBCAT ([Mozilla Hacks, May 2026](https://hacks.mozilla.org/2026/05/trustworthy-javascript-for-the-open-web/)).
- **WAICT** is the W3C-backed effort to build this into browsers. A site binds its code to a manifest committed to a public log, and the browser rejects unlogged code. There is a Firefox Nightly prototype ([Cloudflare](https://blog.cloudflare.com/improving-the-trustworthiness-of-javascript-on-the-web/)).
- **Problem for GARBLE:** all of these assume a *public* log and internet reachability. On an air-gapped fabric, GARBLE's own transparency log (§5) could host the code manifests. Verification would still need a managed browser extension (GPO-deployed) until WAICT ships in enterprise browsers.

**Conclusion:** the web tier stays lower-assurance. Enforce that cryptographically, not by policy memo: put a `client_tier` attribute in the leaf credential, and let rooms set a minimum tier.

---

## 5. Audit log

### Options

- **`ct-merkle`** ([docs.rs](https://docs.rs/ct-merkle)): RFC 6962 tree with inclusion and consistency proofs. Small and focused. Pre-1.0.
- **`siglog`:** a Rust C2SP tlog-tiles server on OpenDAL/sea-orm. Young.
- **`metamorphic-log`:** claims RFC 6962/9162, tlog-tiles, witnessed checkpoints and PQ signing. Maturity unknown **(unverified)**.
- **Trillian / Tessera:** mature, but Go. That breaks the Rust-only story and adds a service to accredit.
- **Meridian's `merkle.rs`:** not read this pass. Check whether it hashes RFC 6962-style (`0x00`/`0x01` domain separation).

### Recommendation: build a thin log on standard formats

- RFC 6962/9162 tree hashing. Use `ct-merkle` for proofs, or Meridian's code if it is compatible.
- C2SP **tlog-tiles** static layout, so the log is files that any verifier can mirror.
- C2SP **signed-note checkpoints**, signed with ML-DSA-87.
- **Witness cosignatures** from independent holders. The records custodian and the ISSM's tool are natural witnesses, so the operator cannot fork the log unseen.

The storage and signing glue is a few hundred lines. Adopting a young server crate would add more to accredit than it saves.

**What goes in the log:** handshake events (the PublicMessage hash, sender, epoch, policy decision with reason) and per-application-message `(hash(ciphertext), sender leaf, epoch, timestamp)` for AU-10. No plaintext. Content retention is the custodian's job.

---

## 6. OSCAL component definition

The latest OSCAL release is **v1.2.3** (7 Aug 2026), per the GitHub releases API. Required fields below come from `oscal_component_schema.json` in that release:

| Object | Required | Useful optional |
|---|---|---|
| root `component-definition` | `uuid`, `metadata` | `components`, `capabilities`, `back-matter` |
| `metadata` | `title`, `last-modified`, `version`, `oscal-version` | `parties`, `roles`, `responsible-parties` |
| `components[]` | `uuid`, `type`, `title`, `description` | `purpose`, `props`, `links`, `responsible-roles`, `protocols` |
| `control-implementations[]` | `uuid`, `source`, `description`, `implemented-requirements` | `set-parameters`, `props` |
| `implemented-requirements[]` | `uuid`, `control-id`, `description` | `statements`, `set-parameters`, `responsible-roles`, `links`, `props` |

A minimal useful file for GARBLE follows. It is not validated in this pass; run it through `oscal-cli` when written.

```json
{ "component-definition": {
  "uuid": "…",
  "metadata": { "title": "GARBLE", "last-modified": "2026-10-04T00:00:00Z",
                "version": "0.1.0", "oscal-version": "1.2.3" },
  "components": [{
    "uuid": "…", "type": "software", "title": "GARBLE delivery service",
    "description": "Routes MLS ciphertext; enforces room policy on PublicMessage handshakes.",
    "control-implementations": [{
      "uuid": "…",
      "source": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
      "description": "NIST SP 800-53 Rev 5 controls implemented by the DS.",
      "implemented-requirements": [{
        "uuid": "…", "control-id": "ac-3.3",
        "description": "Rejects Add/Commit when the joiner's signed attributes do not dominate the room ceiling. See crates/policy/src/decide.rs.",
        "links": [{ "href": "https://…/crates/policy/src/decide.rs", "rel": "reference" }]
      }]
    }]
  }]
}}
```

Use one `component` per deployable (DS, desktop client, web client, log, custodian) so a site can inherit selectively.

- **Control IDs** are lowercase and dotted (`ac-3.3`). Confirm the enhancement format against the catalog **(unverified)**.
- **`source`** should eventually point at a CNSSI 1253 or JSIG *profile*, not the raw catalog, if one exists in OSCAL form **(unverified: none found in this pass)**.
- **Tie each `implemented-requirement` to a test** so CI can produce assessment results for cATO.

---

## 7. Prior art

**ChatSurfer.** I could not find authoritative public detail. The only hit was a [CSIAC inquiry](https://csiac.dtic.mil/technical-inquiries/notable/can-you-provide-information-and-a-government-point-of-contact-for-the-chatsurfer-software/) with no body. From background knowledge **(unverified)**: it is a web front end that aggregates XMPP chat rooms across SIPR/JWICS, with persistent history, cross-room search and keyword alerting, and heavy use in operations centers.

- **Take:** search and alerting are the killer features. Analysts live in dozens of rooms at once.
- **Avoid:** server-side plaintext that every admin can read. GARBLE's tension is that E2EE breaks server-side search, so search must happen client-side over rooms the user holds. That is a real UX cost; plan for it early.

**AWS Wickr.** E2EE messaging with FedRAMP High and DoD IL4/IL5 in GovCloud ([AWS](https://aws.amazon.com/blogs/messaging-and-targeting/aws-wickr-achieves-dod-impact-level-4-and-5-authorization)). Retention is done by a data-retention bot that sits in conversations, now also as a managed service (July 2026).

- **Take:** it validates the "visible records custodian member" design almost exactly.
- **Avoid:** proprietary protocol, no classification ceiling, no attribute policy, and no public evidence of classified-fabric authorization.

**Matrix/Element in government.** BwMessenger (Bundeswehr, up to VS-NfD on issued devices), Tchap (France, ~350K DAU), BundesMessenger, and NATO NI2CE ([Element](https://element.io/blog/nato-ni2ce-messenger-utilises-the-power-of-decentralised-communication/)).

- **Take:** sovereign self-hosting and federation between national deployments are the proven draws, and the federation model is a useful reference for later.
- **Avoid:** Megolm/Olm group crypto (no PCS at group level, so MLS is the better base), and the operational weight of a full federated homeserver. Their ceiling is restricted / VS-NfD, not SECRET and above.

**Mattermost in DoD.** Mattermost shipped *server-enforced* ABAC on clearance and other attributes (v10.9+) and classification banners per instance and channel (v11.8), with air-gapped support ([docs](https://docs.mattermost.com/administration-guide/manage/admin/attribute-based-access-control.html), [v11.8](https://mattermost.com/blog/mattermost-v11-8-is-now-available/)). This is the closest competitor feature-for-feature.

- **Take:** the UX of banners and ABAC rule editing.
- **Differentiate on:** Mattermost's enforcement is in the server, so a sysadmin can bypass it. GARBLE's thesis, cryptographic need-to-know against the operator, is precisely what Mattermost lacks. Lead every pitch with this.

---

## Decisions this research supports

1. **Ciphersuite:** pure TBD11 `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87` via OpenMLS's `draft-ietf-mls-pq-ciphersuites` feature, at OpenMLS's provisional code point 0x0907. Make the suite a single constant so the IANA re-number is a one-line change. No X-Wing; no hybrid.
2. **All handshakes as PublicMessage.** The DS rejects PrivateMessage handshakes and keeps a public tree view per group. Room policy lives in a GroupContext extension listed in `required_capabilities`. The DS holds Welcomes until the Commit is sequenced.
3. **Policy enforcement in both places.** The same `policy` crate runs in the client and the DS. The client side is what defeats a malicious DS; the DS side is what gives the operator accountability and fast rejects.
4. **CAC for enrollment only.** The CAC signs an attestation binding the user's ML-DSA-87 MLS key. Revisit when SP 800-78-6 cards exist.
5. **Extract `markings` from Meridian** with the refactors in §1. Fix the REL TO ordering bug first. Add `Clearance` + `dominates()` and a strict no-`Other` mode.
6. **Audit log:** build thin on RFC 6962 hashing + C2SP tlog-tiles + signed-note checkpoints (ML-DSA-87) + witness cosigning. Evaluate Meridian's `merkle.rs` and `ct-merkle` for the proof code.
7. **Records:** records custodian member on by default. No disappearing-message feature at all. Cite DoDI 8170.01 / 44 U.S.C. 2911.
8. **Client tier as a credential attribute,** so rooms can refuse web clients cryptographically.
9. **OSCAL:** one component per deployable, OSCAL 1.2.3, generated and validated in CI, each requirement linked to code and a test. Expose site-set values (retention, review cadence, banner text) as `set-parameters`.
10. **Positioning:** state plainly that GARBLE is insider/operator defense in depth on an already-encrypted fabric, not a Type 1 replacement, and that it never spans fabrics.

## Open questions for Joe

1. **Shared crate home:** move `markings` into its own repo (both projects depend on it) or keep it in Meridian's workspace and publish? I'd lean to its own repo, since the ISM CVE register data wants its own update cadence.
2. **Attribute authority:** who signs clearance/compartment attributes in a real deployment? A GARBLE-run attribute authority fed by the personnel-security system, or credentials issued by an existing IdP? This decides the trust root and how revocation propagates.
3. **History after debrief:** MLS removal stops *future* access. Do you want clients to also purge local history for rooms a user is removed from? It is unenforceable against a malicious client, but it matters for policy optics.
4. **Search:** client-side search only, or a cleared, accredited "search custodian" member (like the records custodian) that indexes plaintext for the rooms it is in? The second is ChatSurfer-like and carries a big accreditation cost.
5. **SAP support in v1:** SAR rooms pull in JSIG and DoDM 5205.07 and a different AO chain. Should v1 be collateral + SCI only?
6. **CUI as a level:** keep Meridian's `U < CUI < C` ordering, or model CUI as an orthogonal category?
7. **FIPS path:** ship a libcrux-only build first and add an AWS-LC `fips` provider later (Meridian's pattern), or block on validated modules?
8. **Web tier:** keep it at all for v1, given that §4 shows code integrity is unsolved on air-gapped fabrics?

---

## Budget report

- **Web searches: 19 / 20.**
- **Page fetches: 10 / 15.** That is 3 WebFetch calls, 2 WebFetch redirect stubs (counted conservatively), and 5 `curl` downloads: OpenMLS `types.rs`, RFC 9420, the ICD 503 PDF, the OSCAL releases API and the OSCAL component schema.
- **Not reachable or not attempted:**
  - JSIG text: no official copy found.
  - ChatSurfer detail: the CSIAC page has no body.
  - DoDM 5205.07, DoDI 8500.01, DoDI 8510.01 and ICD 501: not fetched, for budget. Bullets are marked (unverified) where they go beyond search snippets.
  - OSCAL reference site: the page didn't render; the schema was used instead.
