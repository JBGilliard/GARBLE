# Spike results (architecture §11.1)

Date: 2026-10-04. Code: `spike/src/main.rs`. Run with `cargo run -p spike` (or `cargo test -p spike`).
Versions: openmls 0.9.0, openmls_traits 0.6.0, openmls_rust_crypto 0.6.0, openmls_basic_credential 0.6.0, all with `draft-ietf-mls-pq-ciphersuites`. Ciphersuite `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87` (0x0907).

The scenario has three parties. Alice creates a room with a private-use GroupContext extension (0xF0A0, standing in for `RoomPolicyExt`), lists the DS in `external_senders`, and puts both private-use types in `required_capabilities`. The DS tracks the group with `PublicGroup` from an exported GroupInfo and ratchet tree. Alice adds Bob, and Bob joins from the Welcome using the ratchet tree *served by the DS*. The DS then proposes Remove(Bob), Alice commits it, and the DS sequences that commit. Every message goes through TLS serialization and back, to simulate the wire.

## Results

| Check | Result | Proof (spike/src/main.rs) | Fallback needed |
|---|---|---|---|
| **(a)** `PublicGroup` reads a private-use GroupContext extension | **PASS** | `PublicGroup::from_external` at :120, then `group_context().extensions().unknown(0xF0A0)` at :133 returns the exact bytes. Bob's joined group sees the same at :204 | None |
| **(b)** An `external_senders` Remove proposal is accepted and committable by a member | **PASS** | `ExternalProposal::new_remove` signed by the DS key at :250. Alice processes it (`Sender::External`), stores it, and commits it with `commit_to_pending_proposals` at :302. The DS's `PublicGroup` processes and merges that commit. Bob processes his own removal and becomes inactive (:340) | None |
| **(c)** Leaves carry a custom credential type | **PASS** | `CredentialType::Other(0xF0A1)` at :37. Every member, in Alice's and the DS's views, has that type (:213). The DS reads it from the Add proposal's KeyPackage while the Add commit is still staged. That is the inspection hook the sequencer's `decide` needs | None |
| **(d)** *(extra)* Handshakes are PublicMessage and application messages PrivateMessage under one policy; `PublicGroup` refuses PrivateMessage | **PASS** | Groups use `PURE_PLAINTEXT_WIRE_FORMAT_POLICY`. In openmls 0.9 that policy governs **handshake framing only**: application messages are still encrypted, and the incoming check applies only to handshakes. The DS's `process_message` returns `IncompatibleWireFormat` for the app message (:232), and Bob decrypts it normally | None |

All three §11.1 questions pass, so none of the §11.1 fallbacks applies.

## Findings that change assumptions

1. **`openmls_libcrux_crypto` 0.4.0 does not support 0x0907. This contradicts §11.1.** Its published `supports()` accepts only Ed25519 signatures, and `supported_ciphersuites()` lists only X25519 and X-Wing suites. The ML-DSA support that §11.1 found is on `main` only. The spike pins this down with `libcrux_provider_rejects_0x0907()` (:73). Creating the group with the libcrux provider fails with `UnsupportedCiphersuite`.
2. **`openmls_rust_crypto` 0.6.0 does support 0x0907** in `supports()`. It uses the RustCrypto `ml-dsa` 0.1 crate for signatures and `hpke-rs-rust-crypto` for ML-KEM-1024. Oddly, it doesn't list 0x0907 in `supported_ciphersuites()`, so code that negotiates suites from that list won't see it. The spike runs on this provider. It is neither libcrux (not formally verified) nor validated. See `docs/open-questions.md` Q1.
3. **The target of an external Remove must also receive the proposal.** A member can process a commit only if it already holds the by-reference proposals the commit covers. Otherwise it fails with `InvalidCommit(MissingProposal)`. So the DS must fan its own proposal out to all members *before* the commit, the target included (:273). §5.6 and §5.7 draw only DS → custodian.
4. **Leaf capabilities must list the private-use types.** Both the KeyPackage (`leaf_node_capabilities`) and the creator's group config need `ExtensionType::Unknown(0xF0A0)` and `CredentialType::Other(0xF0A1)`. Otherwise `required_capabilities` rejects them. This is expected, but `client` has to set it on every KeyPackage.
5. **OpenMLS does not validate custom credentials,** as expected. Content validation (EA signature, expiry) belongs to `identity`, and it must run wherever a leaf appears: in the DS's commit staging, in `StagedWelcome` before `into_group`, and in member commit processing.
