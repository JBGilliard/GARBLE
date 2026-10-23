# GARBLE

A reference design, with a Rust implementation, for end-to-end encrypted group messaging
on classified networks. MLS (RFC 9420) with a
CNSA 2.0 ciphersuite, every message signed and logged, and need-to-know enforced by
every client as well as the server: someone without the right clearance and
compartments can't be added to a room, and the refusal is logged.

Scope and build order: [`docs/idea-v1.md`](docs/idea-v1.md). Design detail:
[`docs/architecture.md`](docs/architecture.md). Open design problems:
[`docs/open-questions.md`](docs/open-questions.md).

## Status: walking skeleton

One box, CLI only. It shows the core thesis end to end:

```
scripts/demo.sh
```

That script starts a delivery service and three users. Alice creates a `TS//SI/TK//NF`
room. Adding Bob (no TK) is refused by Alice's client, and again by the DS when she
forces it. Carol is added and reads Alice's marked message. A message above the
ceiling is refused. A forged identity header gets 401, and enrolling with a copy of
someone else's credential is refused and logged. Then membership over time: a steward
removes Erin; Carol is debriefed and removed; Dave's credential expires, he is
suspended, refreshes, and is back; Frank stays expired and the steward's cleanup
removes him. Each removed client purges its copy and reports it. Dave acks a message
and Alice sees a signed ROGER; Alice forwards a message into a DM (marking kept), and a
forward above the DM's ceiling is refused and logged. It prints the audit log, verifies
it against the DS's signed checkpoint (`garble log verify`), then restarts the DS with a
rolled-back log: clients raise an integrity alert and stop sending.

| Real | Stand-in for now (marked `ponytail:` in the code) |
|---|---|
| MLS on `0x0907` (ML-KEM-1024, ML-DSA-87) | Provider is `openmls_rust_crypto`, not libcrux (open question Q1) |
| CAPCO markings: parse, dominance, ceilings (`markings`) | Sample registers, no signed trust bundle |
| One `policy::decide`, run by client and DS | Create / Add / Remove / Send / ReadArchive; no policy changes or cards yet |
| Expiry suspends (sends refused, nothing delivered; refresh resumes). `Remove` is a steward act: debriefs (DS asks the steward) and `cleanup` of long-expired members; removed clients purge and report | Purge covers MLS state only; cleanup runs when an admin invokes it (timer is the deployer's cron) |
| Issuer-signed attribute credentials (ML-DSA-87), bound to the user's key | Mock issuer; no CAC enrollment; MLS credential is a bare user ID |
| Sessions: client signs a DS challenge with its ML-DSA-87 key, gets a bearer token | Tokens in DS memory, one session per CLI run; no key rotation |
| Handshakes public, DS tracks group state, holds Welcomes | DS is single-threaded and in-memory; plain HTTP |
| Every decision logged with a reason code, in an RFC 6962 Merkle log (C2SP tlog-tiles layout) with an ML-DSA-87 signed checkpoint after every request; entries readable only by those cleared for their marking | No witnesses or cosignatures yet; first checkpoint is trusted on first use. Clients pin the last checkpoint and refuse one that isn't signed or doesn't extend it (alert, sending stops, reads continue); `garble log verify` proves every readable entry is in the tree |
| Client state (MLS groups, cursors, history) in one SQLCipher file; purge deletes a room's rows and its MLS group in one commit | The DB key sits in a file beside the dev signing key, not in a keychain or on a card |

## Files and the records archive

```
scripts/archive-demo.sh
```

`garble send-file ROOM --marking M FILE` encrypts the file under a fresh AES-256-GCM key; the
DS stores only ciphertext, addressed by its SHA-384, and the key travels inside the MLS
message. Members `garble fetch ROOM SEQ`. A blob is uploaded under the marking of the message
it precedes and decided by the same policy; the message names the blob in its signed header, and
the log entry records it.

Every message also carries a copy sealed (HPKE, ML-KEM-1024, room as `info`) to the room's
custodian key. The DS refuses a message without its copy. `garble-custodian` pulls the copies
into an append-only store; it holds no private key. Opening is `garble archive-permit ROOM
--reason TEXT --out FILE` (the DS decides `ReadArchive`, logs it, and denies anyone who isn't
a listed records officer cleared for the room) followed by `garble-custodian read ROOM --permit
FILE --key archive-private.hex`. Each permit opens once. The key holder can still skip the
procedure: open question Q16 says where the gap is. A copy has to hold the same envelope the
members received (its hash is in the signed AAD), or the custodian reports it as bad.

## Desktop console

A Tauri 2 window over the same client core. It opens an identity made by `garble init` and
`garble enroll`; it doesn't enroll yet.

```
scripts/desktop-demo.sh       # seeds a DS with alice, bob and two rooms; opens alice's console
garble-desktop --home DIR     # or GARBLE_HOME=DIR, against a DS you already run
```

Needs Node 22+ for the UI (`cd crates/garble-desktop/ui && npm ci && npm run build`; the
app embeds `ui/dist` at compile time). On Linux it needs webkit2gtk 4.1. For UI work without
a core, `npm run dev` serves it in a browser against a fake one.

The webview only sees rendered strings. Keys, MLS state and raw credentials stay in Rust, the
banner is computed by the core (`Marking::max`, not a string max), and the only commands it
may call are the ten in `build.rs` / `capabilities/main.json`. It polls the DS every two
seconds; there's no WebSocket in v1.

## Running across machines

The DS speaks plain HTTP, so don't put it on an untrusted network. Run it on a VPS or a
Tailscale node and let the tailnet carry and encrypt the traffic; there is no TLS in v1.
Bind to the tailnet address, not `0.0.0.0` on a public interface, unless the host's
firewall only admits the tailnet.

Build once per machine: `cargo build --release -p ds -p garble-cli` (binaries `garble-ds`
and `garble` in `target/release/`).

**1. DS log key (on the DS host), then the issuer (any one machine, your laptop is fine).**
The DS signs its log checkpoints with its own key; the trust bundle names the public half.

```
garble-ds keygen --key ds-log.key   # prints the public key (hex); keep the file on the DS host
garble issuer init --out issuer --log-key <HEX> --records-officers alice
```

`issuer/trust.json` is public: copy it to the DS host and every client machine. Keep
`issuer/issuer.json` on the issuer machine only. `issuer/archive-private.hex` is the
custodian's dev stand-in key; keep it off the DS and the clients too.

**2. DS host.**

```
tailscale ip -4                     # e.g. 100.64.0.7
garble-ds --listen 100.64.0.7:7777 --trust trust.json --log-dir garble-log --log-key ds-log.key
```

**3. Each client machine** (substitute the DS's tailnet address):

```
export DS=http://100.64.0.7:7777
garble --home ~/.garble init --user alice --ds $DS --trust trust.json
garble --home ~/.garble key          # prints the user's public key; send it to the issuer
```

**4. Back on the issuer machine**, issue each user's credential from the key they sent,
and hand the file back to them:

```
garble issuer issue --issuer issuer --user alice --key <HEX> --access 'TS//SI/TK//NF' --out alice.cred.json
```

**5. Each client** enrolls, then the machines talk:

```
garble --home ~/.garble enroll --credential alice.cred.json
garble --home ~/.garble create-room ops --ceiling 'TS//SI/TK//NF'     # machine A
garble --home ~/.garble add ops bob                                    # machine A
garble --home ~/.garble send ops --marking 'TS//SI//NF' "hello"        # machine A
garble --home ~/.garble read                                           # machine B
```

Gotchas:

- DS state lives in memory. Restarting it forgets users and rooms, so users re-enroll and
  rooms are recreated. The log in `--log-dir` persists and carries on; the DS refuses to
  start if that directory no longer matches the last checkpoint it signed.
- The DS refuses to start without a log key that matches `trust.json`.
- The log origin ends in the wire version (`garble-ds/v2`). A `--log-dir` left by an older
  wire version is refused at start. To retire one: stop the DS, then
  `garble-ds log seal --trust OLD_TRUST --log-dir DIR --log-key KEY`, and start the new DS
  on a fresh `--log-dir` with a bundle from `garble issuer init`. A sealed log stays
  checkable from its files alone: `garble log verify --offline DIR --trust OLD_TRUST`.
- `trust.json` without a custodian makes every `create-room` fail with `P-006`. That's
  deliberate.
- Credentials default to 8 hours (`--hours` or `--seconds` to change). An expired user is
  suspended until the issuer reissues.
- Check the DS is reachable from a client box first: `curl http://100.64.0.7:7777/v1/log/checkpoint`
  should answer `401`.

## Layout

`crates/`: `markings` and `policy` (pure), `proto` (wire types), `identity` (credentials,
shared room rules), `client`, `ds` (`garble-ds`), `garble-cli` (`garble`), `tlog` (Merkle log, tiles,
proofs, signed checkpoints), `garble-desktop` (Tauri console, UI in `ui/`), and `custodian` (`garble-custodian`).

## Checks

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings   # needs the UI built first (see above)
cargo test --workspace
cargo xtask check-deps          # architecture §3.1 dependency rules
cargo xtask oscal               # compliance/controls.toml -> oscal/component-definition.json
cargo deny check -D unmatched-wrapper
scripts/demo.sh
scripts/archive-demo.sh
```

Fuzzing (nightly, separate from the pinned toolchain; needs `cargo install cargo-fuzz`):

```
cd fuzz
cargo +nightly fuzz run marking_parse       # also: marking_canonical, wire_decode
```

## License

Apache-2.0. `crates/markings` adapts code from Meridian; see [NOTICE](NOTICE).
