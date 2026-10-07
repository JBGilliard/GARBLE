//! GARBLE CLI (architecture §3).
//!
//! ponytail: hand-rolled argument parsing and line output; a TUI and clap when the
//! command set stops fitting on one screen.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use client::{Client, Denied, Event, IntegrityAlert};
use identity::{AttributeIssuer, MockIssuer};
use proto::{Bytes, CustodianRef};

const USAGE: &str = "\
garble issuer init --out DIR --log-key HEX [--log-origin NAME] [--custodian ID] [--records-officers U,U]
garble --home DIR init --user U --ds URL --trust FILE
garble --home DIR key
garble issuer issue --issuer DIR --user U --key HEX --access MARKING [--citizenship USA] [--hours 8 | --seconds N] --out FILE
garble --home DIR enroll --credential FILE
garble --home DIR create-room ROOM --ceiling MARKING
garble --home DIR add ROOM USER [--skip-client-check]
garble --home DIR remove ROOM USER
garble --home DIR set-ceiling ROOM --ceiling MARKING
garble --home DIR dm USER --ceiling MARKING
garble --home DIR cleanup ROOM [--expired-for SECS]
garble --home DIR clear-fork ROOM --note TEXT
garble --home DIR send ROOM --marking MARKING TEXT
garble --home DIR ack ROOM SEQ
garble --home DIR forward FROM SEQ TO
garble --home DIR send-file ROOM --marking MARKING FILE
garble --home DIR fetch ROOM SEQ [--out DIR]
garble --home DIR archive-permit ROOM --reason TEXT --out FILE
garble --home DIR read
garble --home DIR log
garble --home DIR log verify";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => match (
            e.downcast_ref::<Denied>(),
            e.downcast_ref::<IntegrityAlert>(),
        ) {
            (Some(d), _) => {
                eprintln!("{d}");
                ExitCode::from(2)
            }
            (_, Some(alert)) => {
                eprintln!("{alert}");
                ExitCode::from(3)
            }
            _ => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        },
    }
}

/// `--flag value` lookup; bare flags are booleans.
struct Args(Vec<String>);

impl Args {
    fn opt(&mut self, flag: &str) -> Option<String> {
        let i = self.0.iter().position(|a| a == flag)?;
        self.0.remove(i);
        (i < self.0.len()).then(|| self.0.remove(i))
    }
    fn req(&mut self, flag: &str) -> Result<String> {
        self.opt(flag)
            .with_context(|| format!("missing {flag}\n\n{USAGE}"))
    }
    fn flag(&mut self, flag: &str) -> bool {
        let i = self.0.iter().position(|a| a == flag);
        i.map(|i| self.0.remove(i)).is_some()
    }
    fn pos(&mut self, what: &str) -> Result<String> {
        if self.0.is_empty() {
            bail!("missing {what}\n\n{USAGE}");
        }
        Ok(self.0.remove(0))
    }
}

fn run(args: Vec<String>) -> Result<()> {
    let mut a = Args(args);
    let home = a.opt("--home").map(PathBuf::from);
    let cmd = a.pos("command")?;
    match (cmd.as_str(), home) {
        ("issuer", _) => issuer(&mut a),
        ("init", Some(home)) => {
            let c = Client::create(
                &home,
                &a.req("--user")?,
                &a.req("--ds")?,
                &PathBuf::from(a.req("--trust")?),
            )?;
            println!("created identity {} in {}", c.user(), home.display());
            Ok(())
        }
        (cmd, Some(home)) => {
            let mut c = Client::open(&home)?;
            let result = act(&mut c, cmd, &mut a);
            c.save()?; // keep MLS state consistent even after a refusal
            result
        }
        (_, None) => bail!("--home DIR is required for {cmd}\n\n{USAGE}"),
    }
}

fn act(c: &mut Client, cmd: &str, a: &mut Args) -> Result<()> {
    match cmd {
        "key" => println!("{}", c.public_key_hex()),
        "log" if a.0.first().is_some_and(|v| v == "verify") => {
            a.0.remove(0);
            let r = c.verify_log()?;
            let from = r.from.map_or("first checkpoint".into(), |n| {
                format!("consistent with {n}")
            });
            println!(
                "checkpoint {} {} ({from}); {} entries you may read are in the tree, {} withheld by marking",
                r.size,
                &r.root[..16],
                r.verified,
                r.size - r.verified
            );
        }
        "log" => {
            for e in c.audit_log()? {
                let code = e.code.map(|c| format!(" [{c}]")).unwrap_or_default();
                println!(
                    "L-{:<3} {:<6} {:<6} {:<5} {:<20}{code} {}",
                    e.id, e.decision, e.actor, e.room, e.event, e.detail
                );
            }
        }
        "enroll" => {
            let cred = serde_json::from_slice(&std::fs::read(a.req("--credential")?)?)?;
            c.enroll(cred)?;
            println!("{} enrolled", c.user());
        }
        "create-room" => {
            let (room, ceiling) = (a.pos("ROOM")?, a.req("--ceiling")?);
            c.create_room(&room, &ceiling)?;
            println!("created {room} with ceiling {ceiling}");
        }
        "add" => {
            let skip = a.flag("--skip-client-check");
            let (room, user) = (a.pos("ROOM")?, a.pos("USER")?);
            c.add(&room, &user, !skip)?;
            println!("added {user} to {room}");
        }
        "set-ceiling" => {
            let ceiling = a.req("--ceiling")?;
            let room = a.pos("ROOM")?;
            c.set_ceiling(&room, &ceiling)?;
            println!("{room} ceiling is now {ceiling}");
        }
        "dm" => {
            let ceiling = a.req("--ceiling")?;
            let peer = a.pos("USER")?;
            let room = c.dm(&peer, &ceiling)?;
            println!("direct room {room} with {peer}");
        }
        "remove" => {
            let (room, user) = (a.pos("ROOM")?, a.pos("USER")?);
            c.remove(&room, &user)?;
            println!("removed {user} from {room}");
        }
        "clear-fork" => {
            let note = a.req("--note")?;
            let room = a.pos("ROOM")?;
            c.clear_fork(&room, &note)?;
            println!("{room} closed after fork investigation; recreate it with its honest members");
        }
        "cleanup" => {
            let secs = a
                .opt("--expired-for")
                .map(|s| s.parse())
                .transpose()?
                .unwrap_or(7 * 86400);
            let room = a.pos("ROOM")?;
            let removed = c.cleanup(&room, secs)?;
            println!("removed from {room}: [{}]", removed.join(", "));
        }
        "send" => {
            let marking = a.req("--marking")?;
            let (room, text) = (a.pos("ROOM")?, a.pos("TEXT")?);
            let seq = c.send(&room, &marking, &text)?;
            println!("sent to {room} #{seq}");
        }
        "ack" => {
            let (room, seq) = (a.pos("ROOM")?, a.pos("SEQ")?.parse()?);
            let at = c.ack(&room, seq)?;
            println!("acked {room} #{seq} as #{at}");
        }
        "forward" => {
            let (from, seq, to) = (a.pos("FROM")?, a.pos("SEQ")?.parse()?, a.pos("TO")?);
            let at = c.forward(&from, seq, &to)?;
            println!("forwarded {from} #{seq} to {to} #{at}");
        }
        "send-file" => {
            let marking = a.req("--marking")?;
            let (room, file) = (a.pos("ROOM")?, PathBuf::from(a.pos("FILE")?));
            let seq = c.send_file(&room, &marking, &file)?;
            println!("sent {} to {room} #{seq}", file.display());
        }
        "fetch" => {
            let out = a
                .opt("--out")
                .map_or_else(|| PathBuf::from("."), PathBuf::from);
            let (room, seq) = (a.pos("ROOM")?, a.pos("SEQ")?.parse()?);
            let path = c.fetch(&room, seq, &out)?;
            println!("fetched {room} #{seq} to {}", path.display());
        }
        "archive-permit" => {
            let (reason, out) = (a.req("--reason")?, a.req("--out")?);
            let room = a.pos("ROOM")?;
            let permit = c.archive_permit(&room, &reason)?;
            std::fs::write(&out, serde_json::to_vec_pretty(&permit)?)?;
            println!(
                "ReadArchive permitted for {room}, logged as L-{}; permit in {out}",
                permit.record.index + 1
            );
        }
        "read" => {
            for (room, e) in c.sync()? {
                match e {
                    Event::Joined { room } => println!("[{room}] joined"),
                    Event::JoinRefused { reason } => println!("[{room}] REFUSED TO JOIN: {reason}"),
                    Event::Message {
                        seq,
                        sender,
                        marking,
                        text,
                        forwarded_from,
                    } => {
                        let via = forwarded_from
                            .map(|f| format!(" [forwarded from {} in {}]", f.sender, f.room))
                            .unwrap_or_default();
                        println!("[{room} #{seq}] ({marking}) {sender}: {text}{via}")
                    }
                    Event::Ack {
                        seq,
                        sender,
                        of,
                        marking,
                    } => {
                        let of = of.map_or("a message this client doesn't have".into(), |n| {
                            format!("#{n}")
                        });
                        println!("[{room} #{seq}] ({marking}) ROGER from {sender} for {of}")
                    }
                    Event::Quarantined {
                        seq,
                        sender,
                        reason,
                    } => {
                        println!("[{room} #{seq}] QUARANTINED message from {sender}: {reason}")
                    }
                    Event::MembershipChanged {
                        seq,
                        by,
                        added,
                        removed,
                    } => {
                        if !added.is_empty() {
                            println!("[{room} #{seq}] {by} added {}", added.join(", "));
                        }
                        if !removed.is_empty() {
                            println!("[{room} #{seq}] {by} removed {}", removed.join(", "));
                        }
                    }
                    Event::CeilingChanged { seq, by, ceiling } => {
                        println!("[{room} #{seq}] {by} set the ceiling to {ceiling}")
                    }
                    Event::Purged { seq, by } => {
                        println!("[{room} #{seq}] removed by {by}; local copy purged and reported")
                    }
                    Event::LogAlert { reason } => {
                        println!("LOG INTEGRITY ALERT, sending stopped: {reason}")
                    }
                    Event::IntegrityHold { seq, reason } => {
                        println!(
                            "[{room} #{seq}] FORK DETECTED, room frozen and reported: {reason}"
                        )
                    }
                }
            }
        }
        _ => bail!("unknown command {cmd}\n\n{USAGE}"),
    }
    Ok(())
}

/// Stand-in for the site attribute authority. Its secret key lives in `--out` /
/// `--issuer`; `trust.json` beside it is what clients and the DS load.
fn issuer(a: &mut Args) -> Result<()> {
    match a.pos("issuer command")?.as_str() {
        "init" => {
            let dir = PathBuf::from(a.req("--out")?);
            std::fs::create_dir_all(&dir)?;
            let issuer = MockIssuer::generate()?;
            let (private, public) = identity::generate_archive_keypair()?;
            let mut trust = issuer.trust_bundle();
            // From `garble-ds keygen`. Without it the DS refuses to start, so the
            // bundle can't be made without one either.
            let origin = a.opt("--log-origin").unwrap_or_else(|| "garble-ds".into());
            identity::log::checked_origin(&origin)?;
            trust.log = Some(identity::LogRef {
                origin,
                key: Bytes(hex_decode(&a.req("--log-key")?)?),
            });
            trust.custodian = Some(CustodianRef {
                id: a.opt("--custodian").unwrap_or_else(|| "records".into()),
                archive_key: Bytes(public),
            });
            trust.records_officers = a
                .opt("--records-officers")
                .map(|s| s.split(',').map(str::to_owned).collect())
                .unwrap_or_default();
            std::fs::write(dir.join("issuer.json"), serde_json::to_vec(&issuer)?)?;
            std::fs::write(dir.join("trust.json"), serde_json::to_vec_pretty(&trust)?)?;
            // ponytail: dev only. In a deployment this key is generated and sealed
            // offline by the custodian; the issuer never sees it.
            std::fs::write(dir.join("archive-private.hex"), hex_encode(&private))?;
            println!(
                "issuer key in {0}/issuer.json, trust bundle in {0}/trust.json, archive key in {0}/archive-private.hex",
                dir.display()
            );
        }
        "issue" => {
            let dir = PathBuf::from(a.req("--issuer")?);
            let issuer: MockIssuer =
                serde_json::from_slice(&std::fs::read(dir.join("issuer.json"))?)?;
            let user = a.req("--user")?;
            let key = hex_decode(&a.req("--key")?)?;
            let access = a.req("--access")?;
            let citizenship = a.opt("--citizenship").unwrap_or_else(|| "USA".into());
            let secs: u64 = match (a.opt("--seconds"), a.opt("--hours")) {
                (Some(s), _) => s.parse()?,
                (None, h) => h.map(|h| h.parse::<u64>()).transpose()?.unwrap_or(8) * 3600,
            };
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let cred = issuer.issue(&user, &key, &access, &citizenship, now + secs)?;
            let out = a.req("--out")?;
            std::fs::write(&out, serde_json::to_vec_pretty(&cred)?)?;
            println!("issued {user}: {access} for {secs}s -> {out}");
        }
        other => bail!("unknown issuer command {other}\n\n{USAGE}"),
    }
    Ok(())
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("expected hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?))
        .collect()
}
