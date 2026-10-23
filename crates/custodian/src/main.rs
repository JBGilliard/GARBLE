//! `garble-custodian`: the records custodian's command line (architecture §5.9).
//!
//! ponytail: hand-rolled argument parsing, like `garble`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use client::{Client, Denied};
use identity::TrustBundle;
use markings::Marking;
use proto::{FILE, FileRef, TEXT_PLAIN};

const USAGE: &str = "\
garble-custodian --home DIR init --ds URL --trust FILE
garble-custodian --home DIR key
garble-custodian --home DIR enroll --credential FILE
garble-custodian --home DIR pull
garble-custodian --home DIR read ROOM --permit FILE --key FILE [--files DIR]

init makes the custodian's DS identity (named by the trust bundle) and prints its public key.
read needs a permit from `garble archive-permit` and the offline archive private key (hex).";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            match e.downcast_ref::<Denied>() {
                Some(d) => eprintln!("{d}"),
                None => eprintln!("error: {e:#}"),
            }
            ExitCode::FAILURE
        }
    }
}

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
    fn pos(&mut self, what: &str) -> Result<String> {
        if self.0.is_empty() {
            bail!("missing {what}\n\n{USAGE}");
        }
        Ok(self.0.remove(0))
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn run(args: Vec<String>) -> Result<()> {
    let mut a = Args(args);
    let home = PathBuf::from(a.req("--home")?);
    match a.pos("command")?.as_str() {
        "init" => {
            let (ds, trust) = (a.req("--ds")?, PathBuf::from(a.req("--trust")?));
            let id = TrustBundle::load(&trust)?
                .custodian
                .context("trust bundle names no custodian")?
                .id;
            let c = Client::create(&home, &id, &ds, &trust)?;
            println!(
                "custodian identity {} in {}; `key` prints the public key to issue a credential for",
                c.user(),
                home.display()
            );
        }
        "key" => println!("{}", Client::open(&home)?.public_key_hex()),
        "enroll" => {
            let mut c = Client::open(&home)?;
            c.enroll(serde_json::from_slice(&std::fs::read(
                a.req("--credential")?,
            )?)?)?;
            c.save()?;
            println!("{} enrolled", c.user());
        }
        "pull" => {
            let c = Client::open(&home)?;
            let got = custodian::pull(&c, &home)?;
            println!(
                "pulled {} messages and {} files; {} held",
                got.entries,
                got.blobs,
                custodian::held(&home)?.len()
            );
        }
        "read" => {
            let room = a.pos("ROOM")?;
            let permit = serde_json::from_slice(&std::fs::read(a.req("--permit")?)?)?;
            let key = hex_decode(&std::fs::read_to_string(a.req("--key")?)?)?;
            let files = a.opt("--files").map(PathBuf::from);
            let trust = TrustBundle::load(&home.join("trust.json"))?;
            let reg = trust.registers();
            let opened =
                custodian::read(&home, &trust, &key, &room, &permit, now(), files.as_deref())?;
            for o in opened {
                let line = match o.record {
                    Ok(r) => serde_json::json!({
                        "n": o.n,
                        "room": r.room,
                        "seq": o.seq,
                        "sender": r.sender,
                        "sent_at": r.sent_at,
                        "marking": Marking::from_canonical(&r.marking.0, &reg)
                            .map_or_else(|e| format!("unreadable: {e}"), |m| m.portion()),
                        "content_type": r.envelope.content_type,
                        "msg_id": hex(&r.envelope.msg_id.0),
                        "forwarded_from": r.envelope.forwarded_from,
                        "body": match r.envelope.content_type.as_str() {
                            TEXT_PLAIN => String::from_utf8_lossy(&r.envelope.body.0).into_owned(),
                            FILE => proto::decode::<FileRef>(&r.envelope.body.0)
                                .map_or("unreadable file reference".into(), |f| {
                                    format!("[file] {} ({} bytes)", f.name, f.size)
                                }),
                            _ => hex(&r.envelope.body.0),
                        },
                        "file": o.file.map(|f| match f {
                            Ok(p) => p.display().to_string(),
                            Err(e) => format!("not exported: {e}"),
                        }),
                    }),
                    Err(why) => serde_json::json!({"n": o.n, "seq": o.seq, "unreadable": why}),
                };
                println!("{line}");
            }
        }
        other => bail!("unknown command {other}\n\n{USAGE}"),
    }
    Ok(())
}

fn hex(b: &[u8]) -> String {
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
