//! The feed and event logic, driven with synthetic sync events and an offline client.
//! What needs a DS (send, add, denial) is covered by scripts/desktop-demo.sh.

use std::sync::atomic::{AtomicU32, Ordering};

use identity::{AttributeIssuer, MockIssuer};

use super::*;

fn core() -> Core {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "garble-desktop-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let trust = dir.join("trust.json");
    let bundle = MockIssuer::generate().expect("issuer").trust_bundle();
    std::fs::write(&trust, serde_json::to_vec(&bundle).expect("json")).expect("write");
    let c =
        Client::create(&dir.join("home"), "alice", "http://127.0.0.1:1", &trust).expect("client");
    Core::new(c).expect("core")
}

fn msg(seq: u64, marking: &str) -> (String, Event) {
    (
        "ops".into(),
        Event::Message {
            seq,
            sender: "bob".into(),
            marking: marking.into(),
            text: format!("hello {seq}"),
            forwarded_from: None,
        },
    )
}

fn id(seq: u64) -> MsgId {
    MsgId {
        room: "ops".into(),
        seq,
    }
}

fn absorb(core: &Core, events: Vec<(String, Event)>) -> Vec<UiEvent> {
    core.inner.lock().expect("lock").absorb(events)
}

fn seqs(page: &Page<MessageView>) -> Vec<u64> {
    page.items.iter().map(|m| m.id.seq).collect()
}

#[test]
fn feed_stays_in_stream_order_and_ignores_repeats() {
    let c = core();
    let out = absorb(&c, vec![msg(3, "S//NF"), msg(2, "S//NF"), msg(3, "S//NF")]);
    let [UiEvent::MessagesAppended { room, items }] = &out[..] else {
        panic!("one coalesced event");
    };
    assert_eq!((room.as_str(), items.len()), ("ops", 2));
    assert_eq!(seqs(&c.open_room("ops", None, 10).unwrap()), [2, 3]);
}

#[test]
fn unread_clears_when_the_room_is_opened_and_stays_clear_while_focused() {
    let c = core();
    absorb(&c, vec![msg(1, "S//NF"), msg(2, "S//NF")]);
    let unread = |c: &Core| c.inner.lock().unwrap().feeds["ops"].unread();
    assert_eq!(unread(&c), 2);
    c.open_room("ops", None, 10).unwrap();
    assert_eq!(unread(&c), 0);
    absorb(&c, vec![msg(3, "S//NF")]);
    assert_eq!(unread(&c), 0);
    // Paging back isn't opening.
    c.inner.lock().unwrap().focused = None;
    absorb(&c, vec![msg(4, "S//NF")]);
    c.open_room("ops", Some(3), 10).unwrap();
    assert_eq!(unread(&c), 1);
}

#[test]
fn pages_walk_back_from_the_newest() {
    let c = core();
    absorb(&c, (1..=5).map(|n| msg(n, "U")).collect());
    let p = c.open_room("ops", None, 2).unwrap();
    assert_eq!((seqs(&p), p.older), (vec![4, 5], Some(4)));
    let p = c.open_room("ops", p.older, 2).unwrap();
    assert_eq!((seqs(&p), p.older), (vec![2, 3], Some(2)));
    let p = c.open_room("ops", p.older, 2).unwrap();
    assert_eq!((seqs(&p), p.older), (vec![1], None));
}

#[test]
fn a_marking_that_wont_parse_is_never_rendered() {
    let c = core();
    absorb(&c, vec![msg(1, "NOT-A-MARKING")]);
    let page = c.open_room("ops", None, 10).unwrap();
    let m = &page.items[0];
    assert_eq!(m.kind, Kind::Quarantined);
    assert!(m.marking.is_none());
    assert!(!m.text.contains("hello"));
}

#[test]
fn banner_is_the_high_water_mark_of_what_is_visible() {
    let c = core();
    absorb(&c, vec![msg(1, "S//NF"), msg(2, "TS//SI//NF"), msg(3, "U")]);
    let b = |ids: &[u64]| {
        let ids: Vec<_> = ids.iter().map(|n| id(*n)).collect();
        c.banner(&ids)
    };
    assert_eq!(b(&[1, 3]).unwrap().banner, "SECRET//NOFORN");
    assert_eq!(b(&[1, 2, 3]).unwrap().banner, "TOP SECRET//SI//NOFORN");
    assert_eq!(b(&[3]).unwrap().level, "U");
    assert!(
        b(&[]).is_err(),
        "zero markings is an error, not UNCLASSIFIED"
    );
    assert!(b(&[9]).is_err());
}

#[test]
fn quarantine_and_notices_add_nothing_to_the_banner() {
    let c = core();
    absorb(
        &c,
        vec![
            msg(1, "U"),
            (
                "ops".into(),
                Event::Quarantined {
                    seq: 2,
                    sender: "mallory".into(),
                    reason: "above ceiling".into(),
                },
            ),
            (
                "ops".into(),
                Event::MembershipChanged {
                    seq: 3,
                    by: "bob".into(),
                    added: vec!["carol".into()],
                    removed: vec![],
                },
            ),
        ],
    );
    assert_eq!(c.banner(&[id(1), id(2), id(3)]).unwrap().level, "U");
}

#[test]
fn a_quarantined_message_is_a_denial_not_content() {
    let c = core();
    let out = absorb(
        &c,
        vec![(
            "ops".into(),
            Event::Quarantined {
                seq: 2,
                sender: "mallory".into(),
                reason: "above ceiling".into(),
            },
        )],
    );
    assert!(
        out.iter()
            .any(|e| matches!(e, UiEvent::Denial(d) if d.reason == "above ceiling"))
    );
    let page = c.open_room("ops", None, 10).unwrap();
    assert_eq!(page.items[0].kind, Kind::Quarantined);
}

#[test]
fn being_removed_drops_the_room() {
    let c = core();
    absorb(&c, vec![msg(1, "U")]);
    let out = absorb(
        &c,
        vec![(
            "ops".into(),
            Event::Purged {
                seq: 2,
                by: "bob".into(),
            },
        )],
    );
    assert!(matches!(
        &out[..],
        [UiEvent::RoomChanged {
            change: "purged",
            ..
        }]
    ));
    assert!(c.open_room("ops", None, 10).is_err());
}

#[test]
fn names_that_could_reach_other_paths_are_refused() {
    for bad in [
        "",
        ".",
        "..",
        "a/b",
        "a b",
        "a?x=1",
        "..%2f",
        &"x".repeat(65),
    ] {
        assert!(name_ok(bad).is_err(), "{bad:?}");
    }
    for good in ["ops", "dm-alice-bob", "a.b_c@d"] {
        assert!(name_ok(good).is_ok(), "{good:?}");
    }
}

#[test]
fn an_unenrolled_client_says_so_and_no_one_can_send_blank_messages() {
    let c = core();
    assert!(matches!(
        c.inner.lock().unwrap().credential_state(),
        CredentialState::NotEnrolled
    ));
    assert!(c.send("ops", "U", "  ").is_err());
}
