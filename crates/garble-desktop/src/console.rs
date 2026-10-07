//! The application. Holds the one `Client`, the message feed the webview reads, and
//! turns what `sync` finds into events. No Tauri types in here except `UiEvent`, so
//! it's testable without a window.
//!
//! ponytail: the feed is in memory. Text messages come back from the client's own
//! store on start; acks, quarantines and notices don't, until the encrypted message
//! store (§7.2) exists.

use std::collections::BTreeMap;
use std::hash::{BuildHasher, Hasher};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use client::{Client, Event, Inclusion};
use markings::{Marking, aggregate};

use crate::events::UiEvent;
use crate::views::{
    CredentialState, Denial, DenialDetail, InclusionView, Kind, LogLine, MarkingCheck, MarkingView,
    MessageView, MsgId, Page, RoomSummary, UiError, Verdict, WatermarkSpec,
};

pub struct Core {
    inner: Mutex<Inner>,
}

struct Inner {
    client: Client,
    feeds: BTreeMap<String, Feed>,
    /// The room on screen. What arrives in it counts as read.
    focused: Option<String>,
    seed: String,
}

struct Item {
    view: MessageView,
    /// What the banner aggregates. Only messages and acks have one.
    marking: Option<Marking>,
}

#[derive(Default)]
struct Feed {
    /// Sorted by stream position, which is unique within a room.
    items: Vec<Item>,
    read: u64,
}

impl Feed {
    /// False if we already had it.
    fn insert(&mut self, item: Item) -> bool {
        let seq = item.view.id.seq;
        match self.items.binary_search_by_key(&seq, |i| i.view.id.seq) {
            Ok(_) => false,
            Err(at) => {
                self.items.insert(at, item);
                true
            }
        }
    }

    fn get(&self, seq: u64) -> Option<&Item> {
        let at = self
            .items
            .binary_search_by_key(&seq, |i| i.view.id.seq)
            .ok()?;
        self.items.get(at)
    }

    fn last_seq(&self) -> u64 {
        self.items.last().map_or(0, |i| i.view.id.seq)
    }

    fn unread(&self) -> u64 {
        self.items
            .iter()
            .filter(|i| i.view.kind == Kind::Message && !i.view.mine && i.view.id.seq > self.read)
            .count() as u64
    }
}

/// Room and user names go straight into DS URL paths, and nothing below validates them.
fn name_ok(s: &str) -> Result<(), UiError> {
    let fine = !s.is_empty()
        && s.len() <= 64
        && s.bytes().any(|b| b != b'.') // "." and ".." are path segments
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@'));
    if fine {
        Ok(())
    } else {
        Err(UiError::failed(format!(
            "{s:?} isn't a valid name (letters, digits and . _ - @, up to 64)"
        )))
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub struct Sent {
    pub id: MsgId,
    pub view: MessageView,
}

impl Core {
    pub fn new(client: Client) -> Result<Self> {
        // Random per run, not secret: it only has to tell two screenshots apart.
        let seed = format!(
            "{:016x}",
            std::collections::hash_map::RandomState::new()
                .build_hasher()
                .finish()
        );
        let mut inner = Inner {
            client,
            feeds: BTreeMap::new(),
            focused: None,
            seed,
        };
        for r in inner.client.rooms()? {
            let mut feed = Feed::default();
            for m in inner.client.history(&r.room) {
                feed.insert(
                    inner.message_item(&r.room, m.seq, &m.sender, &m.marking, m.text, None),
                );
            }
            // Whatever was already here when we started isn't news.
            feed.read = feed.last_seq().max(r.last_seq);
            inner.feeds.insert(r.room, feed);
        }
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, UiError> {
        self.inner
            .lock()
            .map_err(|_| UiError::failed("core state is poisoned after a crash; restart the app"))
    }

    /// Runs `f` on the client and saves, refused or not: MLS state moves on even when
    /// the DS says no, and the CLI does the same.
    fn act<T>(&self, f: impl FnOnce(&mut Client) -> Result<T>) -> Result<T, UiError> {
        let mut g = self.lock()?;
        let r = f(&mut g.client);
        g.save();
        Ok(r?)
    }

    // ───────────────────────────── sync ─────────────────────────────

    /// One sync round. Never fails: trouble becomes events.
    pub fn tick(&self) -> Vec<UiEvent> {
        let mut g = match self.lock() {
            Ok(g) => g,
            Err(e) => {
                return vec![UiEvent::Connection {
                    ok: false,
                    message: Some(format!("{e:?}")),
                }];
            }
        };
        let mut out = Vec::new();
        match g.client.sync() {
            Ok(events) => {
                out.push(UiEvent::Connection {
                    ok: true,
                    message: None,
                });
                if !events.is_empty() {
                    out.extend(g.absorb(events));
                    g.save();
                }
            }
            Err(e) => {
                // Sync is all or nothing: what it processed before failing was kept
                // by the client but never reported, so pick it up from there.
                g.save();
                out.extend(g.reconcile());
                out.push(UiEvent::Connection {
                    ok: false,
                    message: Some(format!("{e:#}")),
                });
            }
        }
        // Sent every round, not on change: a webview that loaded late missed the last one.
        out.push(UiEvent::CredentialState(g.credential_state()));
        out
    }

    // ──────────────────────────── commands ────────────────────────────

    pub fn list_rooms(&self) -> Result<Vec<RoomSummary>, UiError> {
        let mut g = self.lock()?;
        let rooms = g.client.rooms()?;
        Ok(rooms
            .into_iter()
            .map(|r| {
                let feed = g.feeds.entry(r.room.clone()).or_default();
                RoomSummary {
                    ceiling: MarkingView::of(&r.ceiling),
                    members: r.members,
                    stewards: r.stewards,
                    unread: feed.unread(),
                    last_seq: feed.last_seq().max(r.last_seq),
                    held: r.held,
                    room: r.room,
                }
            })
            .collect())
    }

    /// The newest `limit` items before `anchor`, oldest first. No anchor means the
    /// latest page, and counts as opening the room.
    pub fn open_room(
        &self,
        room: &str,
        anchor: Option<u64>,
        limit: usize,
    ) -> Result<Page<MessageView>, UiError> {
        let mut g = self.lock()?;
        let g = &mut *g;
        let feed = g
            .feeds
            .get_mut(room)
            .ok_or_else(|| UiError::failed(format!("not a member of {room}")))?;
        if anchor.is_none() {
            g.focused = Some(room.into());
            feed.read = feed.read.max(feed.last_seq());
        }
        let end = anchor.map_or(feed.items.len(), |a| {
            feed.items.partition_point(|i| i.view.id.seq < a)
        });
        let start = end.saturating_sub(limit.clamp(1, 500));
        Ok(Page {
            items: feed.items[start..end]
                .iter()
                .map(|i| i.view.clone())
                .collect(),
            older: (start > 0).then(|| feed.items[start].view.id.seq),
        })
    }

    pub fn create_room(&self, room: &str, ceiling: &str) -> Result<String, UiError> {
        name_ok(room)?;
        let mut g = self.lock()?;
        let r = g.client.create_room(room, ceiling);
        g.save();
        r?;
        g.feeds.entry(room.into()).or_default();
        Ok(room.into())
    }

    /// Checks as you type, so a refusal here is data, not an error, and nothing is
    /// reported to the DS.
    pub fn validate_marking(&self, room: &str, text: &str) -> Result<MarkingCheck, UiError> {
        let g = self.lock()?;
        let m = match g.client.parse_marking(text) {
            Ok(m) => m,
            Err(e) => {
                return Ok(MarkingCheck {
                    parsed: None,
                    decision: Verdict::Invalid {
                        code: e.code().into(),
                        reason: e.to_string(),
                    },
                });
            }
        };
        let decision = match g.client.check_send(room, &m)? {
            None => Verdict::Permit,
            Some(r) => Verdict::Deny {
                code: r.code,
                reason: r.reason,
            },
        };
        Ok(MarkingCheck {
            parsed: Some(MarkingView::of(&m)),
            decision,
        })
    }

    pub fn send(&self, room: &str, marking: &str, body: &str) -> Result<Sent, UiError> {
        if body.trim().is_empty() {
            return Err(UiError::failed("nothing to send"));
        }
        let mut g = self.lock()?;
        let r = g.client.send(room, marking, body);
        g.save();
        let seq = r?;
        // The send went through with this marking, so it parsed.
        let me = g.client.user().to_owned();
        let item = g.message_item(room, seq, &me, marking, body.into(), None);
        let (id, view) = (item.view.id.clone(), item.view.clone());
        let feed = g.feeds.entry(room.into()).or_default();
        feed.insert(item);
        feed.read = feed.read.max(seq);
        Ok(Sent { id, view })
    }

    pub fn add_member(&self, room: &str, user: &str) -> Result<MessageView, UiError> {
        name_ok(user)?;
        self.membership(room, user, true)
    }

    pub fn remove_member(&self, room: &str, user: &str) -> Result<MessageView, UiError> {
        name_ok(user)?;
        self.membership(room, user, false)
    }

    fn membership(&self, room: &str, user: &str, add: bool) -> Result<MessageView, UiError> {
        let mut g = self.lock()?;
        let r = if add {
            g.client.add(room, user, true)
        } else {
            g.client.remove(room, user)
        };
        g.save();
        let seq = r?;
        let me = g.client.user().to_owned();
        let text = if add {
            format!("you added {user}")
        } else {
            format!("you removed {user}")
        };
        let view = notice(room, seq, &me, text);
        let feed = g.feeds.entry(room.into()).or_default();
        feed.insert(Item {
            view: view.clone(),
            marking: None,
        });
        feed.read = feed.read.max(seq);
        Ok(view)
    }

    /// The high-water mark of what's on screen. Aggregation isn't a string max
    /// (NOFORN wins, REL TO intersects), so it stays here.
    pub fn banner(&self, visible: &[MsgId]) -> Result<MarkingView, UiError> {
        let g = self.lock()?;
        let mut markings = Vec::new();
        for id in visible {
            let item = g
                .feeds
                .get(&id.room)
                .and_then(|f| f.get(id.seq))
                .ok_or_else(|| UiError::failed(format!("no message #{} in {}", id.seq, id.room)))?;
            markings.extend(item.marking.as_ref());
        }
        let m = aggregate(markings).map_err(|e| UiError::failed(e.to_string()))?;
        Ok(MarkingView::of(&m))
    }

    pub fn denial(&self, audit_ref: &str) -> Result<DenialDetail, UiError> {
        let d = self.act(|c| c.audit_detail(audit_ref))?;
        Ok(DenialDetail {
            audit: audit_ref.into(),
            entry: d.entry.map(|e| LogLine {
                id: e.id,
                at: e.at,
                actor: e.actor,
                room: e.room,
                event: e.event,
                decision: e.decision,
                code: e.code,
                detail: e.detail,
                marking: e.marking,
            }),
            inclusion: match d.inclusion {
                Inclusion::Proven { size, root } => InclusionView::Proven { size, root },
                Inclusion::Withheld => InclusionView::Withheld,
            },
        })
    }

    pub fn watermark(&self) -> Result<WatermarkSpec, UiError> {
        let g = self.lock()?;
        Ok(WatermarkSpec {
            text: format!("{} · {}", g.client.user(), &g.seed[..8]),
            seed: g.seed.clone(),
        })
    }
}

fn notice(room: &str, seq: u64, by: &str, text: String) -> MessageView {
    MessageView {
        id: MsgId {
            room: room.into(),
            seq,
        },
        kind: Kind::Notice,
        sender: by.into(),
        mine: false,
        marking: None,
        text,
        forwarded_from: None,
        of: None,
    }
}

impl Inner {
    fn save(&self) {
        if let Err(e) = self.client.save() {
            eprintln!("state not saved: {e:#}");
        }
    }

    fn credential_state(&self) -> CredentialState {
        match self.client.credential_expiry() {
            None => CredentialState::NotEnrolled,
            Some(t) if t <= now() => CredentialState::Expired { since: t },
            Some(t) => CredentialState::Active { until: t },
        }
    }

    /// A received message as a feed item. A marking that won't parse is never rendered
    /// (§8): the item becomes a quarantine with no body.
    fn message_item(
        &self,
        room: &str,
        seq: u64,
        sender: &str,
        marking: &str,
        text: String,
        forwarded_from: Option<String>,
    ) -> Item {
        let id = MsgId {
            room: room.into(),
            seq,
        };
        match self.client.parse_marking(marking) {
            Ok(m) => Item {
                view: MessageView {
                    id,
                    kind: Kind::Message,
                    sender: sender.into(),
                    mine: sender == self.client.user(),
                    marking: Some(MarkingView::of(&m)),
                    text,
                    forwarded_from,
                    of: None,
                },
                marking: Some(m),
            },
            Err(e) => Item {
                view: MessageView {
                    id,
                    kind: Kind::Quarantined,
                    sender: sender.into(),
                    mine: false,
                    marking: None,
                    text: format!("marking won't parse: {e}"),
                    forwarded_from: None,
                    of: None,
                },
                marking: None,
            },
        }
    }

    /// Fold sync's events into the feed. One `messages_appended` per room per round.
    fn absorb(&mut self, events: Vec<(String, Event)>) -> Vec<UiEvent> {
        let mut out = Vec::new();
        let mut appended: BTreeMap<String, Vec<MessageView>> = BTreeMap::new();
        for (room, event) in events {
            let item = match event {
                Event::Joined { room } => {
                    self.feeds.entry(room.clone()).or_default();
                    out.push(UiEvent::RoomChanged {
                        room,
                        change: "joined",
                    });
                    continue;
                }
                Event::JoinRefused { reason } => {
                    out.push(UiEvent::Denial(Denial {
                        room,
                        by: "client".into(),
                        code: None,
                        reason,
                        audit: None,
                    }));
                    continue;
                }
                Event::Message {
                    seq,
                    sender,
                    marking,
                    text,
                    forwarded_from,
                } => {
                    let via = forwarded_from.map(|f| format!("{} in {}", f.sender, f.room));
                    self.message_item(&room, seq, &sender, &marking, text, via)
                }
                Event::Ack {
                    seq,
                    sender,
                    of,
                    marking,
                } => match self.client.parse_marking(&marking) {
                    Ok(m) => Item {
                        view: MessageView {
                            id: MsgId {
                                room: room.clone(),
                                seq,
                            },
                            kind: Kind::Ack,
                            mine: false,
                            sender,
                            marking: Some(MarkingView::of(&m)),
                            text: String::new(),
                            forwarded_from: None,
                            of,
                        },
                        marking: Some(m),
                    },
                    Err(_) => self.message_item(&room, seq, &sender, &marking, String::new(), None),
                },
                Event::Quarantined {
                    seq,
                    sender,
                    reason,
                } => {
                    out.push(UiEvent::Denial(Denial {
                        room: room.clone(),
                        by: format!("received from {sender}"),
                        code: None,
                        reason: reason.clone(),
                        audit: None,
                    }));
                    Item {
                        view: MessageView {
                            id: MsgId {
                                room: room.clone(),
                                seq,
                            },
                            kind: Kind::Quarantined,
                            sender,
                            mine: false,
                            marking: None,
                            text: reason,
                            forwarded_from: None,
                            of: None,
                        },
                        marking: None,
                    }
                }
                Event::CeilingChanged { seq, by, ceiling } => {
                    out.push(UiEvent::RoomChanged {
                        room: room.clone(),
                        change: "ceiling",
                    });
                    notice_item(&room, seq, &by, format!("ceiling is now {ceiling}"))
                }
                Event::MembershipChanged {
                    seq,
                    by,
                    added,
                    removed,
                } => {
                    out.push(UiEvent::RoomChanged {
                        room: room.clone(),
                        change: "membership",
                    });
                    let mut parts = Vec::new();
                    if !added.is_empty() {
                        parts.push(format!("added {}", added.join(", ")));
                    }
                    if !removed.is_empty() {
                        parts.push(format!("removed {}", removed.join(", ")));
                    }
                    notice_item(&room, seq, &by, parts.join("; "))
                }
                Event::Purged { .. } => {
                    self.feeds.remove(&room);
                    appended.remove(&room);
                    out.push(UiEvent::RoomChanged {
                        room,
                        change: "purged",
                    });
                    continue;
                }
                Event::IntegrityHold { seq, reason } => {
                    out.push(UiEvent::IntegrityAlert {
                        room: Some(room.clone()),
                        reason: reason.clone(),
                    });
                    out.push(UiEvent::RoomChanged {
                        room: room.clone(),
                        change: "held",
                    });
                    notice_item(&room, seq, "core", format!("room frozen: {reason}"))
                }
                Event::LogAlert { reason } => {
                    out.push(UiEvent::IntegrityAlert { room: None, reason });
                    continue;
                }
            };
            let view = item.view.clone();
            if self.feeds.entry(room.clone()).or_default().insert(item) {
                appended.entry(room).or_default().push(view);
            }
        }
        for (room, items) in appended {
            if self.focused.as_deref() == Some(room.as_str())
                && let Some(feed) = self.feeds.get_mut(&room)
            {
                feed.read = feed.read.max(feed.last_seq());
            }
            out.push(UiEvent::MessagesAppended { room, items });
        }
        out
    }

    /// Pull in text messages the client has that the feed doesn't.
    fn reconcile(&mut self) -> Vec<UiEvent> {
        let Ok(rooms) = self.client.rooms() else {
            return vec![];
        };
        let mut out = Vec::new();
        for r in rooms {
            let mut fresh = Vec::new();
            for m in self.client.history(&r.room) {
                let item = self.message_item(&r.room, m.seq, &m.sender, &m.marking, m.text, None);
                let view = item.view.clone();
                if self.feeds.entry(r.room.clone()).or_default().insert(item) {
                    fresh.push(view);
                }
            }
            if !fresh.is_empty() {
                out.push(UiEvent::MessagesAppended {
                    room: r.room,
                    items: fresh,
                });
            }
        }
        out
    }
}

fn notice_item(room: &str, seq: u64, by: &str, text: String) -> Item {
    Item {
        view: notice(room, seq, by, text),
        marking: None,
    }
}

#[cfg(test)]
mod tests;
