#![no_main]

use libfuzzer_sys::fuzz_target;
use proto::api::LogEntry;
use proto::{AppAad, ArchiveCopy, ArchiveRecord, AttributeCredential, Envelope, HandshakeAad};
use serde::Serialize;
use serde::de::DeserializeOwned;

// Whatever decodes must re-encode to something that decodes to the same value.
fn check<T: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug>(data: &[u8]) {
    let Ok(v) = serde_json::from_slice::<T>(data) else {
        return;
    };
    let again = serde_json::to_vec(&v).expect("encode");
    let back = serde_json::from_slice::<T>(&again).expect("re-decode");
    assert_eq!(v, back);
}

fuzz_target!(|data: &[u8]| {
    check::<Envelope>(data);
    check::<AppAad>(data);
    check::<HandshakeAad>(data);
    check::<AttributeCredential>(data);
    check::<ArchiveRecord>(data);
    check::<ArchiveCopy>(data);
    // Has its own version gate on top of serde.
    let _ = LogEntry::from_leaf(data);
});
