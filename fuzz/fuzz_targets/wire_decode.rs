#![no_main]

use libfuzzer_sys::fuzz_target;
use proto::api::LogEntry;
use proto::{
    AppAad, ArchiveCopy, ArchiveRecord, AttributeBody, AttributeCredential, Envelope, FileRef,
    HandshakeAad, RoomPolicy,
};
use tls_codec::{Deserialize, Serialize};

// `decode` already insists the input is canonical, so a decode that succeeds must
// re-encode to exactly the input.
fn check<T: Deserialize + Serialize>(data: &[u8]) {
    if let Ok(v) = proto::decode::<T>(data) {
        assert_eq!(proto::encode(&v).expect("encode"), data);
    }
}

fuzz_target!(|data: &[u8]| {
    check::<Envelope>(data);
    check::<AppAad>(data);
    check::<HandshakeAad>(data);
    check::<AttributeBody>(data);
    check::<AttributeCredential>(data);
    check::<RoomPolicy>(data);
    check::<FileRef>(data);
    check::<ArchiveRecord>(data);
    check::<ArchiveCopy>(data);
    // Has its own version gate on top of the codec.
    let _ = LogEntry::from_leaf(data);
});
