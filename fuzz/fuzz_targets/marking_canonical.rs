#![no_main]

use libfuzzer_sys::fuzz_target;
use markings::{Marking, Registers};

fuzz_target!(|data: &[u8]| {
    let reg = Registers::sample();
    let Ok(m) = Marking::from_canonical(data, &reg) else {
        return;
    };
    // Strict decode: only the exact bytes `canonical_bytes` produces may be accepted,
    // or two byte strings could name one marking.
    assert_eq!(m.canonical_bytes().as_deref(), Ok(data));
});
