#![no_main]

use libfuzzer_sys::fuzz_target;
use markings::{Marking, Registers, parse};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let reg = Registers::sample();
    let Ok(m) = parse(text, &reg) else {
        return;
    };
    // Anything the parser accepts must survive both renderings and the wire encoding.
    assert_eq!(parse(&m.portion(), &reg).as_ref(), Ok(&m), "portion: {m}");
    assert_eq!(parse(&m.banner(), &reg).as_ref(), Ok(&m), "banner: {m}");
    let bytes = m.canonical_bytes().expect("canonical encode");
    assert_eq!(Marking::from_canonical(&bytes, &reg).as_ref(), Ok(&m));
});
