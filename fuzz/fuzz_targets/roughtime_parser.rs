#![no_main]
//! Arbitrary framed packets, nested messages, count/offset tables and size edges.
use libfuzzer_sys::fuzz_target;
use vtime_core::roughtime::{unframe, Message};

fuzz_target!(|data: &[u8]| {
    // Cap pre-parser and allocation work attributable to a single fuzz iteration.
    if data.len() > 65_536 {
        return;
    }
    let _ = Message::parse(data);
    if let Ok(message) = unframe(data) {
        let _ = Message::parse(message);
    }
    // Never panic for user-controlled input. A malformed message is expected
    // to return Err; valid empty messages are allowed.
});
