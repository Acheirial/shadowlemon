#![no_main]

use libfuzzer_sys::fuzz_target;
use shadowlemon_crypto::envelope::HandshakeRequest;

// The parser handles attacker-controlled bytes: it must reject malformed
// requests without panicking or reading out of bounds.
fuzz_target!(|data: &[u8]| {
    let _ = HandshakeRequest::parse(data);
});
