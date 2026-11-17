#![no_main]

use libfuzzer_sys::fuzz_target;
use shadowlemon_crypto::envelope::HandshakeResponse;

// A response is fixed length, but the fuzzer still varies the length to check
// that the parser never indexes past the end of the input.
fuzz_target!(|data: &[u8]| {
    let _ = HandshakeResponse::parse(data);
});
