#![no_main]

use libfuzzer_sys::fuzz_target;
use shadowlemon_wire::Metadata;

// Metadata::parse consumes attacker-controlled bytes directly. It must reject
// malformed inputs without panicking and must ignore reserved bytes.
fuzz_target!(|data: &[u8]| {
    if let Ok(metadata) = Metadata::parse(data) {
        // Encode/parse of a successfully parsed value must be stable.
        let encoded = metadata.encode();
        debug_assert_eq!(Metadata::parse(&encoded), Ok(metadata));
    }
});
