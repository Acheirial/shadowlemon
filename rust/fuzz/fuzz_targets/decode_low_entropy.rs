#![no_main]

#[cfg(feature = "low-entropy")]
use shadowlemon_wire::low_entropy::decode;

use libfuzzer_sys::fuzz_target;

// The low-entropy decoder must accept arbitrary bytes without panicking,
// rejecting bad parameters, lengths and filler polarity through WireError.
fuzz_target!(|data: &[u8]| {
    #[cfg(feature = "low-entropy")]
    {
        if data.len() < 8 {
            return;
        }
        let mode = data[0] % 4 + 1;
        let rotation = data[1] % 64;
        let half_mask = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let extracted_len = usize::from(u16::from_be_bytes([data[6], data[7]])) % 32_769;
        let _ = decode(&data[8..], extracted_len, mode, rotation, half_mask);
    }
});
