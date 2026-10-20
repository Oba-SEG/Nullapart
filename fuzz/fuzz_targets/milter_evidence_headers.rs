//! Fuzz the queued-evidence header parser: arbitrary message bytes must
//! yield bounded observations without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nullapart_mail_core::milter_evidence::parse_queued_evidence;

fuzz_target!(|data: &[u8]| {
    let observations = parse_queued_evidence(data);
    assert!(nullapart_mail_core::milter_evidence::validate_observations(
        &observations
    ));
});
