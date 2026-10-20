//! Fuzz the after-queue handoff contract: arbitrary bytes are parsed as the
//! request JSON, then `process_handoff` (sender/recipient/size/hash/milter
//! bounds) must accept or reject without panicking. No network, no database.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nullapart_mail_core::handoff::{process_handoff, AfterQueueHandoffRequest, HandoffConfig};

fuzz_target!(|data: &[u8]| {
    let Ok(request) = serde_json::from_slice::<AfterQueueHandoffRequest>(data) else {
        return;
    };
    let config = HandoffConfig::default();
    let _ = process_handoff(&config, &request);
});
