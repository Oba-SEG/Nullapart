//! Fuzz the bounded DMARC aggregate-report parser: arbitrary bytes (raw or
//! gzip) must parse or fail cleanly — never panic, never hang on forbidden
//! XML constructs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nullapart_mail_core::dmarc_aggregate::{
    parse_dmarc_aggregate_report, DmarcAggregateLimits, DmarcReportCompression,
};

fuzz_target!(|data: &[u8]| {
    let limits = DmarcAggregateLimits::default();
    for compression in [
        DmarcReportCompression::Auto,
        DmarcReportCompression::Xml,
        DmarcReportCompression::Gzip,
        DmarcReportCompression::Zip,
    ] {
        let _ = parse_dmarc_aggregate_report(data, compression, &limits);
    }
});
