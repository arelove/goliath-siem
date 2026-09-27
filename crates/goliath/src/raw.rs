//! Raw records as they travel from a collector to a normalizer: the bytes as
//! the source wrote them, stamped with when the platform took them.
//!
//! The stamp is what the event store records as `received`, which decides
//! partition and retention (`docs/adr/0013-event-storage.md`), so it must be
//! the time the platform took the record, not the time a later role got to
//! it. Records in a durable topic from before stamps existed have none, and
//! are read as they are.

use std::time::{SystemTime, UNIX_EPOCH};

/// Starts a stamped record. No log file begins with a NUL byte: JSON, text,
/// and EVTX all begin with printable characters.
const MAGIC: &[u8] = b"\0goliath-raw\x01";

/// `bytes` stamped as taken at `received` milliseconds since the Unix epoch.
pub(crate) fn stamp(received: i64, bytes: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(MAGIC.len() + 8 + bytes.len());
    record.extend_from_slice(MAGIC);
    record.extend_from_slice(&received.to_be_bytes());
    record.extend_from_slice(bytes);
    record
}

/// When a record was taken, if it says, and the source's bytes.
pub(crate) fn read(record: &[u8]) -> (Option<i64>, &[u8]) {
    if let Some(rest) = record.strip_prefix(MAGIC)
        && let Some((time, bytes)) = rest.split_first_chunk::<8>()
    {
        return (Some(i64::from_be_bytes(*time)), bytes);
    }
    (None, record)
}

/// Now, in milliseconds since the Unix epoch.
pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stamped_record_reads_back() {
        let record = stamp(1_790_294_400_123, b"{\"a\": 1}\n");
        assert_eq!(
            read(&record),
            (Some(1_790_294_400_123), &b"{\"a\": 1}\n"[..])
        );
    }

    #[test]
    fn records_from_before_stamps_read_as_they_are() {
        for old in [
            &b"{\"a\": 1}"[..],
            b"type=SYSCALL msg=audit(1.0:1):",
            b"",
            b"\0goliath",
        ] {
            assert_eq!(read(old), (None, old));
        }
    }
}
