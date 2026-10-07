//! HTTP requests as Suricata writes them to `eve.json`. Only what plants a
//! URL: Sysmon records no URL, so an indicator that is one needs a source
//! that does.

use crate::time::timestamp;
use serde_json::{Value, json};

/// A request from `source`, an internal address, for `path` of `host`, over
/// plain HTTP on port 80. The server's address is of a documentation range,
/// which no indicator names.
pub(crate) fn http(source: &str, host: &str, path: &str, flow: u64, time_ms: i64) -> Value {
    // Suricata writes microseconds and a numeric zone.
    let stamp = timestamp(time_ms, 'T');
    let stamp = format!("{}000+0000", stamp.trim_end_matches('Z'));
    json!({
        "timestamp": stamp,
        "flow_id": flow,
        "in_iface": "eth0",
        "event_type": "http",
        "src_ip": source,
        "src_port": 49_152 + flow % 16_384,
        "dest_ip": "203.0.113.81",
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
        "tx_id": 0,
        "http": {
            "hostname": host,
            "url": path,
            "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "http_method": "GET",
            "protocol": "HTTP/1.1",
            "status": 200,
            "length": 48_211
        }
    })
}
