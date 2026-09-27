//! Identity ground truth, independent of event volume.
use crate::Organization;
use serde_json::{Value, json};

/// One JSON object per person or host. Identifier values are arrays because
/// a person can have a separate administrator account. IP addresses are not
/// permanent identities and are deliberately absent from this static file.
pub fn entities(org: &Organization) -> impl Iterator<Item = Value> + '_ {
    let users = org.users.iter().map(|u| {
        let mut accounts = vec![format!("{}\\{}", org.netbios, u.sam)];
        let mut sids = vec![u.sid.clone()];
        if let Some(sam) = &u.admin_sam { accounts.push(format!("{}\\{sam}", org.netbios)); }
        if let Some(sid) = &u.admin_sid { sids.push(sid.clone()); }
        json!({"kind": "user", "id": u.object_id, "identifiers": {
            "windows_account": accounts, "upn": [u.upn], "entra_object_id": [u.object_id], "sid": sids
        }})
    });
    users.chain(org.hosts.iter().map(|h| {
        json!({"kind": "host", "id": h.device_id, "identifiers": {
            "netbios": [h.name], "fqdn": [h.fqdn], "entra_device_id": [h.device_id]
        }})
    }))
}
