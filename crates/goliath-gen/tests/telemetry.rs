//! Formatter contracts against the shipped normalization definitions.
#![allow(clippy::unwrap_used, clippy::panic)]
use goliath_gen::{Generator, Options, Organization, entities, entra::Entra, sysmon::Sysmon};
use goliath_normalize::{ENTRA, Normalizer, Outcome, SYSMON};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn check(normalizer: &Normalizer, record: &Value, time: i64) {
    let mut outcomes = Vec::new();
    normalizer.normalize(record.to_string().as_bytes(), |o| outcomes.push(o));
    let [Outcome::Event(done)] = outcomes.as_slice() else {
        panic!("{outcomes:?}")
    };
    assert!(done.issues.is_empty(), "{:?}", done.issues);
    assert_eq!(done.event["time"], json!(time));
}

#[test]
fn a_thousand_sysmon_records_normalize_and_keep_process_identity() {
    let org = Organization::generate(&Options::default());
    let (mut first, mut second) = (Sysmon::new(&org, 7), Sysmon::new(&org, 7));
    let normalizer = Normalizer::from_yaml(SYSMON).unwrap();
    let mut seen = BTreeMap::new();
    let mut kinds = BTreeSet::new();
    for index in 0..1_000 {
        let time = 1_790_244_930_123 + index;
        let host = usize::try_from(index % 5).unwrap();
        let record = first.record(&org, host, time);
        assert_eq!(record, second.record(&org, host, time));
        check(&normalizer, &record, time);
        let system = &record["Event"]["System"];
        let data = &record["Event"]["EventData"];
        assert_eq!(system["Computer"], org.hosts[host].fqdn);
        let id = system["EventID"].as_u64().unwrap();
        kinds.insert(id);
        let identity = (
            data["ProcessId"].clone(),
            data["Image"].clone(),
            data["User"].clone(),
        );
        let guid = data["ProcessGuid"].as_str().unwrap().to_owned();
        if id == 1 {
            assert!(seen.insert(guid, identity).is_none());
        } else {
            assert_eq!(seen.get(&guid), Some(&identity));
        }
        if id == 3 {
            assert_eq!(
                data["SourceIp"],
                org.hosts[host].address(
                    &org.offices[org.hosts[host].office],
                    time.div_euclid(86_400_000)
                )
            );
        }
    }
    assert_eq!(kinds, BTreeSet::from([1, 3, 7, 11, 13]));
}

#[test]
fn a_thousand_entra_records_normalize_and_name_the_organization() {
    let org = Organization::generate(&Options::default());
    let (mut first, mut second) = (Entra::new(9), Entra::new(9));
    let normalizer = Normalizer::from_yaml(ENTRA).unwrap();
    let mut codes = BTreeSet::new();
    for index in 0..1_000 {
        let time = 1_790_244_930_123 + index;
        let user = usize::try_from(index).unwrap() % org.users.len();
        let record = first.record(&org, user, time);
        assert_eq!(record, second.record(&org, user, time));
        check(&normalizer, &record, time);
        assert_eq!(record["tenantId"], org.tenant_id);
        assert_eq!(
            record["properties"]["userPrincipalName"],
            org.users[user].upn
        );
        assert_eq!(record["properties"]["userId"], org.users[user].object_id);
        assert_eq!(
            record["properties"]["ipAddress"],
            org.offices[org.users[user].office].egress
        );
        codes.insert(record["resultType"].as_str().unwrap().to_owned());
    }
    assert_eq!(
        codes,
        BTreeSet::from(["0", "50126", "50074", "50140"].map(str::to_owned))
    );
}

#[test]
fn stream_and_truth_are_reproducible() {
    let org = Organization::generate(&Options::default());
    let (mut first, mut second) = (Generator::new(&org, 11), Generator::new(&org, 11));
    let mut entra = 0;
    for index in 0..10_000 {
        let time = 1_790_244_930_123 + index * 60_000;
        let record = first.next(time);
        assert_eq!(record, second.next(time));
        assert_eq!(record.time, time);
        entra += usize::from(record.source == "entra");
    }
    assert!((500..1_000).contains(&entra), "{entra}");
    let truth: Vec<_> = entities(&org).collect();
    assert_eq!(truth.len(), org.users.len() + org.hosts.len());
    for (user, row) in org.users.iter().zip(&truth) {
        assert!(
            row["identifiers"]["windows_account"]
                .as_array()
                .unwrap()
                .contains(&json!(format!("{}\\{}", org.netbios, user.sam)))
        );
        if let Some(sam) = &user.admin_sam {
            assert!(
                row["identifiers"]["windows_account"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(format!("{}\\{sam}", org.netbios)))
            );
        }
    }
}
