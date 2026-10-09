//! The cases of `docs/adr/0022-context-snapshot.md`, each as a site's
//! export, an event's values, and what the finding gets.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;

use goliath_enrich::{Definition, EnrichError, Id, IdKind, LIMIT, Snapshot, enrichments};
use serde_json::{Value, json};

/// 2026-10-10T12:00:00Z.
const NOW: i64 = 1_791_633_600;
const DAY: i64 = 86_400;

fn load(snapshot: &mut Snapshot, definition: &str, version: &str, export: &str) {
    let definition = Definition::from_yaml(definition).expect("the definition loads");
    let parsed = definition
        .parse(export.as_bytes())
        .expect("the export reads");
    assert_eq!(parsed.rejected, 0, "{:?}", parsed.reasons);
    snapshot.replace(&definition.name, version, parsed.records);
}

fn id(kind: IdKind, value: &str) -> Id {
    Id::new(kind, value).expect("an identifier")
}

fn of<'a>(entries: &'a [Value], provider: &str) -> &'a Value {
    entries
        .iter()
        .find(|entry| entry["provider"] == provider)
        .unwrap_or_else(|| panic!("no entry of {provider} in {entries:#?}"))
}

const NETWORKS: &str = "name: ipam\nkind: network\nformat: csv\nrange: cidr\n\
    fields: { name: name, zone: zone, site: site }\nlabels: { pci_scope: pci }\n";
const CMDB: &str = "name: cmdb\nkind: asset\nformat: csv\n\
    identifiers: { host: [hostname], address: [ip] }\n\
    fields: { type: class, owner: owner, org: unit, criticality: tier }\n\
    criticality: { gold: 4, silver: 3, bronze: 2 }\n\
    labels: { information_system: system }\n";

#[test]
fn a_bank_tells_the_cardholder_network_from_the_guest_one() {
    let mut snapshot = Snapshot::new();
    load(
        &mut snapshot,
        NETWORKS,
        "2026-10-09",
        "cidr,name,zone,site,pci\n\
         10.0.0.0/8,corporate,internal,,\n\
         10.20.0.0/16,branch 14,internal,Kazan,\n\
         10.20.30.0/24,tellers of branch 14,internal,Kazan,cde\n\
         192.168.50.0/24,guest wireless,guest,Kazan,\n",
    );
    load(
        &mut snapshot,
        CMDB,
        "2026-10-09",
        "hostname,ip,class,owner,unit,tier,system\n\
         TELLER-14-03,10.20.30.17,workstation,g.ivanova@bank.example,Retail,gold,core banking\n",
    );

    // The teller's workstation: the narrowest network, and the machine.
    let teller = enrichments(&snapshot, &[id(IdKind::Address, "10.20.30.17")], None, NOW);
    assert_eq!(teller.len(), 2);
    let network = of(&teller, "ipam");
    assert_eq!(network["type"], "network");
    assert_eq!(network["name"], "ip");
    assert_eq!(network["value"], "10.20.30.17");
    assert_eq!(network["data"]["name"], "tellers of branch 14");
    assert_eq!(network["data"]["range"], "10.20.30.0/24");
    assert_eq!(network["data"]["labels"]["pci_scope"], "cde");
    assert_eq!(network["data"]["source_version"], "2026-10-09");
    let asset = of(&teller, "cmdb");
    assert_eq!(asset["type"], "asset");
    assert_eq!(asset["data"]["owner"], "g.ivanova@bank.example");
    assert_eq!(asset["data"]["criticality"], 4);
    assert_eq!(
        asset["data"]["labels"]["information_system"],
        "core banking"
    );
    // Networks before assets.
    assert_eq!(teller[0]["type"], "network");

    // The same connection from the guest network: a network, and no asset,
    // which is itself what the analyst needs to see.
    let guest = enrichments(&snapshot, &[id(IdKind::Address, "192.168.50.9")], None, NOW);
    assert_eq!(guest.len(), 1);
    assert_eq!(guest[0]["data"]["zone"], "guest");
    // An address of nobody's gets nothing.
    assert_eq!(
        enrichments(&snapshot, &[id(IdKind::Address, "203.0.113.5")], None, NOW),
        Vec::<Value>::new()
    );
}

#[test]
fn a_cloud_instance_is_found_as_it_was_when_it_held_the_address() {
    let mut snapshot = Snapshot::new();
    load(
        &mut snapshot,
        "name: cloud-inventory\nkind: asset\nformat: jsonl\n\
         identifiers: { uid: [instance_id], address: [private_ip], host: [name] }\n\
         fields: { type: kind, region: region }\n\
         labels: { project: tags.project, service: tags.service, runs_as: service_account }\n\
         valid_from: started\nvalid_until: stopped\n",
        "inventory at 12:00",
        r#"{"instance_id":"i-0a1","name":"batch-7f9c","private_ip":"10.8.4.21","kind":"instance","region":"us-east-1","tags":{"project":"payments-prod","service":"settlement"},"service_account":"settlement@payments.iam","started":"2026-10-10T09:00:00Z","stopped":"2026-10-10T09:06:00Z"}
{"instance_id":"i-0b2","name":"web-11ab","private_ip":"10.8.4.21","kind":"instance","region":"us-east-1","tags":{"project":"storefront","service":"web"},"service_account":"web@storefront.iam","started":"2026-10-10T09:30:00Z"}
"#,
    );
    let address = [id(IdKind::Address, "10.8.4.21")];
    let at = |text: &str| text.parse::<jiff::Timestamp>().unwrap().as_second();

    // While the first instance lived, the address was its own.
    let first = enrichments(&snapshot, &address, None, at("2026-10-10T09:03:00Z"));
    assert_eq!(first.len(), 1);
    assert_eq!(first[0]["data"]["labels"]["project"], "payments-prod");
    assert_eq!(
        first[0]["data"]["labels"]["runs_as"],
        "settlement@payments.iam"
    );
    assert_eq!(first[0]["data"]["region"], "us-east-1");
    assert_eq!(first[0]["data"].get("ended"), None);

    // An hour later the same address is another instance.
    let second = enrichments(&snapshot, &address, None, at("2026-10-10T10:00:00Z"));
    assert_eq!(second.len(), 1);
    assert_eq!(second[0]["data"]["labels"]["project"], "storefront");

    // Between the two nothing held it: the instance that last did, as ended.
    let between = enrichments(&snapshot, &address, None, at("2026-10-10T09:15:00Z"));
    assert_eq!(between.len(), 1);
    assert_eq!(between[0]["data"]["labels"]["project"], "payments-prod");
    assert_eq!(between[0]["data"]["ended"], true);

    // By its identifier the first instance is found whatever the time.
    let by_uid = enrichments(
        &snapshot,
        &[id(IdKind::Uid, "I-0A1")],
        None,
        at("2026-10-10T09:03:00Z"),
    );
    assert_eq!(by_uid[0]["name"], "uid");
    assert_eq!(by_uid[0]["data"]["labels"]["service"], "settlement");
}

const DIRECTORY: &str = "name: directory\nkind: identity\nformat: csv\n\
    identifiers: { user: [sam, upn], email: [mail], uid: [sid] }\n\
    fields: { name: display, type: kind, department: department, manager: manager, is_enabled: enabled }\n\
    groups: { column: member_of, separator: \"|\" }\n\
    valid_until: left\n";

#[test]
fn an_account_used_after_its_owner_left_is_found_as_ended() {
    let mut snapshot = Snapshot::new();
    load(
        &mut snapshot,
        DIRECTORY,
        "2026-10-10",
        "sam,upn,mail,sid,display,kind,department,manager,enabled,member_of,left\n\
         CORP\\adam,adam@corp.example,adam.k@corp.example,S-1-5-21-1-2-3-1104,Adam K,person,Treasury,olga@corp.example,no,Treasury Users,2026-10-03\n",
    );
    // Every form of the name finds the one record, however it is cased.
    for (kind, value) in [
        (IdKind::User, "corp\\Adam"),
        (IdKind::User, "ADAM@corp.example"),
        (IdKind::Email, "Adam.K@corp.example"),
        (IdKind::Uid, "s-1-5-21-1-2-3-1104"),
    ] {
        let found = enrichments(&snapshot, &[id(kind, value)], None, NOW);
        assert_eq!(found.len(), 1, "{value}");
        assert_eq!(found[0]["type"], "identity");
        assert_eq!(found[0]["data"]["department"], "Treasury");
        assert_eq!(found[0]["data"]["is_enabled"], false);
        // A week after the last day: the context is the finding.
        assert_eq!(found[0]["data"]["ended"], true, "{value}");
        assert_eq!(found[0]["data"]["groups"], json!(["Treasury Users"]));
    }
    // Before that day the same account was a person at work.
    let before = enrichments(
        &snapshot,
        &[id(IdKind::User, "CORP\\adam")],
        None,
        NOW - 10 * DAY,
    );
    assert_eq!(before[0]["data"].get("ended"), None);
}

#[test]
fn a_service_account_and_a_privileged_group_are_said_to_be_so() {
    let mut snapshot = Snapshot::new();
    load(
        &mut snapshot,
        DIRECTORY,
        "2026-10-10",
        "sam,upn,mail,sid,display,kind,department,manager,enabled,member_of,left\n\
         CORP\\svc-backup,,,S-1-5-21-1-2-3-2201,Nightly backup,service account,IT,,yes,Backup Operators|Domain Admins,\n",
    );
    load(
        &mut snapshot,
        "name: directory-groups\nkind: group\nformat: csv\n\
         identifiers: { group: [name] }\n\
         fields: { name: name, is_privileged: tier0 }\n",
        "2026-10-10",
        "name,tier0\nDomain Admins,yes\nBackup Operators,yes\nTreasury Users,no\n",
    );
    let found = enrichments(
        &snapshot,
        &[id(IdKind::User, "corp\\svc-backup")],
        None,
        NOW,
    );
    let account = of(&found, "directory");
    assert_eq!(account["data"]["type"], "service account");
    // Its groups are looked up, so what is said of a group once reaches
    // every finding of a member.
    let groups: Vec<&Value> = found
        .iter()
        .filter(|entry| entry["type"] == "group")
        .collect();
    assert_eq!(groups.len(), 2);
    assert!(
        groups
            .iter()
            .all(|group| group["data"]["is_privileged"] == true)
    );
    assert!(groups.iter().any(|group| group["value"] == "domain admins"));
    // Identities before groups.
    assert_eq!(found[0]["type"], "identity");
}

#[test]
fn one_address_in_two_customers_gets_the_context_of_its_own() {
    let mut snapshot = Snapshot::new();
    for (customer, name) in [("acme", "Acme warehouse"), ("globex", "Globex laboratory")] {
        load(
            &mut snapshot,
            &format!(
                "name: {customer}-networks\nkind: network\nscope: {customer}\nformat: csv\n\
                 range: cidr\nfields: {{ name: name }}\n"
            ),
            "1",
            &format!("cidr,name\n10.1.2.0/24,{name}\n"),
        );
    }
    // A list of no scope, for every customer.
    load(
        &mut snapshot,
        "name: vpn-ranges\nkind: list\nformat: csv\ncsv: { columns: [cidr, provider] }\n\
         range: cidr\nfields: { label: provider }\n",
        "2e4e649",
        "10.1.0.0/16,Example VPN\n",
    );
    let address = [id(IdKind::Address, "10.1.2.3")];
    for (scope, name) in [("acme", "Acme warehouse"), ("globex", "Globex laboratory")] {
        let found = enrichments(&snapshot, &address, Some(scope), NOW);
        assert_eq!(found.len(), 2, "{scope}");
        assert_eq!(found[0]["data"]["name"], name);
        assert_eq!(found[0]["data"]["scope"], scope);
        assert_eq!(found[1]["type"], "list");
        assert_eq!(found[1]["data"]["label"], "Example VPN");
        assert_eq!(found[1]["data"]["source_version"], "2e4e649");
    }
    // An event of no scope is not given either customer's.
    let found = enrichments(&snapshot, &address, None, NOW);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["type"], "list");
}

#[test]
fn a_host_is_described_by_a_list_that_names_a_domain_above_it() {
    let mut snapshot = Snapshot::new();
    load(
        &mut snapshot,
        "name: dynamic-dns\nkind: list\nformat: csv\nidentifiers: { host: [domain] }\n\
         fields: { label: provider }\n",
        "2e4e649",
        "domain,provider\nmooo.com,afraid.org\nus.to,afraid.org\n",
    );
    load(
        &mut snapshot,
        CMDB,
        "1",
        "hostname,ip,class,owner,unit,tier,system\ncorp.example,,server,web@corp.example,,,\n",
    );
    // A name registered under a dynamic DNS domain, however deep.
    for host in ["evil.mooo.com", "a.b.MOOO.com", "mooo.com"] {
        let found = enrichments(&snapshot, &[id(IdKind::Host, host)], None, NOW);
        assert_eq!(found.len(), 1, "{host}");
        assert_eq!(found[0]["type"], "list");
        assert_eq!(found[0]["data"]["label"], "afraid.org");
    }
    // Not a name that only ends the same.
    assert_eq!(
        enrichments(&snapshot, &[id(IdKind::Host, "notmooo.com")], None, NOW),
        Vec::<Value>::new()
    );
    // An asset is found by its own name alone, not by names under it.
    assert_eq!(
        enrichments(
            &snapshot,
            &[id(IdKind::Host, "www.corp.example")],
            None,
            NOW
        ),
        Vec::<Value>::new()
    );
}

#[test]
fn two_sources_that_disagree_are_both_reported_under_their_names() {
    let mut snapshot = Snapshot::new();
    load(
        &mut snapshot,
        CMDB,
        "2026-10-01",
        "hostname,ip,class,owner,unit,tier,system\n\
         pay-api-02,,server,platform@corp.example,Platform,silver,payments\n",
    );
    load(
        &mut snapshot,
        "name: cloud-tags\nkind: asset\nformat: csv\nidentifiers: { host: [name] }\n\
         fields: { owner: team, criticality: criticality }\n",
        "2026-10-10",
        "name,team,criticality\nPAY-API-02.corp.example,payments@corp.example,4\n\
         pay-api-02,payments@corp.example,4\n",
    );
    let found = enrichments(&snapshot, &[id(IdKind::Host, "PAY-API-02")], None, NOW);
    assert_eq!(found.len(), 2);
    assert_eq!(of(&found, "cmdb")["data"]["owner"], "platform@corp.example");
    assert_eq!(of(&found, "cmdb")["data"]["criticality"], 3);
    assert_eq!(
        of(&found, "cloud-tags")["data"]["owner"],
        "payments@corp.example"
    );
    assert_eq!(
        of(&found, "cloud-tags")["data"]["source_version"],
        "2026-10-10"
    );

    // A source replaced holds what its last export held, and no more.
    load(
        &mut snapshot,
        CMDB,
        "2026-10-11",
        "hostname,ip,class,owner,unit,tier,system\n\
         other-host,,server,x@corp.example,Platform,bronze,none\n",
    );
    let found = enrichments(&snapshot, &[id(IdKind::Host, "pay-api-02")], None, NOW);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["provider"], "cloud-tags");
    assert_eq!(
        snapshot.sources(),
        [("cloud-tags", "2026-10-10", 2), ("cmdb", "2026-10-11", 1)]
    );
}

#[test]
fn no_more_than_the_limit_is_written_and_networks_come_first() {
    let mut snapshot = Snapshot::new();
    let mut hosts = String::from("hostname,ip,class,owner,unit,tier,system\n");
    let mut ids = Vec::new();
    for number in 0..40 {
        let _ = writeln!(hosts, "scan-{number},10.9.0.{number},server,,,,");
        ids.push(id(IdKind::Address, &format!("10.9.0.{number}")));
    }
    load(&mut snapshot, CMDB, "1", &hosts);
    load(
        &mut snapshot,
        NETWORKS,
        "1",
        "cidr,name,zone,site,pci\n10.9.0.0/24,scanners,internal,,\n",
    );
    let found = enrichments(&snapshot, &ids, None, NOW);
    assert_eq!(found.len(), LIMIT);
    // The one network is found once, whatever number of addresses is in it.
    assert_eq!(found[0]["type"], "network");
    assert!(found[1..].iter().all(|entry| entry["type"] == "asset"));
}

#[test]
fn an_export_that_is_not_what_its_definition_describes_is_refused() {
    let definition = Definition::from_yaml(CMDB).unwrap();
    let refused = |export: &str, expected: &str| match definition.parse(export.as_bytes()) {
        Err(EnrichError::Source { why, .. }) => assert!(why.contains(expected), "{why}"),
        other => panic!("{export}: {other:?}"),
    };
    // An error page in place of the file, or a column that was renamed.
    refused("<html>Service unavailable</html>\n", "no column");
    refused(
        "hostname,ip,class,owner,unit,system\nh,,,,,\n",
        "no column `tier`",
    );
    // A word for criticality nobody gave a meaning to, in every row.
    refused(
        "hostname,ip,class,owner,unit,tier,system\nh1,,,,,platinum,\n",
        "criticality `platinum`",
    );
    // One bad row in a hundred is counted and the rest kept.
    let mut export = String::from("hostname,ip,class,owner,unit,tier,system\n");
    for number in 0..99 {
        let _ = writeln!(export, "host-{number},,,,,gold,");
    }
    export.push_str(",,,,,,\n");
    let parsed = definition.parse(export.as_bytes()).unwrap();
    assert_eq!((parsed.records.len(), parsed.rejected), (99, 1));
}

#[test]
fn definitions_that_contradict_themselves_are_refused() {
    for (yaml, expected) in [
        (
            "name: a\nkind: asset\nformat: csv\nidentifiers: { host: [h] }\nfields: { pci_scope: p }\n",
            "has no field `pci_scope`",
        ),
        (
            "name: a\nkind: asset\nformat: csv\nidentifiers: { host: [h] }\ncriticality: { top: 5 }\n",
            "criticality is 1 to 4",
        ),
        (
            "name: a\nkind: asset\nformat: csv\n",
            "nothing to find a row by",
        ),
        (
            "name: a\nkind: network\nformat: csv\nidentifiers: { host: [h] }\n",
            "found by its `range`",
        ),
        (
            "name: a\nkind: identity\nformat: csv\nidentifiers: { user: [u] }\nrange: r\n",
            "`range` is for networks",
        ),
    ] {
        match Definition::from_yaml(yaml) {
            Err(EnrichError::Definition { why, .. }) => assert!(why.contains(expected), "{why}"),
            other => panic!("{yaml}: {other:?}"),
        }
    }
    // A field nobody defined is refused by name, not ignored.
    assert!(matches!(
        Definition::from_yaml("name: a\nkind: asset\nformat: csv\nidentifier: { host: [h] }\n"),
        Err(EnrichError::Yaml(_))
    ));
}
