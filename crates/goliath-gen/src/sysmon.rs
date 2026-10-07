//! Ordinary Windows activity in the `evtx_dump` JSON envelope.

use crate::{HostKind, Organization, data, intel::Plant, random::Random, time::timestamp};
use serde_json::{Value, json};
use std::net::Ipv4Addr;

struct Process {
    guid: String,
    pid: usize,
    image: &'static str,
    user: usize,
    parent: String,
}

/// Stateful Sysmon formatter. Use the same organization for its lifetime.
pub struct Sysmon {
    random: Random,
    processes: Vec<Option<Process>>,
    records: Vec<u64>,
}

impl Sysmon {
    /// Starts an independent, reproducible stream for `org`.
    pub fn new(org: &Organization, seed: u64) -> Self {
        Self {
            random: Random::new(seed),
            processes: (0..org.hosts.len()).map(|_| None).collect(),
            records: vec![0; org.hosts.len()],
        }
    }

    /// Emits one event. A launch precedes the other events of each process.
    ///
    /// # Panics
    /// Panics if `host` is outside the organization used to construct this formatter.
    pub fn record(&mut self, org: &Organization, host: usize, time_ms: i64) -> Value {
        self.emit(org, host, time_ms, None)
    }

    /// Emits one event that holds `plant`: a launch for a hash, a network
    /// connection for an address or a name. A connection of a machine that
    /// has launched nothing yet is of a process whose launch was not seen,
    /// as a sensor started late sees them.
    pub(crate) fn planted(
        &mut self,
        org: &Organization,
        host: usize,
        time_ms: i64,
        plant: &Plant,
    ) -> Value {
        self.emit(org, host, time_ms, Some(plant))
    }

    fn emit(
        &mut self,
        org: &Organization,
        host: usize,
        time_ms: i64,
        plant: Option<&Plant>,
    ) -> Value {
        let machine = &org.hosts[host];
        let office = &org.offices[machine.office];
        // The draws of an ordinary record are the same as before plants
        // existed, so the streams of published runs do not change.
        let launch = match plant {
            None => self.processes[host].is_none() || self.random.chance(0.15),
            Some(Plant::Hash(_)) => true,
            Some(_) => false,
        };
        if launch || self.processes[host].is_none() {
            let user = match machine.kind {
                HostKind::Workstation { owner } => owner,
                HostKind::Server { .. } => org
                    .users
                    .iter()
                    .position(|u| u.office == machine.office && u.admin_sam.is_some())
                    .or_else(|| org.users.iter().position(|u| u.office == machine.office))
                    .unwrap_or(0),
            };
            let image = match machine.kind {
                HostKind::Workstation { .. } => *self.random.pick(&[
                    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
                    r"C:\Windows\explorer.exe",
                    r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
                ]),
                HostKind::Server { .. } => r"C:\Windows\System32\svchost.exe",
            };
            self.processes[host] = Some(Process {
                guid: self.random.guid(),
                pid: 1024 + self.random.below(30_000),
                image,
                user,
                parent: self.random.guid(),
            });
        }
        let Some(process) = &self.processes[host] else {
            unreachable!("process initialized above")
        };
        let person = &org.users[process.user];
        let account = match machine.kind {
            HostKind::Server { .. } => person.admin_sam.as_ref().unwrap_or(&person.sam),
            HostKind::Workstation { .. } => &person.sam,
        };
        let user = format!("{}\\{account}", org.netbios);
        let id = match plant {
            _ if launch => 1,
            Some(_) => 3,
            None => *self.random.pick(&[3, 3, 3, 7, 7, 11, 13]),
        };
        let mut fields = match id {
            1 => {
                json!({"CommandLine": format!("\"{}\"", process.image), "CurrentDirectory": r"C:\Windows\",
                "IntegrityLevel": "Medium", "LogonId": format!("0x{:x}", process.user + 4096),
                "ParentImage": r"C:\Windows\explorer.exe", "ParentCommandLine": r"C:\Windows\explorer.exe",
                "ParentProcessId": 512, "ParentProcessGuid": process.parent, "ParentUser": user})
            }
            3 => {
                let endpoint = self.random.pick(data::m365_endpoints());
                let offset =
                    u32::try_from(self.random.below(endpoint.network.1 as usize)).unwrap_or(0);
                let address =
                    Ipv4Addr::from(u32::from_be_bytes(endpoint.network.0).wrapping_add(offset));
                json!({"Protocol": "tcp", "Initiated": "true", "SourceIsIpv6": "false", "DestinationIsIpv6": "false",
                    "SourceIp": machine.address(office, time_ms.div_euclid(86_400_000)), "SourceHostname": machine.fqdn,
                    "SourcePort": 49_152 + self.random.below(16_384), "DestinationIp": address.to_string(),
                    "DestinationHostname": endpoint.host, "DestinationPort": endpoint.port, "DestinationPortName": endpoint.service})
            }
            7 => {
                json!({"ImageLoaded": self.random.pick(&[r"C:\Windows\System32\ntdll.dll", r"C:\Windows\System32\kernel32.dll", r"C:\Windows\System32\winhttp.dll"]),
                "Signed": "true", "Signature": "Microsoft Windows", "SignatureStatus": "Valid"})
            }
            11 => {
                json!({"TargetFilename": format!(r"C:\Users\{}\AppData\Local\Temp\office-{}.tmp", person.sam, self.random.below(1_000_000)), "CreationUtcTime": timestamp(time_ms, ' ')})
            }
            _ => {
                json!({"EventType": "SetValue", "TargetObject": format!(r"HKU\{}\Software\Microsoft\Office\16.0\Common\LastRun", person.sid), "Details": "DWORD (0x00000001)"})
            }
        };
        match plant {
            Some(Plant::Hash(hash)) => {
                fields["Hashes"] = json!(format!("SHA256={}", hash.to_ascii_uppercase()));
            }
            Some(Plant::Address(address)) => fields["DestinationIp"] = json!(address),
            Some(Plant::Name(name)) => fields["DestinationHostname"] = json!(name),
            Some(Plant::Request { .. }) | None => {}
        }
        fields["RuleName"] = json!("-");
        fields["UtcTime"] = json!(timestamp(time_ms, ' '));
        fields["ProcessGuid"] = json!(process.guid);
        fields["ProcessId"] = json!(process.pid);
        fields["Image"] = json!(process.image);
        fields["User"] = json!(user);
        self.records[host] += 1;
        json!({"Event": {"System": {
            "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}}, "EventID": id,
            "TimeCreated": {"#attributes": {"SystemTime": timestamp(time_ms, 'T')}},
            "EventRecordID": self.records[host], "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": machine.fqdn
        }, "EventData": fields}})
    }
}
