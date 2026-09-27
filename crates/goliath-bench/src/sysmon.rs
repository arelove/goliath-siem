//! Sysmon records, as `evtx_dump -o json` writes them, for measuring what
//! is stored rather than what is matched.

use serde_json::{Value, json};

use crate::{DIRECTORIES, FRAGMENTS, ORDINARY, PARENTS, Random, SUSPICIOUS};

/// Machines in the fleet a recording comes from.
const HOSTS: usize = 2_000;

/// Accounts that act on them.
const USERS: usize = 5_000;

/// Ports a machine connects to, most of them common.
const PORTS: &[u16] = &[443, 443, 443, 443, 80, 80, 53, 445, 135, 3389, 8080, 5985];

const MODULES: &[&str] = &[
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\user32.dll",
    r"C:\Windows\System32\advapi32.dll",
    r"C:\Windows\System32\ws2_32.dll",
    r"C:\Windows\System32\crypt32.dll",
    r"C:\Windows\System32\amsi.dll",
    r"C:\Windows\System32\dbghelp.dll",
    r"C:\Windows\System32\wininet.dll",
    r"C:\Windows\System32\vaultcli.dll",
];

const KEYS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive",
    r"HKLM\SYSTEM\CurrentControlSet\Services\Spooler\Start",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
    r"HKCU\Software\Microsoft\Office\16.0\Word\Security\VBAWarnings",
];

const EXTENSIONS: &[&str] = &[
    ".tmp", ".log", ".docx", ".xlsx", ".ps1", ".dll", ".exe", ".zip",
];

/// A fleet of Windows machines running Sysmon, generated from a seed so that
/// every run stores exactly the same records.
///
/// Records come in the proportions a workstation fleet writes them: image
/// loads and network connections most, then process launches, file creation,
/// and registry writes. Values repeat as they do in real telemetry: two
/// thousand hosts, a few thousand users, the same binaries and modules over
/// and over, and rarely something an analyst would search for.
#[derive(Debug)]
pub struct Fleet {
    random: Random,
    record: u64,
}

impl Fleet {
    /// A fleet whose records follow from `seed`.
    pub fn new(seed: u64) -> Self {
        Self {
            random: Random::new(seed),
            record: 0,
        }
    }

    /// The next record, written at `time` milliseconds since the Unix epoch.
    pub fn record(&mut self, time: i64) -> Value {
        let random = &mut self.random;
        let host = random.below(HOSTS);
        let user = format!(r"CORP\user{:04}", random.below(USERS));
        let image = image(random);
        let pid = 1_000 + random.below(60_000);
        let guid = guid(random);
        let (id, data) = match random.below(100) {
            0..30 => (
                7,
                json!({
                    "ImageLoaded": random.pick(MODULES),
                    "Product": "Microsoft Windows Operating System",
                    "Company": "Microsoft Corporation",
                    "Signed": "true",
                }),
            ),
            30..58 => (3, connection(random)),
            58..83 => (1, launch(random, &image)),
            83..94 => (
                11,
                json!({
                    "TargetFilename": format!(
                        r"C:\Users\user{:04}\AppData\Local\Temp\{:08x}{}",
                        random.below(USERS),
                        random.next() & 0xffff_ffff,
                        random.pick(EXTENSIONS)
                    ),
                }),
            ),
            _ => (
                13,
                json!({
                    "EventType": "SetValue",
                    "TargetObject": random.pick(KEYS),
                    "Details": "DWORD (0x00000001)",
                }),
            ),
        };
        let actor = Actor {
            host: format!("WS-{host:04}.corp.example"),
            user,
            image,
            pid,
            guid,
        };
        self.wrap(time, id, &actor, data)
    }

    /// An intrusion on one machine, starting at `start` milliseconds since
    /// the Unix epoch and lasting twenty minutes: a macro in a mailed
    /// document starts encoded PowerShell, which drops a DLL, makes it start
    /// with the user's session, calls out to its server on port 4444, looks
    /// around the domain, and packs the user's finance documents into an
    /// archive with a password, ready to leave.
    ///
    /// The encoded PowerShell decodes to a harmless line, and the chain leaves
    /// out what antivirus software quarantines as text on disk, such as a
    /// credential dump, so the recording can be written anywhere.
    ///
    /// Every record names `WS-0042.corp.example` and `CORP\user0042`, so a
    /// search for either finds the whole chain among the fleet's records.
    // The chain is data, read from top to bottom; split up, it reads worse.
    #[allow(clippy::too_many_lines)]
    pub fn intrusion(&mut self, start: i64) -> Vec<(i64, Value)> {
        const TEMP: &str = r"C:\Users\user0042\AppData\Local\Temp\";
        let actor = |image: &str, pid: usize, guid: &str| Actor {
            host: "WS-0042.corp.example".to_owned(),
            user: r"CORP\user0042".to_owned(),
            image: image.to_owned(),
            pid,
            guid: guid.to_owned(),
        };
        let outlook = actor(
            r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
            4_120,
            "4E2A1C3B-0042-6512-0A00-000000000001",
        );
        let word = actor(
            r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            6_312,
            "4E2A1C3B-0042-6512-0A00-000000000002",
        );
        let powershell = actor(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            7_044,
            "4E2A1C3B-0042-6512-0A00-000000000003",
        );
        let rundll32 = actor(
            r"C:\Windows\System32\rundll32.exe",
            7_588,
            "4E2A1C3B-0042-6512-0A00-000000000004",
        );
        let cmd = actor(
            r"C:\Windows\System32\cmd.exe",
            7_902,
            "4E2A1C3B-0042-6512-0A00-000000000005",
        );
        let child = |parent: &Actor, command: &str| {
            json!({
                "CommandLine": command,
                "CurrentDirectory": TEMP,
                "IntegrityLevel": "Medium",
                "LogonId": "0x3c2a1",
                "ParentImage": parent.image,
                "ParentProcessId": parent.pid,
                "ParentProcessGuid": parent.guid,
            })
        };
        let server = |port: u16| {
            json!({
                "Protocol": "tcp",
                "SourceIp": "10.4.0.42",
                "SourcePort": 51_337,
                "DestinationIp": "198.51.100.77",
                "DestinationHostname": "cdn-update.example.org",
                "DestinationPort": port,
            })
        };
        let dll = format!("{TEMP}msupdate.dll");
        let steps = [
            (
                0,
                1,
                &word,
                child(
                    &outlook,
                    &format!(r#""{}" /n "{TEMP}Invoice_0917.docm""#, word.image),
                ),
            ),
            (
                1,
                1,
                &powershell,
                child(
                    &word,
                    "powershell.exe -nop -w hidden -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGMAaABlAGMAawBpAG4AZwAgAGYAbwByACAAdQBwAGQAYQB0AGUAcwAnAA==",
                ),
            ),
            (2, 3, &powershell, server(443)),
            (3, 11, &powershell, json!({ "TargetFilename": dll })),
            (
                4,
                1,
                &rundll32,
                child(
                    &powershell,
                    &format!("rundll32.exe {dll},DllRegisterServer"),
                ),
            ),
            (
                5,
                13,
                &rundll32,
                json!({
                    "EventType": "SetValue",
                    "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MsUpdate",
                    "Details": format!("rundll32.exe {dll},DllRegisterServer"),
                }),
            ),
            (6, 3, &rundll32, server(4444)),
            (9, 1, &cmd, child(&rundll32, "cmd.exe /c whoami /all")),
            (
                11,
                1,
                &cmd,
                child(&rundll32, "cmd.exe /c nltest /domain_trusts"),
            ),
            (
                14,
                1,
                &cmd,
                child(&rundll32, r#"cmd.exe /c net group "Domain Admins" /domain"#),
            ),
            (
                18,
                1,
                &cmd,
                child(
                    &rundll32,
                    r"cmd.exe /c 7z.exe a -mx1 -pq3report C:\Users\Public\q3.7z C:\Users\user0042\Documents\Finance",
                ),
            ),
            (
                19,
                11,
                &cmd,
                json!({ "TargetFilename": r"C:\Users\Public\q3.7z" }),
            ),
        ];
        steps
            .into_iter()
            .map(|(minutes, id, actor, data)| {
                let time = start + minutes * 60_000;
                (time, self.wrap(time, id, actor, data))
            })
            .collect()
    }

    fn wrap(&mut self, time: i64, id: u32, actor: &Actor, data: Value) -> Value {
        self.record += 1;
        let mut data = data;
        data["RuleName"] = json!("-");
        data["UtcTime"] = json!(timestamp(time, ' '));
        data["ProcessGuid"] = json!(actor.guid);
        data["ProcessId"] = json!(actor.pid);
        data["Image"] = json!(actor.image);
        data["User"] = json!(actor.user);
        json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-Sysmon" } },
                    "EventID": id,
                    "TimeCreated": { "#attributes": { "SystemTime": timestamp(time, 'T') } },
                    "EventRecordID": self.record,
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "Computer": actor.host,
                },
                "EventData": data,
            }
        })
    }
}

/// The machine, account, and process a record is written for.
struct Actor {
    host: String,
    user: String,
    image: String,
    pid: usize,
    guid: String,
}

fn image(random: &mut Random) -> String {
    let name = if random.chance(10) {
        random.pick(SUSPICIOUS)
    } else {
        random.pick(ORDINARY)
    };
    format!("{}{name}", random.pick(DIRECTORIES))
}

fn launch(random: &mut Random, image: &str) -> Value {
    let command = if random.chance(2) {
        format!("{image}{}", random.some(FRAGMENTS, 3).concat())
    } else {
        format!("\"{image}\" --id {}", random.below(100_000))
    };
    json!({
        "CommandLine": command,
        "CurrentDirectory": r"C:\Windows\System32\",
        "IntegrityLevel": if random.chance(20) { "High" } else { "Medium" },
        "LogonId": format!("0x{:x}", random.below(1 << 24)),
        "ParentImage": random.pick(PARENTS),
        "ParentProcessId": 4 + random.below(1_000),
        "ParentProcessGuid": guid(random),
    })
}

fn connection(random: &mut Random) -> Value {
    // One connection in a thousand goes somewhere an analyst would look.
    let port = if random.chance(1) && random.chance(10) {
        4444
    } else {
        PORTS[random.below(PORTS.len())]
    };
    json!({
        "Protocol": "tcp",
        "SourceIp": format!("10.{}.{}.{}", random.below(8), random.below(256), 1 + random.below(254)),
        "SourcePort": 49_152 + random.below(16_000),
        "DestinationIp": format!("203.0.113.{}", 1 + random.below(254)),
        "DestinationHostname": format!("host{}.example.net", random.below(500)),
        "DestinationPort": port,
    })
}

fn guid(random: &mut Random) -> String {
    let bits = random.next();
    format!(
        "{:08X}-{:04X}-{:04X}-0000-{:012X}",
        bits >> 32,
        (bits >> 16) & 0xffff,
        bits & 0xffff,
        random.next() & 0xffff_ffff_ffff
    )
}

/// `time` milliseconds since the Unix epoch in RFC 3339, as
/// `2026-09-24T10:15:30.123Z`.
pub fn rfc3339(time: i64) -> String {
    timestamp(time, 'T')
}

/// `time` milliseconds since the Unix epoch as `2026-09-24T10:15:30.123Z`,
/// or with a space and no zone as Sysmon's own `UtcTime` has it.
fn timestamp(time: i64, separator: char) -> String {
    let days = time.div_euclid(86_400_000);
    let of_day = time.rem_euclid(86_400_000);
    let (year, month, day) = civil(days);
    let zone = if separator == 'T' { "Z" } else { "" };
    format!(
        "{year:04}-{month:02}-{day:02}{separator}{:02}:{:02}:{:02}.{:03}{zone}",
        of_day / 3_600_000,
        of_day / 60_000 % 60,
        of_day / 1_000 % 60,
        of_day % 1_000
    )
}

/// The civil date of a day counted from 1970-01-01, after Howard Hinnant's
/// `civil_from_days`.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let of_era = z.rem_euclid(146_097);
    let year_of_era = (of_era - of_era / 1_460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * of_year + 2) / 153;
    let day = of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 {
        shifted + 3
    } else {
        shifted - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use goliath_normalize::{Normalizer, Outcome, SYSMON};

    use super::*;

    #[test]
    fn writes_times_as_sysmon_does() {
        assert_eq!(timestamp(0, 'T'), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            timestamp(1_790_244_930_123, 'T'),
            "2026-09-24T10:15:30.123Z"
        );
        assert_eq!(timestamp(1_790_244_930_123, ' '), "2026-09-24 10:15:30.123");
        assert_eq!(timestamp(951_782_400_000, 'T'), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn every_record_becomes_an_event_at_its_time() {
        let normalizer = Normalizer::from_yaml(SYSMON).unwrap();
        let mut fleet = Fleet::new(5);
        let mut classes = std::collections::BTreeSet::new();
        for index in 0..2_000 {
            let time = 1_790_244_930_000 + index;
            let record = fleet.record(time).to_string();
            let mut became = Vec::new();
            normalizer.normalize(record.as_bytes(), |outcome| became.push(outcome));
            let [Outcome::Event(done)] = became.as_slice() else {
                panic!("{record} became {became:?}");
            };
            assert!(done.issues.is_empty(), "{:?}", done.issues);
            assert_eq!(done.event["time"], json!(time));
            classes.insert(done.event["class_uid"].as_u64().unwrap());
        }
        assert_eq!(
            classes.into_iter().collect::<Vec<_>>(),
            [1001, 1005, 1007, 4001, 201_002]
        );
    }

    #[test]
    fn the_intrusion_is_one_host_and_one_user_in_time_order() {
        let normalizer = Normalizer::from_yaml(SYSMON).unwrap();
        let steps = Fleet::new(3).intrusion(1_790_244_930_000);
        assert_eq!(steps.len(), 12);
        let mut previous = 0;
        for (time, record) in steps {
            assert!(time > previous);
            previous = time;
            let record = record.to_string();
            let mut became = Vec::new();
            normalizer.normalize(record.as_bytes(), |outcome| became.push(outcome));
            let [Outcome::Event(done)] = became.as_slice() else {
                panic!("{record} became {became:?}");
            };
            assert!(done.issues.is_empty(), "{:?}", done.issues);
            assert_eq!(done.event["time"], json!(time));
            assert_eq!(done.event["device"]["hostname"], "WS-0042.corp.example");
            assert!(record.contains(r"CORP\\user0042"), "{record}");
        }
    }

    #[test]
    fn a_fleet_is_the_same_on_every_run() {
        let (mut first, mut second) = (Fleet::new(9), Fleet::new(9));
        for time in 0..100 {
            assert_eq!(first.record(time), second.record(time));
        }
    }
}
