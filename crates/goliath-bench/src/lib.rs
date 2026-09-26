//! Workloads for measuring Goliath.
//!
//! A workload is a set of rules and a stream of events, generated from a seed
//! so that every run measures exactly the same work. The Callgrind benchmarks
//! count the instructions the engine spends on one, and CI fails a pull
//! request that makes that count grow; see `docs/benchmarks.md`.
//!
//! The rules and events are synthetic, shaped after `SigmaHQ`'s Windows
//! process creation rules: mostly suffix tests on the image and substring
//! tests on the command line, some with filters, a few with wildcards and
//! regular expressions. That makes them a guard against regressions, not a
//! claim about speed. The claim is made on real `SigmaHQ` rules and events in
//! `docs/sigma-coverage.md`.

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use std::fmt::Write as _;

use goliath_rule::{MappingSet, ResolvedRule, sigma};
use serde_json::{Value, json};

mod sysmon;

pub use sysmon::{Fleet, rfc3339};

const SIGMA_WINDOWS: &str = goliath_rule::SIGMA_WINDOWS;

/// Rules and the events to evaluate them against.
#[derive(Debug, Clone)]
pub struct Workload {
    /// Resolved rules, ready for [`goliath_match::Engine::new`].
    pub rules: Vec<ResolvedRule>,
    /// OCSF events.
    pub events: Vec<Value>,
}

/// Windows process launches against process creation rules.
///
/// About one event in ten is suspicious, built from the same binaries and
/// command line fragments the rules look for. The rest is ordinary activity,
/// much of it by the same binaries, which rules must wake up for and then
/// reject.
///
/// # Panics
///
/// Panics if a generated rule does not parse or resolve, which is a bug in
/// the generator rather than a condition to handle.
#[allow(clippy::expect_used)]
pub fn process_creation(rules: usize, events: usize, seed: u64) -> Workload {
    let mut random = Random::new(seed);
    let mappings = MappingSet::from_yaml(SIGMA_WINDOWS).expect("shipped mapping loads");
    let rules = (0..rules)
        .map(|index| {
            let source = rule(&mut random, index);
            let parsed = goliath_sigma::parse_rule(&source).expect("generated rule parses");
            sigma::resolve(&parsed, &mappings).expect("generated rule resolves")
        })
        .collect();
    let events = (0..events).map(|_| launch(&mut random)).collect();
    Workload { rules, events }
}

/// A small deterministic generator, so a workload is the same on every run
/// and every platform.
#[derive(Debug)]
struct Random(u64);

impl Random {
    fn new(seed: u64) -> Self {
        // xorshift never leaves zero.
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        // xorshift64
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        // The bound is small, so the remainder fits and its bias is
        // irrelevant here.
        usize::try_from(self.next() % bound as u64).unwrap_or(0)
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }

    /// Between one and `most` distinct items.
    fn some<'a>(&mut self, items: &[&'a str], most: usize) -> Vec<&'a str> {
        let count = 1 + self.below(most);
        let mut chosen: Vec<&str> = Vec::with_capacity(count);
        while chosen.len() < count {
            let item = self.pick(items);
            if !chosen.contains(&item) {
                chosen.push(item);
            }
        }
        chosen
    }
}

/// Binaries that attack tooling and living off the land techniques use.
const SUSPICIOUS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "schtasks.exe",
    "wmic.exe",
    "net.exe",
    "net1.exe",
    "reg.exe",
    "sc.exe",
    "msiexec.exe",
    "installutil.exe",
    "msbuild.exe",
    "curl.exe",
    "whoami.exe",
    "nltest.exe",
    "vssadmin.exe",
    "bcdedit.exe",
    "wevtutil.exe",
    "taskkill.exe",
    "procdump.exe",
    "rclone.exe",
    "7z.exe",
    "adfind.exe",
];

/// Binaries of ordinary activity.
const ORDINARY: &[&str] = &[
    "explorer.exe",
    "svchost.exe",
    "chrome.exe",
    "msedge.exe",
    "teams.exe",
    "outlook.exe",
    "winword.exe",
    "excel.exe",
    "notepad.exe",
    "code.exe",
    "git.exe",
    "python.exe",
    "node.exe",
    "java.exe",
    "conhost.exe",
    "dllhost.exe",
    "searchindexer.exe",
    "onedrive.exe",
    "taskhostw.exe",
    "spoolsv.exe",
];

const DIRECTORIES: &[&str] = &[
    r"C:\Windows\System32\",
    r"C:\Windows\SysWOW64\",
    r"C:\Program Files\Common Files\",
    r"C:\Users\adam\AppData\Local\Temp\",
    r"C:\ProgramData\",
];

const PARENTS: &[&str] = &[
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    r"C:\Windows\System32\services.exe",
];

/// Command line fragments that rules look for.
const FRAGMENTS: &[&str] = &[
    " -enc ",
    " -nop ",
    " -w hidden",
    "downloadstring",
    "invoke-expression",
    "iex(",
    "frombase64string",
    "/c whoami",
    "-urlcache",
    "-split",
    "/transfer",
    "/create /sc",
    "shadowcopy delete",
    "delete shadows",
    "resize shadowstorage",
    "recoveryenabled no",
    "process call create",
    "javascript:",
    "vbscript:",
    r"\\127.0.0.1\admin$",
    "add-mppreference",
    "-exclusionpath",
    "disablerealtimemonitoring",
    "comsvcs.dll",
    "minidump",
    "sekurlsa",
    "lsadump",
    "-accepteula",
    "/node:",
    "net user",
    "/add",
    "localgroup administrators",
    "domain admins",
    "/dclist",
    r"save hklm\sam",
    r"hklm\system",
    "/ru system",
    "-exec bypass",
    "scrobj.dll",
    "/i:http",
    "-decode",
    "-decodehex",
    r"\appdata\",
    "wevtutil cl",
    "clear-eventlog",
    ".hta",
];

/// Short command line fragments that ordinary activity is full of. `SigmaHQ`
/// rules use them only together with a specific image, as rules here do.
const COMMON: &[&str] = &[
    " /c ", ".dll", "http", "http://", "https://", " -e ", "/i ", ".bat", ".ps1", "copy ",
];

/// Ordinary uses of the same binaries attackers use. Real telemetry is full
/// of them, and they are what makes a rule's choice of trigger matter: a
/// rule waiting on `\cmd.exe` or `.dll` wakes on every one.
const ADMINISTRATION: &[(&str, &str)] = &[
    ("cmd.exe", "/c echo ok"),
    ("cmd.exe", r#"/c "C:\Program Files\Vendor\run.bat""#),
    ("cmd.exe", r"/c copy C:\logs\app.log \\backup\logs\"),
    ("powershell.exe", "-NoProfile -Command Get-Process"),
    ("powershell.exe", r"-File C:\scripts\inventory.ps1"),
    (
        "powershell.exe",
        "-ExecutionPolicy RemoteSigned -File update.ps1",
    ),
    ("rundll32.exe", "shell32.dll,Control_RunDLL"),
    (
        "rundll32.exe",
        r"C:\Windows\System32\printui.dll,PrintUIEntryDPIAware",
    ),
    ("rundll32.exe", "advapi32.dll,ProcessIdleTasks"),
    ("msiexec.exe", r"/i C:\Windows\Temp\agent.msi /qn"),
    ("schtasks.exe", "/query /fo csv"),
    ("reg.exe", r"query HKLM\Software\Vendor"),
    ("net.exe", r"use Z: \\fileserver\share"),
    ("curl.exe", "-s https://api.example.com/health"),
    ("regsvr32.exe", r"/s C:\Program Files\Vendor\plugin.dll"),
    ("wmic.exe", "os get caption"),
];

/// Command line arguments of ordinary activity.
const ARGUMENTS: &[&str] = &[
    "--type=renderer",
    "/prefetch:1",
    "-Embedding",
    "--no-sandbox",
    "status",
    "commit -m update",
    "-m pip install requests",
    "--update",
    "/S",
    "-k netsvcs -p",
    "/background",
    "--profile-directory=Default",
    r"C:\Users\adam\Documents\report.docx",
    "--field-trial-handle=1812",
    "-ServerName:App.AppXzst44mncqdg84v7sv6p7yznqwssy6f7f.mca",
];

fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

fn list(items: &[&str], prefix: &str) -> String {
    let mut out = String::new();
    for item in items {
        let _ = write!(out, "\n      - {}", quoted(&format!("{prefix}{item}")));
    }
    out
}

/// A Sigma rule in the style of `SigmaHQ`'s process creation rules.
fn rule(random: &mut Random, index: usize) -> String {
    let mut detection = String::new();
    let condition = match random.below(100) {
        // An image and what its command line contains: the commonest shape.
        0..45 => {
            let images = random.some(SUSPICIOUS, 3);
            let fragments = random.some(FRAGMENTS, 3);
            let all = if fragments.len() > 1 && random.chance(40) {
                "|all"
            } else {
                ""
            };
            let _ = write!(
                detection,
                "  selection_img:
    Image|endswith:{}
  selection_cli:
    CommandLine|contains{all}:{}
",
                list(&images, "\\"),
                list(&fragments, ""),
            );
            // Some rules also require a common fragment, such as `.dll` for
            // `rundll32.exe`: ordinary activity then has two literals to wake
            // the rule and only the specific one to reject it with.
            if random.chance(30) {
                let _ = write!(
                    detection,
                    "  selection_common:
    CommandLine|contains:{}
",
                    list(&random.some(COMMON, 2), ""),
                );
            }
            "all of selection_*"
        }
        // The same with a filter on the parent.
        45..60 => {
            let image = random.pick(SUSPICIOUS);
            let fragments = random.some(FRAGMENTS, 2);
            let parents = random.some(PARENTS, 2);
            let _ = write!(
                detection,
                "  selection:\n    Image|endswith: {}\n    CommandLine|contains:{}\n  filter_parent:\n    ParentImage:{}\n",
                quoted(&format!("\\{image}")),
                list(&fragments, ""),
                list(&parents, ""),
            );
            "selection and not 1 of filter_*"
        }
        // A renamed binary: the image or its original file name.
        60..70 => {
            let image = random.pick(SUSPICIOUS);
            let fragment = random.pick(FRAGMENTS);
            let _ = write!(
                detection,
                "  selection_img:\n    - Image|endswith: {}\n    - OriginalFileName: {}\n  selection_cli:\n    CommandLine|contains: {}\n",
                quoted(&format!("\\{image}")),
                quoted(&image.to_uppercase()),
                quoted(fragment),
            );
            "all of selection_*"
        }
        // Command line fragments alone.
        70..82 => {
            let fragments = random.some(FRAGMENTS, 3);
            let _ = write!(
                detection,
                "  selection:\n    CommandLine|contains|all:{}\n",
                list(&fragments, ""),
            );
            "selection"
        }
        // A suspicious parent and child.
        82..90 => {
            let parent = random.pick(ORDINARY);
            let images = random.some(SUSPICIOUS, 2);
            let _ = write!(
                detection,
                "  selection:\n    ParentImage|endswith: {}\n    Image|endswith:{}\n",
                quoted(&format!("\\{parent}")),
                list(&images, "\\"),
            );
            "selection"
        }
        // A wildcard pattern, which takes the engine's general path.
        90..96 => {
            let image = random.pick(SUSPICIOUS);
            let fragment = random.pick(FRAGMENTS);
            let _ = write!(
                detection,
                "  selection:\n    CommandLine: {}\n",
                quoted(&format!("*{image}*{fragment}*")),
            );
            "selection"
        }
        // A regular expression.
        _ => {
            let image = random.pick(SUSPICIOUS).trim_end_matches(".exe");
            let _ = write!(
                detection,
                "  selection:\n    CommandLine|re: {}\n",
                quoted(&format!(r"(?i)\\{image}\.exe.+-[a-z]{{3,}}\s")),
            );
            "selection"
        }
    };
    format!(
        "title: Generated rule {index}\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n{detection}  condition: {condition}\n"
    )
}

/// A Windows process launch in OCSF.
fn launch(random: &mut Random) -> Value {
    let (image, cmd_line) = if random.chance(10) {
        let image = random.pick(SUSPICIOUS);
        let fragments = random.some(FRAGMENTS, 3).concat();
        (image, format!("{image} {fragments}"))
    } else if random.chance(40) {
        let (image, arguments) = ADMINISTRATION[random.below(ADMINISTRATION.len())];
        (image, format!("{image} {arguments}"))
    } else {
        let image = random.pick(ORDINARY);
        let arguments = random.some(ARGUMENTS, 2).join(" ");
        (image, format!("\"{image}\" {arguments}"))
    };
    let directory = random.pick(DIRECTORIES);
    let path = if random.chance(30) {
        format!("{directory}{}", image.to_uppercase())
    } else {
        format!("{directory}{image}")
    };
    json!({
        "class_uid": 1007,
        "activity_id": 1,
        "device": { "os": { "type_id": 100, "name": "Windows" } },
        "process": {
            "pid": 1000 + random.below(60_000),
            "file": { "path": path },
            "cmd_line": cmd_line,
            "user": { "name": r"CORP\adam" },
            "parent_process": {
                "pid": 4 + random.below(1_000),
                "file": { "path": random.pick(PARENTS) },
            },
        },
        "unmapped": { "OriginalFileName": image.to_uppercase() },
    })
}

#[cfg(test)]
mod tests {
    use goliath_match::Engine;

    use super::*;

    #[test]
    fn a_workload_is_the_same_on_every_run() {
        let first = process_creation(50, 50, 7);
        let second = process_creation(50, 50, 7);
        assert_eq!(first.rules, second.rules);
        assert_eq!(first.events, second.events);
    }

    #[test]
    fn every_shape_of_rule_resolves_and_compiles() {
        let workload = process_creation(2_000, 10, 1);
        Engine::new(workload.rules).expect("generated rules compile");
    }

    #[test]
    fn some_events_match_and_most_do_not() {
        // A workload where nothing matches, or everything does, would not
        // exercise the engine the way real traffic does.
        let workload = process_creation(1_000, 1_000, 3);
        let engine = Engine::new(workload.rules).expect("rules compile");
        let matching = workload
            .events
            .iter()
            .filter(|event| !engine.matches(event).is_empty())
            .count();
        assert!((50..500).contains(&matching), "{matching} of 1000 matched");
    }
}
