//! Selection of sources and entities on the simulated clock.
use crate::{
    HostKind, Organization,
    entra::Entra,
    intel::{self, Plant},
    random::{Random, Weighted},
    suricata,
    sysmon::Sysmon,
};

/// One raw JSON record, without a trailing newline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Built-in source definition to normalize with.
    pub source: &'static str,
    /// Simulated Unix time in milliseconds.
    pub time: i64,
    /// JSON bytes in the source's own format.
    pub bytes: Vec<u8>,
}

/// An owned organization and deterministic telemetry state.
pub struct Generator {
    org: Organization,
    random: Random,
    sysmon: Sysmon,
    entra: Entra,
    hour: Option<i64>,
    hosts: Weighted,
    users: Weighted,
    /// Planted HTTP requests so far, each a flow of its own.
    flows: u64,
}

impl Generator {
    /// Starts a stream; the organization is copied once, never per event.
    pub fn new(org: &Organization, seed: u64) -> Self {
        let random = Random::new(seed ^ org.seed);
        let sysmon = Sysmon::new(org, random.fork("sysmon").next());
        let entra = Entra::new(random.fork("entra").next());
        Self {
            org: org.clone(),
            random: random.fork("selection"),
            sysmon,
            entra,
            hour: None,
            hosts: Weighted::new([]),
            users: Weighted::new([]),
            flows: 0,
        }
    }

    /// Generates the next record at `time_ms`. Input times are UTC; office
    /// offsets are fixed and intentionally do not model daylight saving.
    pub fn next(&mut self, time_ms: i64) -> Record {
        self.turn(time_ms);
        let (source, value) = if self.random.chance(0.075) {
            (
                "entra",
                self.entra
                    .record(&self.org, self.users.draw(&mut self.random), time_ms),
            )
        } else {
            (
                "sysmon",
                self.sysmon
                    .record(&self.org, self.hosts.draw(&mut self.random), time_ms),
            )
        };
        Record {
            source,
            time: time_ms,
            bytes: value.to_string().into_bytes(),
        }
    }

    /// Generates a record at `time_ms` that holds indicator `index` of
    /// [`intel`](crate::intel), on a machine drawn as for any record: a
    /// Sysmon event for an address, a name, or a hash, and a Suricata HTTP
    /// request for a URL. It holds no other indicator.
    pub fn planted(&mut self, time_ms: i64, index: u64) -> Record {
        self.turn(time_ms);
        let host = self.hosts.draw(&mut self.random);
        let plant = intel::plant(index);
        let (source, value) = match &plant {
            Plant::Request { host: name, path } => {
                let machine = &self.org.hosts[host];
                let address = machine.address(
                    &self.org.offices[machine.office],
                    time_ms.div_euclid(86_400_000),
                );
                self.flows += 1;
                (
                    "suricata",
                    suricata::http(
                        &address,
                        name,
                        path,
                        1_600_000_000_000_000 + self.flows,
                        time_ms,
                    ),
                )
            }
            plant => (
                "sysmon",
                self.sysmon.planted(&self.org, host, time_ms, plant),
            ),
        };
        Record {
            source,
            time: time_ms,
            bytes: value.to_string().into_bytes(),
        }
    }

    /// Weighs who is active in the hour of `time_ms`, once an hour.
    fn turn(&mut self, time_ms: i64) {
        let hour = time_ms.div_euclid(3_600_000);
        if self.hour != Some(hour) {
            self.users = Weighted::new(
                self.org
                    .users
                    .iter()
                    .map(|u| u.activity * daily(hour + self.org.offices[u.office].utc_offset)),
            );
            self.hosts = Weighted::new(self.org.hosts.iter().map(|h| match h.kind {
                HostKind::Workstation { owner } => {
                    self.org.users[owner].activity
                        * daily(hour + self.org.offices[h.office].utc_offset)
                }
                HostKind::Server { .. } => 0.02,
            }));
            self.hour = Some(hour);
        }
    }
}

fn daily(local_hour: i64) -> f64 {
    let weekday = (local_hour.div_euclid(24) + 3).rem_euclid(7);
    if weekday >= 5 {
        return 0.05;
    }
    match local_hour.rem_euclid(24) {
        9..18 => 1.0,
        18..23 => 0.3,
        _ => 0.05,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[allow(clippy::float_cmp)] // These are selected constants, not computed approximations.
    fn local_working_week() {
        assert_eq!(daily(9), 1.0); // Thursday, 1970-01-01.
        assert_eq!(daily(18), 0.3);
        assert_eq!(daily(23), 0.05);
        assert_eq!(daily(48 + 12), 0.05);
        assert_eq!(daily(-24 + 9), 1.0);
    }
}
