//! The public data in `data/`, compiled in and parsed once. Its sources and
//! licenses are in `data/README.md`.

use std::sync::OnceLock;

/// Given names and each one's share of people.
pub(crate) fn given_names() -> &'static [(&'static str, f64)] {
    static NAMES: OnceLock<Vec<(&str, f64)>> = OnceLock::new();
    NAMES.get_or_init(|| pairs(include_str!("../data/given-names.csv")))
}

/// Surnames and how many people hold each.
pub(crate) fn surnames() -> &'static [(&'static str, f64)] {
    static NAMES: OnceLock<Vec<(&str, f64)>> = OnceLock::new();
    NAMES.get_or_init(|| pairs(include_str!("../data/surnames.csv")))
}

/// Microsoft first-party applications: application id and name.
pub(crate) fn entra_apps() -> &'static [(&'static str, &'static str)] {
    static APPS: OnceLock<Vec<(&str, &str)>> = OnceLock::new();
    APPS.get_or_init(|| {
        rows(include_str!("../data/entra-apps.csv"))
            .map(|fields| (fields[0], fields[1]))
            .collect()
    })
}

/// A Microsoft 365 service endpoint.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Endpoint {
    pub(crate) service: &'static str,
    pub(crate) host: &'static str,
    /// The first address and the size of the network it is served from.
    pub(crate) network: ([u8; 4], u32),
    pub(crate) port: u16,
}

pub(crate) fn m365_endpoints() -> &'static [Endpoint] {
    static ENDPOINTS: OnceLock<Vec<Endpoint>> = OnceLock::new();
    ENDPOINTS.get_or_init(|| {
        rows(include_str!("../data/m365-endpoints.csv"))
            .filter_map(|fields| {
                let (address, bits) = fields[2].split_once('/')?;
                let mut octets = [0; 4];
                for (octet, text) in octets.iter_mut().zip(address.split('.')) {
                    *octet = text.parse().ok()?;
                }
                let bits: u32 = bits.parse().ok()?;
                Some(Endpoint {
                    service: fields[0],
                    host: fields[1],
                    network: (octets, 1 << (32 - bits.min(32))),
                    port: fields[3].parse().ok()?,
                })
            })
            .collect()
    })
}

fn rows(text: &'static str) -> impl Iterator<Item = Vec<&'static str>> {
    text.lines()
        .skip(1)
        .filter(|line| !line.is_empty())
        .map(|line| line.split(',').collect())
}

fn pairs(text: &'static str) -> Vec<(&'static str, f64)> {
    rows(text)
        .filter_map(|fields| Some((fields[0], fields.get(1)?.parse().ok()?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_file_parses_whole() {
        assert_eq!(given_names().len(), 100);
        assert_eq!(surnames().len(), 300);
        assert_eq!(surnames()[0].0, "Smith");
        assert!(entra_apps().len() >= 10);
        assert!(m365_endpoints().len() >= 10);
        assert!(
            m365_endpoints()
                .iter()
                .any(|endpoint| endpoint.host == "outlook.office365.com")
        );
    }
}
