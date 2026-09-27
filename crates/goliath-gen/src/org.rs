//! The organization telemetry comes from: offices, people, their accounts,
//! and their machines.

use std::collections::HashSet;

use crate::data;
use crate::random::{Random, Weighted, zipf};

/// What to generate.
#[derive(Debug, Clone)]
pub struct Options {
    /// The company's name, such as `Acme`.
    pub name: String,
    /// Its DNS domain, used for machine names and sign-in names.
    pub domain: String,
    /// People employed.
    pub users: usize,
    /// Everything follows from it.
    pub seed: u64,
}

impl Default for Options {
    /// Acme, at `acme.example`, with 500 people. The `.example` domain is
    /// reserved for examples, so nothing generated names a real company.
    fn default() -> Self {
        Self {
            name: "Acme".to_owned(),
            domain: "acme.example".to_owned(),
            users: 500,
            seed: 1,
        }
    }
}

/// A company: offices, the people in them, and their machines.
#[derive(Debug, Clone)]
pub struct Organization {
    /// The company's name.
    pub name: String,
    /// Its DNS domain.
    pub domain: String,
    /// Its Windows domain name, as account names carry it: `ACME`.
    pub netbios: String,
    /// Its Entra ID tenant id.
    pub tenant_id: String,
    /// The security identifier prefix of its Windows domain.
    pub domain_sid: String,
    /// Where people work.
    pub offices: Vec<Office>,
    /// People, most active first.
    pub users: Vec<User>,
    /// Workstations and servers.
    pub hosts: Vec<Host>,
    pub(crate) seed: u64,
}

/// An office: a city, a time zone, and networks.
#[derive(Debug, Clone)]
pub struct Office {
    /// The city.
    pub city: &'static str,
    /// The ISO 3166 country code.
    pub country: &'static str,
    /// Three letters that start its machines' names.
    pub code: &'static str,
    /// Hours from UTC. Fixed: the generator does not follow daylight saving.
    pub utc_offset: i64,
    /// Its internal network is `10.<subnet>.0.0/16`.
    pub subnet: u8,
    /// The public address its traffic leaves from.
    pub egress: String,
    /// Latitude and longitude, as sign-in logs locate it.
    pub coordinates: (f64, f64),
}

/// Offices of the generated company; the first is the head office.
const OFFICES: &[(&str, &str, &str, i64, (f64, f64))] = &[
    ("New York", "US", "NYC", -5, (40.7128, -74.0060)),
    ("Chicago", "US", "CHI", -6, (41.8781, -87.6298)),
    ("London", "GB", "LON", 0, (51.5072, -0.1276)),
    ("Singapore", "SG", "SIN", 8, (1.3521, 103.8198)),
];

/// A person, and every name the systems they use know them by.
#[derive(Debug, Clone)]
pub struct User {
    /// Given name.
    pub given: String,
    /// Family name.
    pub family: String,
    /// As directories display it: `Maria Garcia`.
    pub display_name: String,
    /// Their department.
    pub department: &'static str,
    /// Index into [`Organization::offices`].
    pub office: usize,
    /// Windows account name, without the domain: `mgarcia`.
    pub sam: String,
    /// Entra ID sign-in name: `maria.garcia@acme.example`.
    pub upn: String,
    /// Entra ID object id.
    pub object_id: String,
    /// Windows security identifier.
    pub sid: String,
    /// A separate administrative account, for people in IT: `adm-mgarcia`.
    pub admin_sam: Option<String>,
    /// The security identifier of the administrative account.
    pub admin_sid: Option<String>,
    /// Index into [`Organization::hosts`] of their workstation.
    pub workstation: usize,
    /// How much they do, relative to others: a Zipf weight.
    pub activity: f64,
}

/// A machine.
#[derive(Debug, Clone)]
pub struct Host {
    /// Its NetBIOS name: `NYC-LT4821`.
    pub name: String,
    /// Its fully qualified name, as Sysmon writes `Computer`.
    pub fqdn: String,
    /// What it is.
    pub kind: HostKind,
    /// Index into [`Organization::offices`].
    pub office: usize,
    /// Its Entra ID device id.
    pub device_id: String,
    /// How many days its DHCP lease lasts; servers keep one address.
    lease_days: i64,
    salt: u64,
}

/// What a machine is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    /// A laptop or desktop, used by the person at this index of
    /// [`Organization::users`].
    Workstation {
        /// Its owner.
        owner: usize,
    },
    /// A server with a role.
    Server {
        /// What it serves.
        role: ServerRole,
    },
}

/// What a server does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRole {
    /// Active Directory domain controller.
    DomainController,
    /// File shares.
    FileServer,
    /// Microsoft SQL Server.
    Database,
    /// Internal line-of-business applications.
    Application,
}

impl ServerRole {
    fn code(self) -> &'static str {
        match self {
            Self::DomainController => "DC",
            Self::FileServer => "FS",
            Self::Database => "SQL",
            Self::Application => "APP",
        }
    }
}

/// Departments, with the share of people in each.
const DEPARTMENTS: &[(&str, f64)] = &[
    ("Engineering", 0.24),
    ("Sales", 0.18),
    ("Customer Support", 0.12),
    ("Operations", 0.10),
    ("Finance", 0.08),
    ("Marketing", 0.08),
    ("IT", 0.07),
    ("Human Resources", 0.06),
    ("Legal", 0.04),
    ("Executive", 0.03),
];

impl Organization {
    /// Generates the organization `options` describes.
    ///
    /// # Panics
    ///
    /// Panics if `options.users` is zero.
    pub fn generate(options: &Options) -> Self {
        assert!(options.users > 0, "an organization needs people");
        let root = Random::new(options.seed);
        let mut ids = root.fork("ids");
        let netbios = options
            .name
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(15)
            .collect::<String>()
            .to_uppercase();
        let domain_sid = format!(
            "S-1-5-21-{}-{}-{}",
            1_000_000_000 + ids.below(3_000_000_000),
            1_000_000_000 + ids.below(3_000_000_000),
            1_000_000_000 + ids.below(3_000_000_000)
        );
        let tenant_id = ids.guid();

        let mut addresses = root.fork("egress");
        // Larger companies have more offices; the head office is largest.
        let office_count = match options.users {
            0..200 => 1,
            200..1_000 => 2,
            1_000..5_000 => 3,
            _ => OFFICES.len(),
        };
        let offices: Vec<Office> = OFFICES[..office_count]
            .iter()
            .zip(1_u8..)
            .map(|(&(city, country, code, utc_offset, coordinates), subnet)| {
                // Documentation ranges stand in for the company's public
                // addresses, so none belongs to a real network.
                let egress = format!(
                    "{}.{}",
                    ["198.51.100", "203.0.113", "192.0.2"][addresses.below(3)],
                    1 + addresses.below(254)
                );
                Office {
                    city,
                    country,
                    code,
                    utc_offset,
                    subnet,
                    egress,
                    coordinates,
                }
            })
            .collect();

        let mut people = root.fork("people");
        let given = Weighted::new(data::given_names().iter().map(|&(_, share)| share));
        let family = Weighted::new(data::surnames().iter().map(|&(_, count)| count));
        let departments = Weighted::new(DEPARTMENTS.iter().map(|&(_, share)| share));
        let office_weights = Weighted::new((0..offices.len()).map(|index| {
            // The head office holds about half the company.
            if index == 0 { 1.0 } else { 1.0 / offices.len() as f64 }
        }));
        let activity = zipf(options.users, 1.1);

        let mut taken_sams = HashSet::new();
        let mut taken_upns = HashSet::new();
        let mut taken_hosts = HashSet::new();
        let mut users = Vec::with_capacity(options.users);
        let mut hosts = Vec::new();
        let mut machines = root.fork("machines");
        for (index, weight) in activity.into_iter().enumerate() {
            let given_name = data::given_names()[given.draw(&mut people)].0.to_owned();
            let family_name = data::surnames()[family.draw(&mut people)].0.to_owned();
            let department = DEPARTMENTS[departments.draw(&mut people)].0;
            let office = office_weights.draw(&mut people);
            let sam = unique(
                &mut taken_sams,
                &format!(
                    "{}{}",
                    ascii(&given_name)[..1].to_owned(),
                    ascii(&family_name)
                )
                .chars()
                .take(18)
                .collect::<String>(),
                "",
            );
            let upn = format!(
                "{}@{}",
                unique(
                    &mut taken_upns,
                    &format!("{}.{}", ascii(&given_name), ascii(&family_name)),
                    "",
                ),
                options.domain
            );
            // Relative identifiers of domain accounts start at 1103 or so;
            // the first thousand are the domain's own.
            let rid = 1_103 + index * 2;
            let admin = department == "IT";
            let workstation = hosts.len();
            hosts.push(Host::new(
                &mut machines,
                &mut taken_hosts,
                &offices[office],
                office,
                HostKind::Workstation { owner: index },
                &options.domain,
            ));
            users.push(User {
                display_name: format!("{given_name} {family_name}"),
                given: given_name,
                family: family_name,
                department,
                office,
                admin_sam: admin.then(|| format!("adm-{sam}")),
                admin_sid: admin.then(|| format!("{domain_sid}-{}", rid + 1)),
                sam,
                upn,
                object_id: ids.guid(),
                sid: format!("{domain_sid}-{rid}"),
                workstation,
                activity: weight,
            });
        }
        for (index, office) in offices.iter().enumerate() {
            let roles: &[ServerRole] = if index == 0 {
                &[
                    ServerRole::DomainController,
                    ServerRole::DomainController,
                    ServerRole::FileServer,
                    ServerRole::Database,
                    ServerRole::Application,
                ]
            } else {
                &[ServerRole::DomainController, ServerRole::FileServer]
            };
            for &role in roles {
                hosts.push(Host::new(
                    &mut machines,
                    &mut taken_hosts,
                    office,
                    index,
                    HostKind::Server { role },
                    &options.domain,
                ));
            }
        }
        Self {
            name: options.name.clone(),
            domain: options.domain.clone(),
            netbios,
            tenant_id,
            domain_sid,
            offices,
            users,
            hosts,
            seed: options.seed,
        }
    }

    /// Servers in an office with a role.
    pub fn servers(&self, office: usize, role: ServerRole) -> impl Iterator<Item = usize> + '_ {
        self.hosts.iter().enumerate().filter_map(move |(index, host)| {
            (host.office == office && host.kind == HostKind::Server { role }).then_some(index)
        })
    }
}

impl Host {
    fn new(
        random: &mut Random,
        taken: &mut HashSet<String>,
        office: &Office,
        office_index: usize,
        kind: HostKind,
        domain: &str,
    ) -> Self {
        let name = match kind {
            HostKind::Workstation { .. } => loop {
                // Asset tags: laptops mostly, some desktops.
                let form = if random.chance(0.8) { "LT" } else { "DT" };
                let name = format!("{}-{form}{:04}", office.code, 1_000 + random.below(9_000));
                if taken.insert(name.clone()) {
                    break name;
                }
            },
            HostKind::Server { role } => {
                unique(taken, &format!("{}-{}", office.code, role.code()), "0")
            }
        };
        Self {
            fqdn: format!("{}.{domain}", name.to_lowercase()),
            name,
            kind,
            office: office_index,
            device_id: random.guid(),
            lease_days: match kind {
                HostKind::Workstation { .. } => 1 + i64::try_from(random.below(7)).unwrap_or(0),
                HostKind::Server { .. } => 0,
            },
            salt: random.next(),
        }
    }

    /// Its internal address on day `day`, counted from the Unix epoch.
    /// Workstations get a new one from DHCP when their lease runs out;
    /// servers keep theirs.
    pub fn address(&self, office: &Office, day: i64) -> String {
        let lease = if self.lease_days == 0 {
            0
        } else {
            day.div_euclid(self.lease_days)
        };
        let mut random = Random::new(self.salt ^ lease.unsigned_abs());
        let (third, fourth) = match self.kind {
            HostKind::Server { .. } => (10, 10 + random.below(200)),
            HostKind::Workstation { .. } => (32 + random.below(64), 2 + random.below(252)),
        };
        format!("10.{}.{third}.{fourth}", office.subnet)
    }
}

/// `base`, or `base` with the first free number appended: `jsmith`,
/// `jsmith2`; for servers `NYC-DC` becomes `NYC-DC01`, `NYC-DC02`.
fn unique(taken: &mut HashSet<String>, base: &str, pad: &str) -> String {
    let mut number = 1;
    loop {
        let candidate = match (number, pad) {
            (1, "") => base.to_owned(),
            (_, "") => format!("{base}{number}"),
            _ => format!("{base}{number:02}"),
        };
        if taken.insert(candidate.to_lowercase()) {
            return candidate;
        }
        number += 1;
    }
}

/// A name as account names spell it: lowercase ASCII letters only.
fn ascii(name: &str) -> String {
    name.chars()
        .filter(char::is_ascii_alphabetic)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn organization(users: usize) -> Organization {
        Organization::generate(&Options {
            users,
            ..Options::default()
        })
    }

    #[test]
    fn names_and_accounts_are_unique_and_consistent() {
        let org = organization(2_000);
        let sams: HashSet<_> = org.users.iter().map(|user| &user.sam).collect();
        let upns: HashSet<_> = org.users.iter().map(|user| &user.upn).collect();
        let hosts: HashSet<_> = org.hosts.iter().map(|host| &host.name).collect();
        assert_eq!(sams.len(), 2_000);
        assert_eq!(upns.len(), 2_000);
        assert_eq!(hosts.len(), org.hosts.len());
        for user in &org.users {
            assert!(user.upn.ends_with("@acme.example"), "{}", user.upn);
            assert!(user.sid.starts_with(&org.domain_sid));
            let HostKind::Workstation { owner } = org.hosts[user.workstation].kind else {
                panic!("{} has no workstation", user.sam);
            };
            assert_eq!(&org.users[owner].sam, &user.sam);
        }
        assert_eq!(org.netbios, "ACME");
    }

    #[test]
    fn common_names_are_common() {
        let org = organization(5_000);
        let smiths = org.users.iter().filter(|user| user.family == "Smith").count();
        // Smith is about 2.6% of the 300 surnames' holders.
        assert!((70..200).contains(&smiths), "{smiths} Smiths");
        assert!(org.users.iter().any(|user| user.sam.ends_with('2')));
    }

    #[test]
    fn people_in_it_have_administrative_accounts() {
        let org = organization(1_000);
        let admins: Vec<_> = org.users.iter().filter(|user| user.admin_sam.is_some()).collect();
        assert!(!admins.is_empty());
        for user in admins {
            assert_eq!(user.department, "IT");
            assert_eq!(user.admin_sam.as_deref(), Some(format!("adm-{}", user.sam).as_str()));
        }
    }

    #[test]
    fn workstations_change_address_and_servers_do_not() {
        let org = organization(300);
        let office = &org.offices[0];
        let workstation = &org.hosts[org.users[0].workstation];
        let addresses: HashSet<_> = (0..30).map(|day| workstation.address(office, day)).collect();
        assert!(addresses.len() > 3, "{addresses:?}");
        let server = &org.hosts[org.servers(0, ServerRole::DomainController).next().unwrap()];
        assert_eq!(server.address(office, 0), server.address(office, 29));
        assert_eq!(server.name, "NYC-DC01");
    }

    #[test]
    fn the_same_seed_gives_the_same_organization() {
        let (first, second) = (organization(200), organization(200));
        assert_eq!(first.tenant_id, second.tenant_id);
        assert_eq!(
            first.users.iter().map(|user| &user.upn).collect::<Vec<_>>(),
            second.users.iter().map(|user| &user.upn).collect::<Vec<_>>()
        );
    }
}
