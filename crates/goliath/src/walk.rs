//! Walks of the entity graph: what is within two links of an entity, and
//! a path between two.
//!
//! See "What the API answers" in `docs/adr/0025-entity-graph.md`. A walk is
//! made one step at a time, each step one bounded query of the store, so
//! that the bounds apply between steps:
//!
//! - an entity seen with more others than a limit is a hub. It is in the
//!   answer, with its degree, and is not walked through, unless it is the
//!   entity asked for by name or the request allows it;
//! - a step is made from a bounded number of entities and reads a bounded
//!   number of rows. An answer that a bound cut short says so.

use std::collections::{HashMap, HashSet};

use goliath_store::{Degree, Edge, SearchLimits, Store, StoreError};

/// What a walk reads of the graph: one bounded query a call.
pub(crate) trait Steps {
    /// The degree of each of `entities` that was seen with anything.
    async fn degrees(&self, entities: &[String]) -> Result<Vec<Degree>, StoreError>;
    /// Every way each of `entities` was seen with another, the most
    /// recently seen first and `limit` rows at most.
    async fn edges(&self, entities: &[String], limit: u32) -> Result<Vec<Edge>, StoreError>;
}

/// The store, asked within one scope, range, and choice of links.
pub(crate) struct InStore<'a> {
    pub(crate) store: &'a Store,
    pub(crate) scope: &'a str,
    pub(crate) range: (i64, i64),
    pub(crate) links: &'a [String],
    pub(crate) limits: SearchLimits,
}

impl Steps for InStore<'_> {
    async fn degrees(&self, entities: &[String]) -> Result<Vec<Degree>, StoreError> {
        self.store
            .degrees(self.scope, entities, self.range, self.links, self.limits)
            .await
    }

    async fn edges(&self, entities: &[String], limit: u32) -> Result<Vec<Edge>, StoreError> {
        self.store
            .edges(
                self.scope,
                entities,
                self.range,
                self.links,
                limit,
                self.limits,
            )
            .await
    }
}

/// What bounds every step of a walk.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bounds {
    /// An entity seen with more others than this is a hub.
    pub(crate) hub_over: u64,
    /// Entities one step is made from at most.
    pub(crate) frontier: usize,
    /// Rows one step reads at most.
    pub(crate) rows: u32,
}

/// One way two entities were seen together, from the one that acted to the
/// one acted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Link {
    pub(crate) src: String,
    pub(crate) dst: String,
    /// What was done, such as `logged_on_to`.
    pub(crate) kind: String,
    pub(crate) events: u64,
    pub(crate) first_seen: i64,
    pub(crate) last_seen: i64,
}

impl Link {
    fn of(edge: &Edge) -> Self {
        let (src, dst) = if edge.direction == "in" {
            (&edge.neighbour, &edge.origin)
        } else {
            (&edge.origin, &edge.neighbour)
        };
        Self {
            src: src.clone(),
            dst: dst.clone(),
            kind: edge.link.clone(),
            events: edge.events,
            first_seen: edge.first_seen,
            last_seen: edge.last_seen,
        }
    }
}

/// An entity a walk reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Node {
    pub(crate) entity: String,
    /// Links from the entity the walk began at.
    pub(crate) distance: u8,
    /// How many entities it was seen with in the range, if the walk asked.
    pub(crate) degree: Option<u64>,
    /// Whether it is a hub the walk did not go through.
    pub(crate) hub: bool,
}

/// What lies within some links of an entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Walked {
    /// The entities reached, the nearest first, the one asked for first of
    /// all.
    pub(crate) nodes: Vec<Node>,
    pub(crate) links: Vec<Link>,
    /// Whether no bound cut the walk short.
    pub(crate) complete: bool,
}

/// Which of `frontier` a step is made from, and which are hubs with their
/// degree. `named` are walked from whatever their degree: they were asked
/// for by name.
async fn sorted(
    steps: &impl Steps,
    frontier: &[String],
    named: &[&str],
    through_hubs: bool,
    hub_over: u64,
) -> Result<(Vec<String>, HashMap<String, u64>), StoreError> {
    let degrees: HashMap<String, u64> = steps
        .degrees(frontier)
        .await?
        .into_iter()
        .map(|one| (one.entity, one.degree))
        .collect();
    let walked = frontier
        .iter()
        .filter(|entity| {
            through_hubs
                || named.contains(&entity.as_str())
                || degrees.get(*entity).copied().unwrap_or(0) <= hub_over
        })
        .cloned()
        .collect();
    Ok((walked, degrees))
}

/// What lies within `depth` links of `start`.
pub(crate) async fn walk(
    steps: &impl Steps,
    start: &str,
    depth: u8,
    bounds: Bounds,
) -> Result<Walked, StoreError> {
    let mut nodes = vec![Node {
        entity: start.to_owned(),
        distance: 0,
        degree: None,
        hub: false,
    }];
    let mut at: HashMap<String, usize> = HashMap::from([(start.to_owned(), 0)]);
    let mut links = Vec::new();
    let mut read: HashSet<(String, String, String)> = HashSet::new();
    let mut complete = true;
    let mut frontier = vec![start.to_owned()];
    for distance in 1..=depth {
        let (walked, degrees) = sorted(steps, &frontier, &[start], false, bounds.hub_over).await?;
        for entity in &frontier {
            let node = &mut nodes[at[entity]];
            node.degree = Some(degrees.get(entity).copied().unwrap_or(0));
            node.hub = !walked.contains(entity);
        }
        let edges = steps.edges(&walked, bounds.rows).await?;
        complete &= edges.len() < bounds.rows as usize;
        let mut next = Vec::new();
        for edge in &edges {
            let link = Link::of(edge);
            // A link between two entities of one step is read from both.
            if !read.insert((link.src.clone(), link.dst.clone(), link.kind.clone())) {
                continue;
            }
            links.push(link);
            if !at.contains_key(&edge.neighbour) {
                at.insert(edge.neighbour.clone(), nodes.len());
                nodes.push(Node {
                    entity: edge.neighbour.clone(),
                    distance,
                    degree: None,
                    hub: false,
                });
                next.push(edge.neighbour.clone());
            }
        }
        if distance < depth && next.len() > bounds.frontier {
            next.truncate(bounds.frontier);
            complete = false;
        }
        frontier = next;
        if frontier.is_empty() {
            break;
        }
    }
    Ok(Walked {
        nodes,
        links,
        complete,
    })
}

/// One link of a path: two entities, and every way they were seen
/// together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hop {
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) links: Vec<Link>,
}

/// A path between two entities, if one was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Found {
    /// The path, from the source to the target; empty if they are one
    /// entity, and none if no path was found.
    pub(crate) hops: Option<Vec<Hop>>,
    /// Hubs the search met and did not go through, with their degree.
    pub(crate) hubs: Vec<(String, u64)>,
    /// Whether no bound cut the search short: if not, a path may exist
    /// that was not found.
    pub(crate) complete: bool,
}

/// One end of a search for a path: what it reached, and from where.
struct Side {
    /// For each entity reached, the entity it was reached from and how the
    /// two were seen together; none for the end itself.
    reached: HashMap<String, Option<(String, Vec<Link>)>>,
    frontier: Vec<String>,
}

impl Side {
    fn new(end: &str) -> Self {
        Self {
            reached: HashMap::from([(end.to_owned(), None)]),
            frontier: vec![end.to_owned()],
        }
    }

    /// The hops from `entity` back to this side's end.
    fn back(&self, entity: &str) -> Vec<Hop> {
        let mut hops = Vec::new();
        let mut at = entity.to_owned();
        while let Some(Some((from, links))) = self.reached.get(&at) {
            hops.push(Hop {
                from: at.clone(),
                to: from.clone(),
                links: links.clone(),
            });
            at.clone_from(from);
        }
        hops
    }
}

/// The shortest path between `source` and `target` of `most` links at
/// most, within the bounds: searched from both ends, a whole step at once,
/// so the first meeting is a shortest path.
pub(crate) async fn path(
    steps: &impl Steps,
    source: &str,
    target: &str,
    most: u8,
    through_hubs: bool,
    bounds: Bounds,
) -> Result<Found, StoreError> {
    let mut found = Found {
        hops: None,
        hubs: Vec::new(),
        complete: true,
    };
    if source == target {
        found.hops = Some(Vec::new());
        return Ok(found);
    }
    let ends = [source, target];
    let mut sides = [Side::new(source), Side::new(target)];
    let mut hubs: HashMap<String, u64> = HashMap::new();
    for _ in 0..most {
        // The smaller side is stepped from: it reads less.
        let near = usize::from(
            sides[0].frontier.is_empty()
                || (!sides[1].frontier.is_empty()
                    && sides[1].frontier.len() < sides[0].frontier.len()),
        );
        if sides[near].frontier.is_empty() {
            break;
        }
        let (walked, degrees) = sorted(
            steps,
            &sides[near].frontier,
            &ends,
            through_hubs,
            bounds.hub_over,
        )
        .await?;
        for entity in &sides[near].frontier {
            if !walked.contains(entity) {
                hubs.insert(entity.clone(), degrees.get(entity).copied().unwrap_or(0));
            }
        }
        let edges = steps.edges(&walked, bounds.rows).await?;
        found.complete &= edges.len() < bounds.rows as usize;
        let mut next: Vec<String> = Vec::new();
        for edge in &edges {
            match sides[near].reached.get_mut(&edge.neighbour) {
                None => {
                    sides[near].reached.insert(
                        edge.neighbour.clone(),
                        Some((edge.origin.clone(), vec![Link::of(edge)])),
                    );
                    next.push(edge.neighbour.clone());
                }
                // Another way the two were seen together in this step.
                Some(Some((from, links)))
                    if *from == edge.origin && next.contains(&edge.neighbour) =>
                {
                    links.push(Link::of(edge));
                }
                Some(_) => {}
            }
        }
        // Where the two sides meet. A hub is no meeting place, and what
        // was just reached has no degree known yet.
        let far = 1 - near;
        let mut meetings: Vec<String> = next
            .iter()
            .filter(|entity| sides[far].reached.contains_key(*entity))
            .cloned()
            .collect();
        if !through_hubs && !meetings.is_empty() {
            let (open, degrees) = sorted(steps, &meetings, &ends, false, bounds.hub_over).await?;
            for entity in &meetings {
                if !open.contains(entity) {
                    hubs.insert(entity.clone(), degrees.get(entity).copied().unwrap_or(0));
                }
            }
            meetings = open;
        }
        if let Some(meeting) = meetings.first() {
            let mut hops: Vec<Hop> = sides[0]
                .back(meeting)
                .into_iter()
                .rev()
                .map(|hop| Hop {
                    from: hop.to,
                    to: hop.from,
                    links: hop.links,
                })
                .collect();
            hops.extend(sides[1].back(meeting));
            found.hops = Some(hops);
            break;
        }
        // A hub found at a meeting is not stepped from later either.
        next.retain(|entity| !hubs.contains_key(entity));
        if next.len() > bounds.frontier {
            next.truncate(bounds.frontier);
            found.complete = false;
        }
        sides[near].frontier = next;
    }
    found.hubs = hubs.into_iter().collect();
    found.hubs.sort();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A graph in memory, read as the store's steps read theirs.
    struct Drawn(Vec<(&'static str, &'static str, &'static str)>);

    impl Drawn {
        fn around(&self, entity: &str) -> Vec<Edge> {
            self.0
                .iter()
                .enumerate()
                .filter_map(|(index, (src, link, dst))| {
                    let (neighbour, direction) = if *src == entity {
                        (*dst, "out")
                    } else if *dst == entity {
                        (*src, "in")
                    } else {
                        return None;
                    };
                    let time = i64::try_from(index).unwrap_or(0);
                    Some(Edge {
                        origin: entity.to_owned(),
                        neighbour: neighbour.to_owned(),
                        direction: direction.to_owned(),
                        link: (*link).to_owned(),
                        events: 1,
                        first_seen: time,
                        last_seen: time,
                    })
                })
                .collect()
        }
    }

    impl Steps for Drawn {
        fn degrees(
            &self,
            entities: &[String],
        ) -> impl Future<Output = Result<Vec<Degree>, StoreError>> {
            std::future::ready(Ok(entities
                .iter()
                .map(|entity| Degree {
                    entity: entity.clone(),
                    degree: self
                        .around(entity)
                        .iter()
                        .map(|edge| edge.neighbour.clone())
                        .collect::<HashSet<_>>()
                        .len() as u64,
                })
                .filter(|one| one.degree > 0)
                .collect()))
        }

        fn edges(
            &self,
            entities: &[String],
            limit: u32,
        ) -> impl Future<Output = Result<Vec<Edge>, StoreError>> {
            let mut edges: Vec<Edge> = entities
                .iter()
                .flat_map(|entity| self.around(entity))
                .collect();
            edges.sort_by_key(|edge| std::cmp::Reverse(edge.last_seen));
            edges.truncate(limit as usize);
            std::future::ready(Ok(edges))
        }
    }

    const BOUNDS: Bounds = Bounds {
        hub_over: 3,
        frontier: 100,
        rows: 1000,
    };

    /// An account that signed in to a workstation and to a server
    /// everybody signs in to; behind the workstation, a file server.
    fn office() -> Drawn {
        Drawn(vec![
            ("adam", "logged_on_to", "ws-7"),
            ("adam", "logged_on_to", "dc-1"),
            ("eve", "logged_on_to", "dc-1"),
            ("bob", "logged_on_to", "dc-1"),
            ("carol", "logged_on_to", "dc-1"),
            ("ws-7", "connected_to", "files"),
            ("adam", "ran_on", "ws-7"),
            ("eve", "logged_on_to", "files"),
        ])
    }

    fn reached(walked: &Walked) -> Vec<(&str, u8)> {
        let mut reached: Vec<(&str, u8)> = walked
            .nodes
            .iter()
            .map(|node| (node.entity.as_str(), node.distance))
            .collect();
        reached.sort_unstable();
        reached
    }

    #[tokio::test]
    async fn a_walk_goes_two_links_and_not_through_a_hub() {
        let walked = walk(&office(), "adam", 2, BOUNDS).await.unwrap();
        // Everybody signs in to dc-1: it is reached and not walked through,
        // so eve, bob and carol are not within two links of adam.
        assert_eq!(
            reached(&walked),
            [("adam", 0), ("dc-1", 1), ("files", 2), ("ws-7", 1)]
        );
        let hub = walked.nodes.iter().find(|node| node.entity == "dc-1");
        assert_eq!(
            hub.map(|node| (node.degree, node.hub)),
            Some((Some(4), true))
        );
        let near = walked.nodes.iter().find(|node| node.entity == "ws-7");
        assert_eq!(
            near.map(|node| (node.degree, node.hub)),
            Some((Some(2), false))
        );
        // Both ways adam was seen with ws-7, each once.
        let ways: Vec<&str> = walked
            .links
            .iter()
            .filter(|link| link.src == "adam" && link.dst == "ws-7")
            .map(|link| link.kind.as_str())
            .collect();
        assert_eq!(ways.len(), 2);
        assert!(ways.contains(&"logged_on_to") && ways.contains(&"ran_on"));
        assert_eq!(walked.links.len(), 4);
        assert!(walked.complete);
    }

    #[tokio::test]
    async fn a_hub_asked_for_by_name_is_walked_from() {
        let walked = walk(&office(), "dc-1", 1, BOUNDS).await.unwrap();
        assert_eq!(
            reached(&walked),
            [
                ("adam", 1),
                ("bob", 1),
                ("carol", 1),
                ("dc-1", 0),
                ("eve", 1)
            ]
        );
        assert!(!walked.nodes[0].hub);
    }

    #[tokio::test]
    async fn a_walk_cut_short_by_a_bound_says_so() {
        let few = Bounds { rows: 2, ..BOUNDS };
        let walked = walk(&office(), "adam", 1, few).await.unwrap();
        assert_eq!(walked.links.len(), 2);
        assert!(!walked.complete);
    }

    fn names(found: &Found) -> Option<Vec<&str>> {
        let hops = found.hops.as_ref()?;
        let mut names: Vec<&str> = hops
            .first()
            .map(|hop| hop.from.as_str())
            .into_iter()
            .collect();
        names.extend(hops.iter().map(|hop| hop.to.as_str()));
        Some(names)
    }

    #[tokio::test]
    async fn a_path_does_not_pass_through_a_hub_unless_allowed() {
        // From adam to eve: through dc-1 in two links, or around it in
        // three.
        let found = path(&office(), "adam", "eve", 4, false, BOUNDS)
            .await
            .unwrap();
        assert_eq!(names(&found), Some(vec!["adam", "ws-7", "files", "eve"]));
        assert_eq!(found.hubs, [("dc-1".to_owned(), 4)]);
        assert!(found.complete);
        // Each hop holds its links as they were seen, from who acted.
        let hops = found.hops.unwrap();
        assert_eq!(hops[0].links.len(), 2);
        assert_eq!(
            (hops[2].links[0].src.as_str(), hops[2].links[0].dst.as_str()),
            ("eve", "files")
        );

        let through = path(&office(), "adam", "eve", 4, true, BOUNDS)
            .await
            .unwrap();
        assert_eq!(names(&through), Some(vec!["adam", "dc-1", "eve"]));
        assert_eq!(through.hubs, []);
    }

    #[tokio::test]
    async fn a_path_ends_at_a_hub_that_is_asked_for() {
        let found = path(&office(), "bob", "dc-1", 4, false, BOUNDS)
            .await
            .unwrap();
        assert_eq!(names(&found), Some(vec!["bob", "dc-1"]));
        // And from it: bob is reached through the hub that was named.
        let found = path(&office(), "dc-1", "files", 4, false, BOUNDS)
            .await
            .unwrap();
        assert_eq!(names(&found).map(|names| names.len()), Some(3));
    }

    #[tokio::test]
    async fn a_path_is_within_the_links_asked_for_or_is_none() {
        let found = path(&office(), "adam", "eve", 2, false, BOUNDS)
            .await
            .unwrap();
        assert_eq!(found.hops, None);
        let one = path(&office(), "adam", "adam", 4, false, BOUNDS)
            .await
            .unwrap();
        assert_eq!(one.hops, Some(Vec::new()));
        let apart = Drawn(vec![("a", "ran", "b"), ("c", "ran", "d")]);
        let found = path(&apart, "a", "d", 4, false, BOUNDS).await.unwrap();
        assert_eq!((found.hops, found.complete), (None, true));
    }
}
