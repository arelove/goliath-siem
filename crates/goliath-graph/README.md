# goliath-graph

The entity graph of the [Goliath](https://github.com/arelove/goliath-siem)
security platform: what an OCSF event shows of the things it names.

An event names an account, a machine, an address, a domain, a file, and each
source names them its own way. One person is `CORP\adam` in a Windows log,
`adam@corp.example` in a cloud's, and an object identifier in a directory.
This crate reads an event and says three things, without a lookup and
without deciding who is who
([ADR-0025](../../docs/adr/0025-entity-graph.md)):

- **Identifiers.** Each in the one form it is compared in, written as kind,
  form, and value: `user:sid:s-1-5-21-...`, `host:name:ws-7.corp.example`,
  `address:ip:10.20.4.17`.
- **Claims.** Two identifiers the event gave as one thing, since they were
  in one object: a sign in that names a SID and a name with its domain.
- **Links.** One thing seen to act on another: an account signed in to a
  machine, a machine connected to an address, a domain answered with one.

```rust
use goliath_graph::observe;
use serde_json::json;

let seen = observe(&json!({
    "class_uid": 3002, "category_uid": 3, "activity_id": 1,
    "user": { "name": "adam", "domain": "CORP", "uid": "S-1-5-21-1-2-3-1104" },
    "device": { "hostname": "dc-1.corp.example" },
}));

assert_eq!(seen.claims[0].one.to_string(), "user:sid:s-1-5-21-1-2-3-1104");
assert_eq!(seen.claims[0].other.to_string(), "user:name:corp\\adam");
assert_eq!(seen.links[0].kind.as_str(), "logged_on_to");
```

## Strength

An identifier is strong if it names one thing without doubt, and weak if it
does so only at times. Two strong identifiers in one claim are one entity;
a weak one joins nothing.

| Kind | Strong | Weak |
| --- | --- | --- |
| User | A SID of a domain or a directory; a product's or a directory's identifier; an email address; a name with its domain; an account of one host | A bare name; a name under a domain every machine has, such as `NT AUTHORITY`; a well known SID |
| Host | A product's identifier; a qualified name | A short name; a MAC |

An address, a domain, and a file's hash are their own value.

Some things an event writes are not identifiers at all, and each was found
on a source's real events:

- `S-1-0-0`, which Windows writes where there is no account;
- a number alone as a user's identifier, which is a POSIX identifier that
  every machine counts from the same start;
- `?`, `-`, and `(null)`, which sources write for a value they do not know.

## Accounts of one machine

A name that is bare, or under a domain every machine has, and has no strong
identifier beside it, is an account of the event's device:
`user:local:ws-7.corp.example\system`. The same name on another machine is
another account. This is what keeps `root` and `SYSTEM` from being one
account across a company.

## An address is not an identifier

A machine and an address in one object are a link, `held`, and never a
claim. The address is another machine's tomorrow, and an identifier that
changes hands would join both.

## Links

| Link | From | To | Read from |
| --- | --- | --- | --- |
| `logged_on_to` | User | Host | Authentication |
| `ran_on` | User | Host | Process activity |
| `ran` | Host | File | Process and module activity |
| `wrote` | Host | File | File system activity that creates or updates |
| `connected_to` | Host or address | Address | Any class of network activity |
| `resolved` | Host or address | Domain | DNS activity |
| `resolved_to` | Domain | Address | The answers of DNS activity |
| `held` | Host | Address | Any device or endpoint that names both |

A link is written under the strongest identifier the event gives each end.
A sensor that sees addresses alone gives links between addresses; which
machine held an address then is answered when the graph is read.

## Resolution

`resolve` decides which identifiers are one entity, from claims added up
over events and from what people said. It is a function of its evidence:
nothing seen is rewritten, so the answer is computed again whenever it is
asked for, and a wrong one is corrected by correcting its cause.

1. Two strong identifiers in one claim are one entity. Nothing else joins.
2. An identifier claimed with more than three strong identifiers of one
   form is shared and joins nothing: a mailbox that forty accounts list as
   their address.
3. A weak identifier joins nothing. It is an alias of each entity it was
   claimed with.
4. A person's word is last, from a file reviewed as rules are:

```yaml
name: identity
version: 2
decisions:
  - same: ["user:email:a.jones@corp.example", "user:email:a.smith@corp.example"]
    reason: Renamed, HR ticket 4411
  - different: ["user:email:helpdesk@corp.example", "user:sid:s-1-5-21-1-2-3-1107"]
    reason: The helpdesk mailbox is shared
```

`same` joins two identifiers no event shows together. `different` holds two
apart: claims are followed from the most seen to the least, and one that
would bring the two into one entity is not followed.

Every identifier in the answer says why it is there: the identifier it was
seen with, the rule that read the claim or the person's reason, how often,
and from when until when. An entity is named by its strongest identifier,
whatever the order of the evidence. An identifier that is in no entity of
more than one is an entity of its own, and is not in the answer.

## Tested on every source

`tests/sources/` holds, for each source definition the platform ships, the
claims and links its fixture events give, and the entities those claims
resolve to. A change to how events are read or resolved shows in review as a
change to those files.
