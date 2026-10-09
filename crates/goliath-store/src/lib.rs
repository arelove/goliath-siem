//! Storage of normalized OCSF events in ClickHouse.
//!
//! Outcomes of [`goliath_normalize`] are collected into a [`Batch`] and
//! written by a [`Store`]: events to the `events` table, records that could
//! not become events to `dead_letters`, with their raw bytes. The schema is a
//! sequence of forward-only [migrations](MIGRATIONS) that the store applies
//! itself. The layout and its reasons are in
//! `docs/adr/0013-event-storage.md`.

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

mod batch;
mod error;
mod health;
mod migrate;
mod overview;
mod platform;
mod reread;
mod search;
mod store;
mod writer;

pub use batch::Batch;
pub use error::StoreError;
pub use health::{
    DEFAULT_SILENT_AFTER_MINUTES, DeadLetterHour, Health, SourceHour, Status, Watched, judge,
};
pub use migrate::{MIGRATIONS, Migration};
pub use overview::{Arrived, Bucket, Frequent, HostBucket, Overview};
pub use platform::{
    Condition, Held, Instance, Platform, Report, Reported, RoleHealth, Standing, judge_platform,
};
pub use reread::{Kept, Reading};
pub use search::{Found, Page, SearchLimits, Stored};
pub use store::Store;
pub use writer::{Limits, Writer};
