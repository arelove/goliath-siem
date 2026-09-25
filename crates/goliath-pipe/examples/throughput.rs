//! Throughput of a disk topic, and how responsive the runtime stays.
//!
//! ```text
//! cargo run --release -p goliath-pipe --example throughput
//! ```
//!
//! One sender writes records in batches while one group reads and
//! acknowledges them, on a single-threaded runtime. A third task ticks every
//! millisecond: if file I/O blocks the runtime's thread, ticks are missed, and
//! every other task on that runtime, such as a network listener, stalls the
//! same way.

// Rates are printed as floats; precision lost past 2^52 does not matter.
#![allow(clippy::cast_precision_loss)]

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use goliath_pipe::{DiskOptions, DiskTopic, Receiver, Sender};

const RECORDS: usize = 200_000;
const SIZE: usize = 400;
const BATCH: usize = 1000;

fn main() -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(measure())
}

async fn measure() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let topic = DiskTopic::open(directory.path(), DiskOptions::default())?;
    let mut group = topic.subscribe("reader")?;
    let sender = topic.sender();

    let ticks = Arc::new(AtomicU64::new(0));
    let ticking = tokio::spawn({
        let ticks = Arc::clone(&ticks);
        async move {
            let mut interval = tokio::time::interval(Duration::from_millis(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                ticks.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    let start = Instant::now();
    let sending = tokio::spawn(async move {
        let record = vec![b'x'; SIZE];
        for _ in 0..RECORDS / BATCH {
            sender.send(vec![record.clone(); BATCH]).await?;
        }
        Ok::<_, goliath_pipe::PipeError>(())
    });
    let mut received = 0;
    while received < RECORDS {
        let batch = group.receive(BATCH, Duration::from_secs(10)).await?;
        let Some(last) = batch.last() else {
            return Err("stalled".into());
        };
        received += batch.len();
        group.acknowledge(last.offset).await?;
    }
    sending.await??;
    let elapsed = start.elapsed();
    ticking.abort();

    let seconds = elapsed.as_secs_f64();
    let (rate, megabytes) = (
        RECORDS as f64 / seconds,
        (RECORDS * SIZE) as f64 / seconds / 1e6,
    );
    println!("{RECORDS} records of {SIZE} bytes in batches of {BATCH}: {seconds:.2} s");
    println!("{rate:.0} records/s, {megabytes:.1} MB/s, fsync per batch");
    let ticked = ticks.load(Ordering::Relaxed);
    println!(
        "timer ticked {ticked} times of about {} in that time: the runtime was free {:.0}% of the time it should have been",
        elapsed.as_millis(),
        100.0 * ticked as f64 / elapsed.as_millis().max(1) as f64
    );
    Ok(())
}
