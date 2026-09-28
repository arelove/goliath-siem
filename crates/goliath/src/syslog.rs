//! Syslog over TCP, into one source's raw topic.
//!
//! See `docs/adr/0018-collection.md`. A source that takes syslog has a port
//! of its own, since a syslog message names no source. Messages are framed
//! as RFC 6587 describes, by a length before each or by newlines, and
//! gathered into raw records of at most 1,000 messages or 250 milliseconds,
//! each message written with its length before it, so that the source's
//! definition reads them with `framing: syslog`.
//!
//! While a batch cannot be sent because the topic is full, the connection
//! is not read, so TCP's own flow control slows the sender. Messages read
//! but not yet sent are lost if the receiver crashes: at most one batch per
//! connection. A message over 64 KiB closes its connection, as does a
//! sender beyond the limit on open connections.

use std::net::SocketAddr;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use goliath_pipe::Sender;
use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::RunError;
use crate::metrics::{Metrics, Received};
use crate::tls::TlsListener;

/// Bytes a message may hold.
pub(crate) const MAX_MESSAGE: usize = 64 << 10;
/// Messages a raw record holds at most.
const BATCH: usize = 1000;
/// How long the first message of a batch waits for others.
const LINGER: Duration = Duration::from_millis(250);
/// Connections open at once on one listener.
const MAX_CONNECTIONS: usize = 1024;
/// Bytes asked for in one read.
const READ: usize = 64 << 10;

/// A source's syslog listener, bound and ready to serve.
pub(crate) struct Listener<S> {
    incoming: Incoming,
    shared: Arc<Shared<S>>,
}

struct Shared<S> {
    name: String,
    raw: S,
    metrics: Metrics,
}

enum Incoming {
    Plain(TcpListener),
    Tls(TlsListener),
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl Incoming {
    async fn accept(&mut self) -> (Stream, SocketAddr) {
        match self {
            Self::Plain(listener) => loop {
                match listener.accept().await {
                    Ok((stream, peer)) => return (Stream::Plain(stream), peer),
                    Err(error) => {
                        // Such as too many open files: wait rather than spin.
                        debug!(%error, "accepting a connection failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            },
            Self::Tls(listener) => {
                let (stream, peer) = listener.next().await;
                (Stream::Tls(Box::new(stream)), peer)
            }
        }
    }
}

impl<S: Sender + Send + Sync + 'static> Listener<S> {
    /// Binds `listen` for the source `name`, serving TLS if `tls` is given.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Io`] if the address cannot be bound.
    pub(crate) async fn bind(
        name: String,
        listen: SocketAddr,
        tls: Option<TlsAcceptor>,
        raw: S,
        metrics: Metrics,
    ) -> Result<Self, RunError> {
        let failed = |error: std::io::Error| {
            RunError::Io(format!(
                "syslog for `{name}` listening on {listen}: {error}"
            ))
        };
        let listener = TcpListener::bind(listen).await.map_err(failed)?;
        let incoming = match tls {
            Some(acceptor) => Incoming::Tls(TlsListener::new(listener, acceptor).map_err(failed)?),
            None => Incoming::Plain(listener),
        };
        Ok(Self {
            incoming,
            shared: Arc::new(Shared { name, raw, metrics }),
        })
    }

    /// The address it listens on.
    pub(crate) fn address(&self) -> Option<SocketAddr> {
        match &self.incoming {
            Incoming::Plain(listener) => listener.local_addr().ok(),
            Incoming::Tls(listener) => Some(listener.address()),
        }
    }

    /// Serves until `stop` is set, then sends what each connection holds.
    ///
    /// # Errors
    ///
    /// Never, today: a connection whose batch cannot be sent is closed, and
    /// its sender connects again.
    pub(crate) async fn serve(mut self, mut stop: watch::Receiver<bool>) -> Result<(), RunError> {
        let name = self.shared.name.clone();
        info!(source = %name, address = ?self.address(), "syslog listening");
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut connections = JoinSet::new();
        loop {
            let (stream, peer) = tokio::select! {
                () = stopped(&mut stop) => break,
                accepted = self.incoming.accept() => accepted,
                Some(ended) = connections.join_next() => {
                    closed(&name, ended);
                    continue;
                }
            };
            let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                self.shared.metrics.received(&name, Received::Refused, 0);
                warn!(source = %name, %peer, "too many syslog connections; closing this one");
                continue;
            };
            let (shared, stop) = (Arc::clone(&self.shared), stop.clone());
            match stream {
                Stream::Plain(stream) => {
                    connections.spawn(read(stream, peer, shared, stop, permit));
                }
                Stream::Tls(stream) => {
                    connections.spawn(read(stream, peer, shared, stop, permit));
                }
            }
        }
        while let Some(ended) = connections.join_next().await {
            closed(&name, ended);
        }
        Ok(())
    }
}

fn closed(name: &str, ended: Result<Result<(), RunError>, tokio::task::JoinError>) {
    match ended {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(source = %name, %error, "a syslog connection failed"),
        Err(error) => warn!(source = %name, %error, "a syslog connection panicked"),
    }
}

/// Waits until `stop` is set, or its sender is gone.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    while !*stop.borrow_and_update() {
        if stop.changed().await.is_err() {
            return;
        }
    }
}

/// Reads one connection until it ends or the receiver stops, sending its
/// messages in batches.
async fn read<R: AsyncRead + Unpin, S: Sender + Send + Sync>(
    mut stream: R,
    peer: SocketAddr,
    shared: Arc<Shared<S>>,
    mut stop: watch::Receiver<bool>,
    _permit: OwnedSemaphorePermit,
) -> Result<(), RunError> {
    let mut buffer: Vec<u8> = Vec::with_capacity(READ);
    let mut batch = Batch::default();
    let mut ended = false;
    loop {
        let mut offset = 0;
        loop {
            offset += buffer[offset..]
                .iter()
                .take_while(|&&byte| byte.is_ascii_whitespace() || byte == 0)
                .count();
            match frame(&buffer[offset..], ended) {
                Frame::Message(range, next) => {
                    batch.push(&buffer[offset + range.start..offset + range.end]);
                    offset += next;
                    if batch.count >= BATCH {
                        batch.send(&shared).await?;
                    }
                }
                Frame::Incomplete => break,
                Frame::TooLong => {
                    shared.metrics.received(&shared.name, Received::Refused, 0);
                    warn!(source = %shared.name, %peer, "a syslog message is over 64 KiB; closing the connection");
                    return batch.send(&shared).await;
                }
            }
        }
        buffer.drain(..offset);
        if ended {
            return batch.send(&shared).await;
        }
        let due = batch.first.map(|first| first + LINGER);
        buffer.reserve(READ);
        tokio::select! {
            read = stream.read_buf(&mut buffer) => match read {
                Ok(0) => ended = true,
                Ok(_) => {}
                Err(error) => {
                    debug!(source = %shared.name, %peer, %error, "reading a syslog connection failed");
                    ended = true;
                }
            },
            () = tokio::time::sleep_until(due.unwrap_or_else(Instant::now)), if due.is_some() => {
                batch.send(&shared).await?;
            }
            () = stopped(&mut stop) => ended = true,
        }
    }
}

/// Messages gathered for one raw record, each after its length.
#[derive(Default)]
struct Batch {
    bytes: Vec<u8>,
    count: usize,
    first: Option<Instant>,
}

impl Batch {
    fn push(&mut self, message: &[u8]) {
        self.bytes
            .extend_from_slice(format!("{} ", message.len()).as_bytes());
        self.bytes.extend_from_slice(message);
        self.bytes.push(b'\n');
        self.count += 1;
        self.first.get_or_insert_with(Instant::now);
    }

    /// Sends the batch as one raw record, waiting while the topic is full.
    async fn send<S: Sender>(&mut self, shared: &Shared<S>) -> Result<(), RunError> {
        if self.count == 0 {
            return Ok(());
        }
        let record = crate::raw::stamp(crate::raw::now(), &self.bytes);
        let started = Instant::now();
        let sent = shared.raw.send(vec![record]).await;
        shared.metrics.waited(started.elapsed());
        let bytes = self.bytes.len();
        self.bytes.clear();
        self.count = 0;
        self.first = None;
        match sent {
            Ok(()) => {
                shared
                    .metrics
                    .received(&shared.name, Received::Taken, bytes);
                Ok(())
            }
            Err(error) => {
                shared
                    .metrics
                    .received(&shared.name, Received::Failed, bytes);
                Err(error.into())
            }
        }
    }
}

/// What the start of a buffer holds.
#[derive(Debug, PartialEq, Eq)]
enum Frame {
    /// A message at this range, and where the next one starts.
    Message(Range<usize>, usize),
    /// Not a whole message yet.
    Incomplete,
    /// A message over [`MAX_MESSAGE`].
    TooLong,
}

/// Frames the message at the start of `bytes`, which starts with no
/// whitespace, by its length if it starts with one and by its line if not.
/// Once the connection has `ended`, what is left is a message.
fn frame(bytes: &[u8], ended: bool) -> Frame {
    if bytes.is_empty() {
        return Frame::Incomplete;
    }
    let digits = bytes
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits > 0 && digits < 6 && digits == bytes.len() && !ended {
        return Frame::Incomplete;
    }
    if digits > 0 && bytes.get(digits) == Some(&b' ') {
        let length: usize = std::str::from_utf8(&bytes[..digits])
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or(usize::MAX);
        if length > MAX_MESSAGE {
            return Frame::TooLong;
        }
        let start = digits + 1;
        return if bytes.len() >= start + length {
            Frame::Message(start..start + length, start + length)
        } else if ended {
            // Cut short: kept whole, count and all, so that the
            // normalizer shows it as a dead letter.
            Frame::Message(0..bytes.len(), bytes.len())
        } else {
            Frame::Incomplete
        };
    }
    match bytes.iter().position(|&byte| byte == b'\n') {
        Some(end) if end > MAX_MESSAGE => Frame::TooLong,
        Some(end) => {
            let message = if end > 0 && bytes[end - 1] == b'\r' {
                end - 1
            } else {
                end
            };
            Frame::Message(0..message, end + 1)
        }
        None if bytes.len() > MAX_MESSAGE => Frame::TooLong,
        None if ended => Frame::Message(0..bytes.len(), bytes.len()),
        None => Frame::Incomplete,
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use goliath_pipe::{MemoryTopic, Receiver};
    use tokio::io::AsyncWriteExt as _;

    use super::*;

    #[test]
    fn frames_by_length_or_by_line() {
        assert_eq!(frame(b"5 <13>a rest", false), Frame::Message(2..7, 7));
        assert_eq!(frame(b"5 <13>", false), Frame::Incomplete);
        assert_eq!(frame(b"12", false), Frame::Incomplete);
        assert_eq!(frame(b"<13>a\r\nnext", false), Frame::Message(0..5, 7));
        assert_eq!(frame(b"<13>a", false), Frame::Incomplete);
        assert_eq!(frame(b"<13>a", true), Frame::Message(0..5, 5));
        assert_eq!(frame(b"9 <13>", true), Frame::Message(0..6, 6));
        assert_eq!(frame(b"99999999 <13>", false), Frame::TooLong);
        assert_eq!(frame(&vec![b'x'; MAX_MESSAGE + 1], false), Frame::TooLong);
    }

    async fn listener(capacity: usize) -> (Listener<goliath_pipe::MemorySender>, MemoryTopic) {
        let topic = MemoryTopic::new(NonZeroUsize::new(capacity).unwrap());
        let listener = Listener::bind(
            "linux".to_owned(),
            SocketAddr::from(([127, 0, 0, 1], 0)),
            None,
            topic.sender(),
            Metrics::new(),
        )
        .await
        .unwrap();
        (listener, topic)
    }

    fn messages(payload: &[u8]) -> Vec<Vec<u8>> {
        let (received, mut bytes) = crate::raw::read(payload);
        assert!(received.is_some(), "stamped with when it was received");
        let mut found = Vec::new();
        while !bytes.is_empty() {
            let space = bytes.iter().position(|&byte| byte == b' ').unwrap();
            let length: usize = std::str::from_utf8(&bytes[..space])
                .unwrap()
                .parse()
                .unwrap();
            found.push(bytes[space + 1..space + 1 + length].to_vec());
            assert_eq!(bytes[space + 1 + length], b'\n');
            bytes = &bytes[space + 2 + length..];
        }
        found
    }

    #[tokio::test]
    async fn messages_of_either_framing_arrive_in_one_batch_each_with_its_length() {
        let (listener, topic) = listener(10).await;
        let mut reader = topic.subscribe("normalizer");
        let address = listener.address().unwrap();
        let (stop, stopped) = watch::channel(false);
        let serving = tokio::spawn(listener.serve(stopped));

        let mut sender = TcpStream::connect(address).await.unwrap();
        sender
            .write_all(b"<13>1 - - - - - - one\n22 <13>1 - - - - - - tw\no<13>three")
            .await
            .unwrap();
        sender.shutdown().await.unwrap();
        drop(sender);

        let delivered = reader.receive(10, Duration::from_secs(5)).await.unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(
            messages(&delivered[0].payload),
            [
                b"<13>1 - - - - - - one".to_vec(),
                b"<13>1 - - - - - - tw\no".to_vec(),
                b"<13>three".to_vec(),
            ]
        );
        stop.send(true).unwrap();
        serving.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_batch_is_sent_after_its_linger_while_the_connection_stays_open() {
        let (listener, topic) = listener(10).await;
        let mut reader = topic.subscribe("normalizer");
        let address = listener.address().unwrap();
        let (stop, stopped) = watch::channel(false);
        let serving = tokio::spawn(listener.serve(stopped));

        let mut sender = TcpStream::connect(address).await.unwrap();
        sender.write_all(b"<13>held open\n").await.unwrap();
        let delivered = reader.receive(10, Duration::from_secs(5)).await.unwrap();
        assert_eq!(messages(&delivered[0].payload), [b"<13>held open".to_vec()]);

        // A message cut short when the receiver stops is sent, not dropped.
        sender.write_all(b"<13>unfinished").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop.send(true).unwrap();
        serving.await.unwrap().unwrap();
        let delivered = reader.receive(10, Duration::from_secs(1)).await.unwrap();
        assert_eq!(
            messages(&delivered[0].payload),
            [b"<13>unfinished".to_vec()]
        );
    }

    #[tokio::test]
    async fn a_full_topic_stops_reading_until_it_has_room() {
        let (listener, topic) = listener(1).await;
        let mut reader = topic.subscribe("normalizer");
        let address = listener.address().unwrap();
        let (stop, stopped) = watch::channel(false);
        let serving = tokio::spawn(listener.serve(stopped));

        let mut sender = TcpStream::connect(address).await.unwrap();
        let mut stream = Vec::new();
        for index in 0..3 * BATCH {
            stream.extend_from_slice(format!("<13>message {index}\n").as_bytes());
        }
        // Written aside: the receiver stops reading while the topic is full.
        let writing = tokio::spawn(async move {
            sender.write_all(&stream).await.unwrap();
            sender.shutdown().await.unwrap();
        });

        let mut all = Vec::new();
        while all.len() < 3 * BATCH {
            let delivered = reader.receive(1, Duration::from_secs(5)).await.unwrap();
            assert_eq!(delivered.len(), 1, "a batch is waiting");
            reader.acknowledge(delivered[0].offset).await.unwrap();
            let batch = messages(&delivered[0].payload);
            assert!(batch.len() <= BATCH);
            all.extend(batch);
        }
        let expected: Vec<Vec<u8>> = (0..3 * BATCH)
            .map(|index| format!("<13>message {index}").into_bytes())
            .collect();
        assert_eq!(all, expected, "every message, once, in order");
        writing.await.unwrap();
        stop.send(true).unwrap();
        serving.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_message_over_the_limit_closes_its_connection() {
        let (listener, topic) = listener(10).await;
        let mut reader = topic.subscribe("normalizer");
        let address = listener.address().unwrap();
        let (stop, stopped) = watch::channel(false);
        let serving = tokio::spawn(listener.serve(stopped));

        let mut sender = TcpStream::connect(address).await.unwrap();
        sender.write_all(b"<13>before\n").await.unwrap();
        sender
            .write_all(format!("{} <13>", MAX_MESSAGE + 1).as_bytes())
            .await
            .unwrap();
        let mut rest = Vec::new();
        // Closed, whether the sender sees an end or a reset.
        let _ = tokio::time::timeout(Duration::from_secs(5), sender.read_to_end(&mut rest))
            .await
            .expect("the receiver closes the connection");
        assert!(rest.is_empty());
        let delivered = reader.receive(10, Duration::from_secs(1)).await.unwrap();
        assert_eq!(messages(&delivered[0].payload), [b"<13>before".to_vec()]);
        stop.send(true).unwrap();
        serving.await.unwrap().unwrap();
    }
}
