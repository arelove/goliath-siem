//! Fetching the publication of a feed over HTTP, into the file the detector
//! reads it from. Fetching and loading are apart: what was fetched is kept
//! on disk, so a restart needs no network, and a site without internet
//! access puts the same file there by other means.

use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

/// The longest a fetch may take, from connecting to the last byte.
const TIMEOUT: Duration = Duration::from_secs(120);
/// The largest publication taken. The largest feed shipped is a few
/// megabytes; a body beyond this is not a feed.
const MAX_BYTES: u64 = 1 << 30;

/// What a fetch found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Fetched {
    /// The publication has not changed since the one `etag` names.
    Unchanged,
    /// A publication, and the tag the server gave it, to ask next time
    /// whether it changed.
    Publication {
        bytes: Vec<u8>,
        etag: Option<String>,
    },
}

/// Checks that `url` is one a feed may be fetched from: HTTPS, or HTTP on
/// this host alone. A publication fetched in the clear from elsewhere could
/// be replaced on the way, with indicators removed or addresses of the
/// organization itself added.
pub(crate) fn check_url(url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        return Ok(());
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return Err(format!("`{url}` is not an https:// URL"));
    };
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    let host = match authority.strip_prefix('[') {
        Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
        None => authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host),
    };
    let loopback = host == "localhost"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if loopback {
        Ok(())
    } else {
        Err(format!(
            "`{url}` is fetched without TLS from another host; use https://"
        ))
    }
}

/// Fetches feeds, keeping connections between fetches.
pub(crate) struct Fetcher {
    agent: ureq::Agent,
}

impl Fetcher {
    pub(crate) fn new() -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .user_agent(concat!("goliath/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self { agent }
    }

    /// Fetches `url`, unless it is still the publication `etag` names.
    ///
    /// # Errors
    ///
    /// Returns why the publication could not be had: no connection, an
    /// answer other than 200 or 304, or a body beyond the limit.
    pub(crate) fn get(&self, url: &str, etag: Option<&str>) -> Result<Fetched, String> {
        let mut request = self.agent.get(url);
        if let Some(etag) = etag {
            request = request.header("If-None-Match", etag);
        }
        let mut response = request.call().map_err(|error| error.to_string())?;
        match response.status().as_u16() {
            304 => Ok(Fetched::Unchanged),
            200 => {
                let etag = response
                    .headers()
                    .get("etag")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let mut bytes = Vec::new();
                response
                    .body_mut()
                    .as_reader()
                    .take(MAX_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|error| error.to_string())?;
                if bytes.len() as u64 > MAX_BYTES {
                    return Err(format!("the publication is larger than {MAX_BYTES} bytes"));
                }
                Ok(Fetched::Publication { bytes, etag })
            }
            status => Err(format!("the server answered {status}")),
        }
    }
}

/// Writes `bytes` to `file` so that a reader sees the old file or the new,
/// never part of one: under another name, then renamed.
pub(crate) fn publish(file: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(directory) = file.parent() {
        std::fs::create_dir_all(directory)?;
    }
    let partial = file.with_extension("partial");
    std::fs::write(&partial, bytes)?;
    std::fs::rename(partial, file)
}

#[cfg(test)]
mod tests {
    use super::check_url;

    #[test]
    fn a_feed_is_fetched_over_tls_or_from_this_host() {
        for url in [
            "https://feeds.example.com/list.csv",
            "http://127.0.0.1:8080/list.csv",
            "http://localhost/list.csv",
            "http://[::1]:8080/list.csv",
        ] {
            assert_eq!(check_url(url), Ok(()), "{url}");
        }
        for url in [
            "http://feeds.example.com/list.csv",
            "http://203.0.113.7/list.csv",
            "http://localhost.example.com/list.csv",
            "ftp://feeds.example.com/list.csv",
            "feeds.example.com/list.csv",
        ] {
            assert!(check_url(url).is_err(), "{url}");
        }
    }
}
