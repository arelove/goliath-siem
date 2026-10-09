# An Android phone

What a phone talks to, read by the platform on your own machine: every
connection with the app that made it, searched like any other event and
matched against public feeds of addresses, domains, and URLs known to
serve malware.

Nothing about the phone leaves your machine. The feeds are downloaded and
looked up locally; no name or address the phone used is sent to anyone.

## What it can and cannot tell

- It tells which app connected where, when, and how much it sent, and
  whether any of those ends is in a feed of known bad ones.
- It does not look inside the phone: not at its files, its installed
  packages, or what an app does without the network. It is not an
  antivirus.
- A phone with no finding is a phone that talked to nothing the feeds
  know. Malware that uses an address no feed has listed is not found this
  way.
- A finding is a reason to look at the app named, not proof. Feeds list
  shared hosting and addresses that changed hands.

## On the phone

[PCAPdroid](https://github.com/emanuele-f/PCAPdroid) is free software that
captures the phone's own traffic through Android's VPN interface. It needs
no root, and reads no content of encrypted connections. The file it saves
as its traffic dump is a PCAP of packets, which is not what is read here:
the table of connections is.

1. Install PCAPdroid from F-Droid or Google Play.
2. Start a capture and use the phone as usual: an hour, or a day. Android
   allows one VPN at a time, so another VPN is off while it captures.
3. Stop the capture. In the Connections view, open the menu and export the
   connections as CSV.
4. Move the file to the machine that runs the platform, by cable or any
   way you trust.

## On the machine

It needs Docker Desktop, Rust, and this repository, as
[CONTRIBUTING.md](../CONTRIBUTING.md) describes for running the platform
from the working tree.

```sh
docker compose -f compose.dev.yaml up -d --wait
scripts/dev-run.sh deploy/phone.toml
```

In PowerShell `bash` is the one of WSL, which has no `cargo`. Name Git's:

```powershell
& "C:\Program Files\Gitinash.exe" scripts/dev-run.sh deploy/phone.toml
```

The two containers are the store and nothing else: the interface is served
by the second command, and answers once it says where the interface is.

- At its start the detector downloads three feeds of abuse.ch: ThreatFox,
  URLhaus, and Feodo Tracker, some tens of megabytes.
- Put each exported file into `inbox/pcapdroid/`. It is read within
  seconds, and may be deleted after.
- Open <http://127.0.0.1:8080>.

## What to look at

| Question | Where |
| --- | --- |
| Did anything match a feed? | Search, class Detection Finding. Each names the feed, the indicator, and the connection it was found in |
| Which apps talk most, and to where? | Search, source `pcapdroid`, grouped by `actor.app_name` or `dst_endpoint.hostname` |
| What does one app talk to? | Search with `actor.app_uid` set to its package, such as `com.android.chrome` |
| Which connections had no name? | Search with `app_name` set to `TCP` or `UDP`: an app that connects to a bare address is worth a look |

Events have the time of the connection, not of the import, so set the time
range to when the phone was captured.

## How a row is read

The definition is
[`pcapdroid.yaml`](../crates/goliath-normalize/sources/pcapdroid.yaml).
The name PCAPdroid shows as `Info` becomes the queried name of a DNS
connection, the host of an HTTP request, and the destination's name of a
TLS or QUIC connection. Every column is kept under `unmapped` by its own
name, so nothing the file held is lost.

If your export has rows that are refused, they are counted as dead letters
of the source with the reason. Please open an issue with the header line
of the file and one refused row, with addresses changed.
