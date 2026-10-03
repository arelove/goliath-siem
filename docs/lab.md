# A lab on a home network

Two or more Windows machines on one network: one runs the platform, and each
sends it its own Sysmon and Security logs. Nothing is opened to the internet.

The scripts here are a lab's, not an agent: they send a log in rounds, 30
seconds apart by default, and they are run by hand.

## What is exposed

| Port | Open to | Protection |
| --- | --- | --- |
| 8514, the receiver | The local subnet, on networks Windows marks private | HTTPS with the lab's certificate; a token for each source |
| 8080, the interface and API | The machine itself | A token |
| 8123, ClickHouse | The machine itself | A password |

Do not forward any of these ports on the router. A sender that holds a
source's token can write records to that source and do nothing else.

## The machine that runs the platform

It needs Docker Desktop and this repository.

1. Find its address on the network with `ipconfig`, such as `192.168.1.10`.
   Give it a fixed address in the router, since the certificate names it.
2. In PowerShell as an administrator, from the repository:

   ```powershell
   scripts\lab\setup.ps1 -Address 192.168.1.10
   ```

   This writes the tokens to `.env`, makes a certificate in `deploy\lab\tls`,
   and opens port 8514 to the local subnet. Neither place is committed.
3. Start the platform:

   ```powershell
   docker compose -f compose.yaml -f compose.lab.yaml up -d --build
   ```

4. Check that the receiver answers:

   ```powershell
   curl.exe --cacert deploy\lab\tls\receiver.crt --ssl-no-revoke https://192.168.1.10:8514/health
   ```

5. Open `http://127.0.0.1:8080` on this machine and enter the `API_TOKEN` of
   `.env`.

## Each machine that sends

A sender can be the machine that runs the platform.

1. Install [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
   with a configuration, such as
   [sysmon-modular](https://github.com/olafhartong/sysmon-modular):

   ```powershell
   Sysmon64.exe -accepteula -i sysmonconfig.xml
   ```

2. Download `evtx_dump` from the
   [evtx releases](https://github.com/omerbenamram/evtx/releases).
3. Copy three things from the platform's machine: `receiver.crt`,
   `scripts\lab\send-windows-logs.ps1`, and the value of `SYSMON_TOKEN` from
   `.env`, saved alone in a file such as `sysmon.token`. Carry the token on a
   USB drive or over the network share, not through a chat.
4. In PowerShell as an administrator:

   ```powershell
   .\send-windows-logs.ps1 -Receiver https://192.168.1.10:8514 `
       -Certificate receiver.crt -TokenFile sysmon.token -EvtxDump .\evtx_dump.exe
   ```

   The first run starts at the newest record. Add `-FromStart` to send the
   whole log.
5. For the Security log, run a second copy with `SECURITY_TOKEN`:

   ```powershell
   .\send-windows-logs.ps1 -Receiver https://192.168.1.10:8514 `
       -Certificate receiver.crt -TokenFile security.token -EvtxDump .\evtx_dump.exe `
       -Source windows-security -Channel Security
   ```

## Checking that events arrive

- The Sources tab of the interface shows each source, when it last sent, and
  whether records are rejected.
- On the platform's machine, `http://127.0.0.1:9464/metrics` counts what the
  receiver took and refused.
- A sender prints one line for each round that sent records, and a warning
  for a round that failed. A failed round is sent again in the next.

## If a sender is refused

| Sender reports | Cause |
| --- | --- |
| curl exit 7 or 28 | The port is not reachable: the address, the firewall rule, or a network Windows marks public |
| curl exit 60 | The certificate is not the receiver's, or the address is not the one it names |
| curl exit 22 | The receiver answered with an error: 401 for a wrong token, 404 for a source the configuration does not list |

## Removing the lab

```powershell
docker compose -f compose.yaml -f compose.lab.yaml down -v
Remove-NetFirewallRule -DisplayName 'Goliath lab receiver'
```

On each sender, stop the script and delete `C:\ProgramData\goliath-lab`,
which holds the bookmark and a copy of the token.
