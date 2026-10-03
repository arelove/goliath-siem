# Sends a Windows event log channel to a Goliath receiver, as the `sysmon`
# and `windows-security` source definitions read it: exported with wevtutil,
# turned to JSON by evtx_dump, and posted over HTTPS. Run as an
# administrator on the machine whose log is sent. See docs/lab.md.
#
#   scripts\lab\send-windows-logs.ps1 -Receiver https://192.168.1.10:8514 `
#       -Certificate receiver.crt -TokenFile sysmon.token -EvtxDump evtx_dump.exe
#
# It sends what was logged since its last round, every -IntervalSeconds, and
# remembers the last record sent in -State. A round that fails is sent again
# in the next, so the receiver may take a record twice; it stores it once.
# The first run starts at the newest record unless -FromStart is given.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Receiver,
    # The receiver's certificate, deploy\lab\tls\receiver.crt of the lab.
    [Parameter(Mandatory = $true)]
    [string]$Certificate,
    # A file holding the token of the source, and nothing else.
    [Parameter(Mandatory = $true)]
    [string]$TokenFile,
    # evtx_dump, from https://github.com/omerbenamram/evtx/releases.
    [Parameter(Mandatory = $true)]
    [string]$EvtxDump,
    [string]$Source = 'sysmon',
    [string]$Channel = 'Microsoft-Windows-Sysmon/Operational',
    [int]$IntervalSeconds = 30,
    [string]$State = (Join-Path $env:ProgramData 'goliath-lab'),
    [switch]$FromStart,
    # Send one round and stop.
    [switch]$Once
)

$ErrorActionPreference = 'Stop'
# The receiver takes a body of 16 MiB at most.
$maxBody = 8MB

New-Item -ItemType Directory -Force -Path $State | Out-Null
$bookmark = Join-Path $State "$Source.bookmark"
$evtx = Join-Path $State "$Source.evtx"
$json = Join-Path $State "$Source.jsonl"
$body = Join-Path $State "$Source.body"
# curl reads the header from a file, so the token is in no command line.
$header = Join-Path $State "$Source.header"
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText(
    $header, "Authorization: Bearer $((Get-Content -Raw $TokenFile).Trim())", $utf8)
$url = "$($Receiver.TrimEnd('/'))/ingest/$Source"

function Send-Body {
    & curl.exe --silent --show-error --fail --max-time 60 --cacert $Certificate `
        --ssl-no-revoke -H "@$header" --data-binary "@$body" --output NUL $url
    if ($LASTEXITCODE -ne 0) {
        throw "the receiver did not take the records (curl exit $LASTEXITCODE)"
    }
}

function Send-Round {
    if (Test-Path $bookmark) {
        $last = [long](Get-Content $bookmark)
    } elseif ($FromStart) {
        $last = 0
    } else {
        $newest = Get-WinEvent -LogName $Channel -MaxEvents 1 -ErrorAction SilentlyContinue
        $last = if ($newest) { $newest.RecordId } else { 0 }
        Set-Content -Path $bookmark -Value $last
        Write-Host "Starting after record $last of $Channel"
        return
    }

    & wevtutil.exe epl $Channel $evtx "/q:*[System[EventRecordID>${last}]]" /ow:true
    if ($LASTEXITCODE -ne 0) {
        throw "wevtutil could not export $Channel"
    }
    & $EvtxDump -o jsonl --no-confirm-overwrite -f $json $evtx
    if ($LASTEXITCODE -ne 0) {
        throw 'evtx_dump could not read the export'
    }

    $sent = 0
    $size = 0
    $lines = New-Object System.Collections.Generic.List[string]
    $newest = $last
    foreach ($line in [System.IO.File]::ReadLines($json)) {
        if (-not $line) { continue }
        if ($size + $line.Length -gt $maxBody -and $lines.Count -gt 0) {
            [System.IO.File]::WriteAllLines($body, $lines, $utf8)
            Send-Body
            $sent += $lines.Count
            $lines.Clear()
            $size = 0
        }
        $lines.Add($line)
        $size += $line.Length + 1
        if ($line -match '"EventRecordID":\s*(\d+)') {
            $newest = [Math]::Max($newest, [long]$Matches[1])
        }
    }
    if ($lines.Count -gt 0) {
        [System.IO.File]::WriteAllLines($body, $lines, $utf8)
        Send-Body
        $sent += $lines.Count
    }
    # Moved only once every record of the round is taken.
    Set-Content -Path $bookmark -Value $newest
    if ($sent -gt 0) {
        Write-Host "$(Get-Date -Format s) sent $sent records of $Channel, up to $newest"
    }
}

while ($true) {
    try {
        Send-Round
    } catch {
        Write-Warning "$(Get-Date -Format s) $($_.Exception.Message); trying again"
    }
    if ($Once) { break }
    Start-Sleep -Seconds $IntervalSeconds
}
