# Prepares the machine that runs the lab: tokens in .env, a certificate for
# the receiver, and a firewall rule that opens the receiver's port to the
# local subnet only. Run once, as an administrator, from the repository.
#
#   scripts\lab\setup.ps1 -Address 192.168.1.10
#
# -Address is this machine's address on the home network, which senders
# connect to and the certificate names. Secrets are written to .env and
# deploy\lab\tls, both ignored by git, and never printed. See docs/lab.md.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ipaddress]$Address,
    [int]$Port = 8514,
    [switch]$SkipFirewall
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$envFile = Join-Path $root '.env'
$tls = Join-Path $root 'deploy\lab\tls'

function New-Secret([int]$Bytes) {
    $buffer = New-Object byte[] $Bytes
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $random.GetBytes($buffer)
    $random.Dispose()
    -join ($buffer | ForEach-Object { $_.ToString('x2') })
}

# Each secret is made once: a second run keeps what senders already hold.
if (-not (Test-Path $envFile)) {
    New-Item -ItemType File -Path $envFile | Out-Null
}
$present = Get-Content $envFile
foreach ($name in 'CLICKHOUSE_PASSWORD', 'API_TOKEN', 'SYSMON_TOKEN', 'SECURITY_TOKEN') {
    if (-not ($present | Where-Object { $_ -match "^$name=." })) {
        [System.IO.File]::AppendAllText($envFile, "$name=$(New-Secret 32)`n")
        Write-Host "$name written to .env"
    }
}

# A self-signed certificate that names the address, valid for a year. Made
# with openssl in a container, since Docker is here and openssl may not be.
$certificate = Join-Path $tls 'receiver.crt'
if (-not (Test-Path $certificate)) {
    New-Item -ItemType Directory -Force -Path $tls | Out-Null
    docker run --rm -v "${tls}:/out" alpine/openssl req -x509 -newkey rsa:2048 -nodes `
        -days 365 -subj "/CN=goliath-lab" -addext "subjectAltName=IP:$Address" `
        -keyout /out/receiver.key -out /out/receiver.crt
    if ($LASTEXITCODE -ne 0) {
        throw 'the certificate could not be made; is Docker running?'
    }
    Write-Host "Certificate for $Address written to deploy\lab\tls"
}

if (-not $SkipFirewall) {
    $rule = 'Goliath lab receiver'
    if (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $Port -Profile Private -RemoteAddress LocalSubnet | Out-Null
        Write-Host "Port $Port opened to the local subnet on private networks"
    }
}

Write-Host ''
Write-Host 'Start the lab:'
Write-Host '  docker compose -f compose.yaml -f compose.lab.yaml up -d --build'
Write-Host 'Give each sender deploy\lab\tls\receiver.crt and the token of its source from .env.'
