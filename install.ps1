# Fresh Windows host or recreate: CA bundle, DoT cert, start DNS chain.
# Requires Docker Desktop (WSL2 backend recommended).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Require-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "Docker is not on PATH. Install Docker Desktop, then re-run."
    }
    docker info 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is installed but not running. Start Docker Desktop, then re-run."
    }
}

function Copy-CaBundle {
    $dest = Join-Path $Root "unbound\ca-certificates.crt"
    $candidates = @(
        "$env:ProgramFiles\Git\mingw64\ssl\certs\ca-bundle.crt",
        "$env:ProgramFiles(x86)\Git\mingw64\ssl\certs\ca-bundle.crt"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) {
            Copy-Item $p $dest -Force
            return
        }
    }
    Write-Host "Downloading Mozilla CA bundle..."
    Invoke-WebRequest -UseBasicParsing -Uri "https://curl.se/ca/cacert.pem" -OutFile $dest
}

function Find-OpenSsl {
    $cmd = Get-Command openssl -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in @(
        "$env:ProgramFiles\Git\usr\bin\openssl.exe",
        "$env:ProgramFiles(x86)\Git\usr\bin\openssl.exe"
    )) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function New-DotCert {
    $key = Join-Path $Root "unbound\tls.key"
    $pem = Join-Path $Root "unbound\tls.pem"
    if ((Test-Path $key) -and (Test-Path $pem)) { return }
    New-Item -ItemType Directory -Force -Path (Join-Path $Root "unbound") | Out-Null
    $openssl = Find-OpenSsl
    if ($openssl) {
        & $openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes `
            -keyout $key -out $pem -subj "/CN=pihole.lan" `
            -addext "subjectAltName=DNS:pihole.lan,DNS:pi.hole"
        return
    }
    Write-Host "No local openssl; generating cert with Docker..."
    docker run --rm -v "${Root}/unbound:/out" alpine:3.20 sh -c @"
apk add --no-cache openssl >/dev/null
openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
  -keyout /out/tls.key -out /out/tls.pem -subj '/CN=pihole.lan' \
  -addext 'subjectAltName=DNS:pihole.lan,DNS:pi.hole'
"@
}

Require-Docker

if (-not (Test-Path (Join-Path $Root ".env"))) {
    Copy-Item (Join-Path $Root ".env.example") (Join-Path $Root ".env")
    Write-Host "Wrote .env from .env.example — set LAN_IPV4 and passwords before relying on this."
}

New-Item -ItemType Directory -Force -Path (Join-Path $Root "etc-pihole") | Out-Null
Copy-CaBundle
New-DotCert

docker compose up -d --force-recreate dnscrypt unbound pihole
docker compose ps
Write-Host ""
Write-Host "Probe Unbound:"
docker exec unbound drill @127.0.0.1 dnssec.works
Write-Host ""
Write-Host "Admin UI: http://127.0.0.1/admin/"
Write-Host "Geo-lock (nftables) is Linux-only. On Windows, restrict port 53 with Windows Firewall to your LAN."
