#!/usr/bin/env bash
# The platform with something in it, in one command:
#
#   scripts/demo.sh
#
# Starts the single-machine stack of compose.yaml, drops a day of Sysmon
# events from a fleet of 2,000 Windows machines into its inbox, waits until
# the API finds the intrusion hidden among them, and opens the search view on
# it. Needs Docker, bash, curl, and openssl.
#
# Creates .env with a random password and API token where it has none, never
# printing either; the interface asks for the token, the API_TOKEN line of
# .env. Stop with `docker compose down`, adding `--volumes` to delete the
# events.
set -euo pipefail
cd "$(dirname "$0")/.."

touch .env
if ! grep -q '^CLICKHOUSE_PASSWORD=.' .env; then
    printf 'CLICKHOUSE_PASSWORD=%s\n' "$(openssl rand -hex 16)" >> .env
fi
if ! grep -q '^API_TOKEN=.' .env; then
    printf 'API_TOKEN=%s\n' "$(openssl rand -hex 32)" >> .env
fi
# shellcheck disable=SC1091
source .env

# goliath runs as uid 65532 and moves collected files out of the inbox.
mkdir -p inbox/sysmon
chmod -R a+rwX inbox

echo "building and starting the platform"
docker compose --profile demo build
docker compose up -d --wait clickhouse
docker compose up -d goliath

api=http://127.0.0.1:8080
for _ in $(seq 1 60); do
    curl -sf "$api/api/v1/health" >/dev/null && break
    sleep 1
done

echo "writing a day of the fleet's events into the inbox"
started=$(date +%s)
docker compose run --rm recording

# The intrusion's launches on its host: six, when all of it is stored.
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
day_ago=$(date -u -d '-1 day' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || date -u -v-1d +%Y-%m-%dT%H:%M:%SZ)
search="{\"from\": \"$day_ago\", \"to\": \"$now\", \"classes\": [1007],
  \"filters\": [{\"path\": \"device.hostname\", \"op\": \"equals\", \"value\": \"WS-0042.corp.example\"},
                {\"path\": \"process.user.name\", \"op\": \"equals\", \"value\": \"corp\\\\user0042\"}]}"
found=0
for _ in $(seq 1 120); do
    found=$(curl -s "$api/api/v1/search" -H "Authorization: Bearer $API_TOKEN" \
        -H 'content-type: application/json' -d "$search" | grep -o '"at":' | wc -l || true)
    [[ "$found" -ge 6 ]] && break
    sleep 1
done
if [[ "$found" -lt 6 ]]; then
    echo "the intrusion is not searchable after two minutes; see docker compose logs goliath" >&2
    exit 1
fi
echo "stored and searchable $(($(date +%s) - started)) seconds after the recording started"

url="$api/?last=24h&f=device.hostname%7Cequals%7CWS-0042.corp.example"
cat <<EOF

The search view: $url
The token it asks for is the API_TOKEN line of .env.

Things to try:
  - Open the launch of powershell.exe with -enc, and follow its parent back
    to WINWORD.EXE and the mailed document.
  - Every class, destination hostname equals cdn-update.example.org: one
    machine of 2,000 reaching it, once on 443 and once on 4444.
  - Class Process Activity, command line contains q3.7z: the archive it packed.
EOF
case "$(uname -s)" in
    Darwin) open "$url" ;;
    Linux) xdg-open "$url" >/dev/null 2>&1 || true ;;
    MINGW* | MSYS* | CYGWIN*) powershell.exe -NoProfile -Command "Start-Process '$url'" ;;
esac
