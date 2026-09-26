#!/usr/bin/env bash
# Brings a compose stack up, drops a Sysmon file into the inbox, waits for
# its events in ClickHouse, and finds them through the API and its interface.
# Used by CI; runs the same on a laptop.
#
#   scripts/compose-smoke.sh                           # every role in one container
#   scripts/compose-smoke.sh compose.distributed.yaml  # a container per role
#
# Creates .env with a random password and API token where it has none, never
# printing either, and leaves the stack
# running on success so it can be inspected; `docker compose down -v` removes
# it with its data.
set -euo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_FILE="${1:-compose.yaml}"

touch .env
if ! grep -q '^CLICKHOUSE_PASSWORD=.' .env; then
    printf 'CLICKHOUSE_PASSWORD=%s\n' "$(openssl rand -hex 16)" >> .env
fi
if ! grep -q '^API_TOKEN=.' .env; then
    printf 'API_TOKEN=%s\n' "$(openssl rand -hex 32)" >> .env
fi
# shellcheck disable=SC1091
source .env

# goliath runs as uid 65532 and moves collected files; a throwaway inbox is
# simply opened to it.
mkdir -p inbox/sysmon
chmod -R a+rwX inbox
# Build once, then start: two builds at once would share cargo's caches.
docker compose build
docker compose up -d --wait clickhouse
docker compose up -d

sample=crates/goliath-normalize/sources/sysmon/kinds.input.json
cp "$sample" inbox/sysmon/smoke.json.tmp
mv inbox/sysmon/smoke.json.tmp "inbox/sysmon/smoke-$(date +%s).json"

query() {
    docker compose exec -T clickhouse clickhouse-client \
        --user goliath --password "$CLICKHOUSE_PASSWORD" --query "$1" 2>/dev/null || echo 0
}

stored=no
for _ in $(seq 1 60); do
    launches=$(query "SELECT count() FROM goliath.events WHERE kind = 'process_creation'")
    if [[ "$launches" -ge 1 ]]; then
        echo "events stored:"
        query "SELECT kind, count() FROM goliath.events GROUP BY kind ORDER BY kind"
        stored=yes
        break
    fi
    sleep 1
done
if [[ "$stored" != yes ]]; then
    echo "no events after 60 seconds" >&2
    docker compose logs >&2
    exit 1
fi

# The same events through the API, with the token, and never without it.
api=http://127.0.0.1:8080
search='{"from": "2026-09-24T00:00:00Z", "to": "2026-09-25T00:00:00Z", "classes": [1007],
  "filters": [{"path": "process.cmd_line", "op": "contains", "value": "NOTEPAD"}]}'
for _ in $(seq 1 30); do
    curl -sf "$api/api/v1/health" >/dev/null && break
    sleep 1
done
unauthorized=$(curl -s -o /dev/null -w '%{http_code}' "$api/api/v1/search" \
    -H 'content-type: application/json' -d "$search")
if [[ "$unauthorized" != 401 ]]; then
    echo "a search without the token was answered $unauthorized, not 401" >&2
    exit 1
fi
found=$(curl -sf "$api/api/v1/search" -H "Authorization: Bearer $API_TOKEN" \
    -H 'content-type: application/json' -d "$search" | grep -o '"at":' | wc -l)
if [[ "$found" -lt 1 ]]; then
    echo "the API found no events" >&2
    docker compose logs >&2
    exit 1
fi
curl -sf "$api/" | grep -q '<title>Goliath</title>' || {
    echo "the interface is not served" >&2
    exit 1
}
echo "found through the API: $found; interface served at $api"
