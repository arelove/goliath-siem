#!/usr/bin/env bash
# Brings the compose stack up, drops a Sysmon file into the inbox, and waits
# for its events in ClickHouse. Used by CI; runs the same on a laptop.
#
#   scripts/compose-smoke.sh
#
# Creates .env with a random password if there is none, and leaves the stack
# running on success so it can be inspected; `docker compose down -v` removes
# it with its data.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
    printf 'CLICKHOUSE_PASSWORD=%s\n' "$(openssl rand -hex 16)" > .env
fi
# shellcheck disable=SC1091
source .env

# goliath runs as uid 65532 and moves collected files; a throwaway inbox is
# simply opened to it.
mkdir -p inbox/sysmon
chmod -R a+rwX inbox
# Build once, then start: two builds at once would share cargo's caches.
docker compose build goliath
docker compose up -d --wait clickhouse
docker compose up -d goliath

sample=crates/goliath-normalize/sources/sysmon/kinds.input.json
cp "$sample" inbox/sysmon/smoke.json.tmp
mv inbox/sysmon/smoke.json.tmp "inbox/sysmon/smoke-$(date +%s).json"

query() {
    docker compose exec -T clickhouse clickhouse-client \
        --user goliath --password "$CLICKHOUSE_PASSWORD" --query "$1" 2>/dev/null || echo 0
}

for _ in $(seq 1 60); do
    launches=$(query "SELECT count() FROM goliath.events WHERE kind = 'process_creation'")
    if [[ "$launches" -ge 1 ]]; then
        echo "events stored:"
        query "SELECT kind, count() FROM goliath.events GROUP BY kind ORDER BY kind"
        exit 0
    fi
    sleep 1
done

echo "no events after 60 seconds" >&2
docker compose logs goliath >&2
exit 1
