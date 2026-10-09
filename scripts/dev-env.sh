# Points cargo's tests and the benchmark rig at the services of
# compose.dev.yaml. Source it, do not run it:
#
#   . scripts/dev-env.sh
#
# The password is read from .env and is never printed.

if [ ! -f .env ]; then
    echo "no .env here: cp .env.example .env, and set CLICKHOUSE_PASSWORD" >&2
    return 1 2>/dev/null || exit 1
fi
GOLIATH_CLICKHOUSE_PASSWORD="$(sed -n 's/^CLICKHOUSE_PASSWORD=//p' .env | tr -d '\r')"
if [ -z "$GOLIATH_CLICKHOUSE_PASSWORD" ]; then
    echo "CLICKHOUSE_PASSWORD is not set in .env" >&2
    return 1 2>/dev/null || exit 1
fi
export GOLIATH_CLICKHOUSE_PASSWORD
export GOLIATH_CLICKHOUSE_URL=http://127.0.0.1:8123
export GOLIATH_CLICKHOUSE_USER=goliath
export GOLIATH_KAFKA_BROKERS=127.0.0.1:9092
