#!/usr/bin/env bash
# Runs the platform from the working tree, with its interface, against the
# ClickHouse of compose.dev.yaml. Nothing is built in a container and no
# image is downloaded beyond the two that compose file names.
#
#   docker compose -f compose.dev.yaml up -d --wait
#   scripts/dev-run.sh
#
# Then open http://127.0.0.1:8080; on the loopback address the interface
# asks for no token. Drop Sysmon events into inbox/sysmon/. Stop with Ctrl-C.
#
# Another configuration can be named, such as deploy/phone.toml.
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
. scripts/dev-env.sh

if [ ! -f ui/dist/index.html ] || [ -n "$(find ui/src ui/index.html -newer ui/dist/index.html -print -quit)" ]; then
    echo "building the interface"
    (cd ui && pnpm install --frozen-lockfile && pnpm build)
fi
mkdir -p inbox/sysmon inbox/pcapdroid data/dev
exec cargo run --release -p goliath -- run --config "${1:-deploy/dev.toml}"
