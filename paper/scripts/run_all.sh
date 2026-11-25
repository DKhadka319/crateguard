#!/usr/bin/env bash
# Rebuild everything against a running Neo4j. Pass the same flags to every step, e.g.
#   ./scripts/run_all.sh --uri neo4j://localhost:7687 --user neo4j --password secret
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f data/raw/cratesio.json ] || python3 scripts/fetch_cratesio.py   # ~10 min, only if missing
python3 scripts/build_graph.py
python3 scripts/load_neo4j.py --wipe "$@"
python3 scripts/run_queries.py "$@"
python3 scripts/visualize.py "$@"
