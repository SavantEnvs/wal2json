#!/usr/bin/env bash
#
# mayhem/test.sh — run wal2json's OWN regression suite (upstream sql/*.sql vs expected/*.out, the
# `make installcheck` list from the Makefile) against a throw-away PostgreSQL server.
#
# build.sh produced ./wal2json.so with normal flags; PostgreSQL is the pinned dependency in $PG_HOME.
# The server is initdb'd under $TMPDIR, listens only on a unix socket there, and loads the plugin
# from the source tree via dynamic_library_path. pg_regress diffs every query's output against the
# golden files, so a neutered plugin or server fails.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
: "${PG_HOME:=/opt/toolchains/deps/postgresql-17.7}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN="$PG_HOME/bin"
PG_REGRESS="$PG_HOME/lib/pgxs/src/test/regress/pg_regress"
# the REGRESS list from upstream's Makefile (PG 17: every test applies)
TESTS=$(sed -n '/^REGRESS = /,/[^\\]$/p' Makefile | sed 's/^REGRESS = //; s/\\//g' | tr -s ' \t\n' ' ')
NTESTS=$(echo $TESTS | wc -w)

if [ ! -f "$SRC/wal2json.so" ] || [ ! -x "$PG_REGRESS" ] || [ ! -x "$BIN/postgres" ]; then
  echo "test.sh: wal2json.so, pg_regress or postgres missing — run mayhem/build.sh first" >&2
  emit_ctrf pg_regress 0 "$NTESTS"; exit 1
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/wal2json-test.XXXXXX")
PGDATA="$WORK/data"
cleanup() { "$BIN/pg_ctl" -D "$PGDATA" -m immediate stop >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

started=0
if "$BIN/initdb" -D "$PGDATA" -E UTF8 --no-locale -A trust -U postgres >"$WORK/initdb.log" 2>&1; then
  cat >> "$PGDATA/postgresql.conf" <<CONF
listen_addresses = ''
unix_socket_directories = '$WORK'
port = 54329
wal_level = logical
max_replication_slots = 10
max_wal_senders = 4
fsync = off
dynamic_library_path = '\$libdir:$SRC'
CONF
  if "$BIN/pg_ctl" -D "$PGDATA" -l "$WORK/server.log" -w -t 60 start >/dev/null 2>&1; then
    started=1
  fi
fi
if [ "$started" -ne 1 ]; then
  echo "test.sh: could not start the test server" >&2
  cat "$WORK/initdb.log" "$WORK/server.log" 2>/dev/null | tail -20 >&2
  emit_ctrf pg_regress 0 "$NTESTS"; exit 1
fi

mkdir -p "$WORK/out"
# shellcheck disable=SC2086
"$PG_REGRESS" --inputdir="$SRC" --outputdir="$WORK/out" --bindir="$BIN" \
  --host="$WORK" --port=54329 --user=postgres --encoding=UTF8 \
  --dbname=contrib_regression $TESTS 2>&1 | tee "$WORK/regress.log"

passed=$(grep -cE '^ok [0-9]+ ' "$WORK/regress.log")
failed=$(grep -cE '^not ok [0-9]+ ' "$WORK/regress.log")
# a test that never reported (server died, pg_regress aborted) counts as failed
missing=$(( NTESTS - passed - failed )); [ "$missing" -gt 0 ] && failed=$(( failed + missing ))
[ -f "$WORK/out/regression.diffs" ] && head -100 "$WORK/out/regression.diffs"
emit_ctrf pg_regress "$passed" "$failed"
