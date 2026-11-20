#!/usr/bin/env bash
#
# mayhem/build.sh — build the wal2json fuzz harness and the plugin for the upstream regression suite.
#
# PostgreSQL (the host of this plugin) is a pinned, prebuilt dependency in $PG_HOME
# (/opt/toolchains/deps/postgresql-<ver>, see mayhem/Dockerfile). Re-runnable and offline.
#
#  1) fuzz_wal2json (+ -standalone): wal2json.c and the harness, compiled with $SANITIZER_FLAGS and
#     $DEBUG_FLAGS, linked against the backend objects (uninstrumented dependency).
#  2) wal2json.so with the project's NORMAL flags via upstream's PGXS Makefile, left in the source tree
#     (gitignored) where mayhem/test.sh points the test server's dynamic_library_path.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${PG_HOME:=/opt/toolchains/deps/postgresql-17.7}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
PG_CONFIG="$PG_HOME/bin/pg_config"
INC="-I$("$PG_CONFIG" --includedir-server)"
OUT="$SRC/mayhem/out"
mkdir -p "$OUT"

# LIBS the backend itself links with (pg_config --libs), minus the client-only ones.
PGLIBS="$("$PG_CONFIG" --libs | sed "s/-lpgcommon//; s/-lpgport//") -lm"
BACKEND="-Wl,--whole-archive $PG_HOME/lib/libpostgres_backend.a -Wl,--no-whole-archive \
 $PG_HOME/lib/libpgcommon_srv.a $PG_HOME/lib/libpgport_srv.a $PGLIBS"

# 1) sanitized fuzz build
CFLAGS_FUZZ="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 $INC -fno-strict-aliasing -fwrapv"
$CC $CFLAGS_FUZZ -fsanitize=fuzzer-no-link -c "$SRC/wal2json.c" -o "$OUT/wal2json.fuzz.o"
$CC $CFLAGS_FUZZ -fsanitize=fuzzer-no-link -c "$SRC/mayhem/fuzz_wal2json.c" -o "$OUT/fuzz_wal2json.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -rdynamic \
  "$OUT/fuzz_wal2json.o" "$OUT/wal2json.fuzz.o" "$OUT/lsan_off.o" $BACKEND -o "$OUT/fuzz_wal2json"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -rdynamic \
  "$OUT/standalone_main.o" "$OUT/fuzz_wal2json.o" "$OUT/wal2json.fuzz.o" "$OUT/lsan_off.o" $BACKEND \
  -o "$OUT/fuzz_wal2json-standalone"

# 2) the plugin itself, normal flags, for the regression suite (upstream PGXS Makefile)
env -u CFLAGS -u LDFLAGS make -C "$SRC" USE_PGXS=1 PG_CONFIG="$PG_CONFIG" \
  COPT="$COVERAGE_FLAGS" -j"$MAYHEM_JOBS"

# 3) fuzz_wal2json_sql (AFL file-input target): a single-user backend that decodes the input's changes
#    through an AFL+sanitizer build of wal2json.so, on a fresh copy of a template cluster.
AFL_OUT="$OUT/afl"
TEMPLATE="$OUT/pgdata-template"
mkdir -p "$AFL_OUT"
afl-clang-fast $SANITIZER_FLAGS $DEBUG_FLAGS -O1 $INC -fno-strict-aliasing -fwrapv -fPIC -shared \
  "$SRC/wal2json.c" -o "$AFL_OUT/wal2json.so"
afl-clang-fast $SANITIZER_FLAGS $DEBUG_FLAGS -O1 $INC -DTEMPLATE_DIR="\"$TEMPLATE\"" -rdynamic \
  "$SRC/mayhem/fuzz_wal2json_sql.c" "$OUT/lsan_off.o" $BACKEND \
  -Wl,--no-as-needed -L"$AFL_OUT" -l:wal2json.so -Wl,-rpath,"$AFL_OUT" -o "$OUT/fuzz_wal2json_sql"
# (wal2json.so is a DT_NEEDED of the target so it is mapped before AFL's forkserver starts; the
#  backend's later dlopen() of the same file by dynamic_library_path returns that same handle.)

# the template cluster (recreated on every run so a re-run starts from a pristine one)
rm -rf "$TEMPLATE"
"$PG_HOME/bin/initdb" -D "$TEMPLATE" -E UTF8 --no-locale -A trust -U postgres --wal-segsize=1 \
  --no-sync >/dev/null
cat >> "$TEMPLATE/postgresql.conf" <<CONF
wal_level = logical
max_replication_slots = 8
max_wal_senders = 0
fsync = off
synchronous_commit = on   # single-user mode has no walwriter: async commits are never flushed, so decoding would see nothing
full_page_writes = off
shared_buffers = 1MB
min_wal_size = 2MB
max_wal_size = 8MB
dynamic_shared_memory_type = mmap
dynamic_library_path = '\$libdir:$AFL_OUT'
log_min_messages = fatal
CONF
# The input runs as this non-superuser REPLICATION role (what wal2json's real clients are; the harness
# makes it the authenticated user), with what the upstream regression scripts need: tables/types/
# schemas and the replication-origin functions (filter-origins / include-origin).
"$PG_HOME/bin/postgres" --single -D "$TEMPLATE" postgres >/dev/null <<'SQL'
create role fuzz replication
grant create on database postgres to fuzz
grant create on schema public to fuzz
grant execute on function pg_replication_origin_advance(text, pg_lsn), pg_replication_origin_create(text), pg_replication_origin_drop(text), pg_replication_origin_oid(text), pg_replication_origin_progress(text, boolean), pg_replication_origin_session_is_setup(), pg_replication_origin_session_progress(boolean), pg_replication_origin_session_reset(), pg_replication_origin_session_setup(text), pg_replication_origin_xact_reset(), pg_replication_origin_xact_setup(pg_lsn, timestamp with time zone) to fuzz
SQL
chmod -R go+rX "$TEMPLATE"
