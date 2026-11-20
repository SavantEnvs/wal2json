# syntax=docker/dockerfile:1.7
#
# Commit image for wal2json (a PostgreSQL logical-decoding output plugin).
#
# wal2json is a plugin: it only runs inside a PostgreSQL backend. PostgreSQL itself is therefore an
# external dependency, built once here from a pinned release tarball into
# /opt/toolchains/deps/postgresql-<ver>/ (uninstrumented, -g -gdwarf-3). It provides:
#   * bin/ + share/ + lib/ : a real server (postgres, initdb, pg_ctl, psql, pg_regress) for the
#                            upstream regression suite that mayhem/test.sh runs;
#   * include/server       : the headers wal2json compiles against (pg_config --includedir-server);
#   * lib/libpostgres_backend.a : every backend object except main/main.o, plus the _srv flavours of
#                            libpgcommon/libpgport, so the fuzz harness can host wal2json.c in-process.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile --build-arg COMMIT=$(git rev-parse HEAD) -t wal2json .
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

USER root
ARG PG_VER=17.7
ARG PG_SHA256=ef9e343302eccd33112f1b2f0247be493cb5768313adeb558b02de8797a2e9b5
RUN set -eux; d=/opt/toolchains/deps/postgresql-${PG_VER}; mkdir -p "$d/src" /tmp/pg-build; \
    curl -fsSL -o /tmp/pg.tar.bz2 https://ftp.postgresql.org/pub/source/v${PG_VER}/postgresql-${PG_VER}.tar.bz2; \
    echo "${PG_SHA256}  /tmp/pg.tar.bz2" | sha256sum -c -; \
    tar -xjf /tmp/pg.tar.bz2 --strip-components=1 -C "$d/src"; rm -f /tmp/pg.tar.bz2; \
    cd /tmp/pg-build; \
    "$d/src/configure" --prefix="$d" --without-icu --without-readline --without-zlib --without-zstd \
        --without-lz4 --without-openssl --without-ldap --without-gssapi \
        CC=clang CFLAGS="-O1 -g -gdwarf-3 -fno-omit-frame-pointer"; \
    make -j"$(nproc)"; \
    make -j"$(nproc)" install; \
    make -j"$(nproc)" -C src/test/regress install; \
    printf 'include Makefile\nprint-objs:\n\t@echo $(call expand_subsys,$(OBJS))\n' > /tmp/print-objs.mk; \
    objs=$(make -s -C src/backend -f /tmp/print-objs.mk print-objs | tr ' ' '\n' | grep '\.o$' | grep -v '^main/main\.o$'); \
    echo "$objs" | wc -l; \
    (cd src/backend && rm -f "$d/lib/libpostgres_backend.a" && ar crs "$d/lib/libpostgres_backend.a" $objs); \
    cp src/common/libpgcommon_srv.a src/port/libpgport_srv.a "$d/lib/"; \
    cd / && rm -rf /tmp/pg-build; chmod -R a+rX,go-w "$d"
ENV PG_HOME=/opt/toolchains/deps/postgresql-17.7

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
