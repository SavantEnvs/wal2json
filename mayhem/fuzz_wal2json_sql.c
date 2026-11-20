/*
 * fuzz_wal2json_sql.c — file-input (AFL) target: real logical decoding through wal2json.
 *
 * Usage: fuzz_wal2json_sql <input.sql>
 *
 * This binary is a PostgreSQL backend (all backend objects but main.o are linked in) whose main()
 * starts a single-user backend — exactly what `postgres --single` does — on a FRESH copy of a
 * template cluster (initdb'd by mayhem/build.sh, wal_level=logical), and feeds it this script on
 * stdin, one statement per line (single-user mode's own syntax):
 *
 *     select pg_create_logical_replication_slot('fuzz', 'wal2json');
 *     <the input file: DDL/DML/pg_logical_emit_message()/... with untrusted names and values,
 *      and its own pg_logical_slot_*_changes('fuzz', ..., <options>) calls>
 *     select pg_logical_slot_peek_changes('fuzz', NULL, NULL, <format-version 1, all include-* on>);
 *     select pg_logical_slot_get_changes('fuzz', NULL, NULL, <format-version 2, all include-* on>);
 *
 * The output plugin is loaded by name from dynamic_library_path, which points at the AFL+ASan+UBSan
 * build of wal2json.so in mayhem/out/afl/. So every catalog name, type name, tuple value, TOAST datum
 * and message reaches the plugin's change/message/truncate callbacks the way a real server delivers
 * them. An ERROR in a statement just returns to the single-user prompt; a sanitizer report or signal
 * is a crash.
 *
 * State: each execution starts from a pristine copy of the template, so a result depends only on its
 * input. The copy is $TMPDIR/w2jsql.<pid>.XXXXXX; it is removed at exit, and a run killed before that
 * (timeout SIGKILL, sanitizer abort, PANIC) leaves it behind, so every run first removes the copies
 * whose owning pid is gone, together with the SysV shared-memory header segment that backend left
 * (its id is in the copy's postmaster.pid).
 *
 * Privileges: the input never runs as a superuser. wal2json's real clients are REPLICATION roles,
 * so the template has a non-superuser role "fuzz" (REPLICATION, CREATE on the database and on schema
 * public, EXECUTE on the replication-origin functions; see mayhem/build.sh). Single-user mode always
 * authenticates as the bootstrap superuser, so before the first statement is analyzed a
 * post_parse_analyze_hook makes "fuzz" the AUTHENTICATED user (InitializeSessionUserId, what a
 * normal backend does at login). From then on SET SESSION AUTHORIZATION / RESET / DISCARD ALL cannot
 * get back to a superuser, and superuser-only capabilities (COPY TO/FROM a file or PROGRAM,
 * lo_export, ALTER SYSTEM, LOAD, C functions, ...) are refused like for any real client.
 */
#include "postgres.h"

#include "miscadmin.h"
#include "parser/analyze.h"
#include "utils/acl.h"
#include "tcop/tcopprot.h"
#include "utils/memutils.h"
#include "utils/pg_locale.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/shm.h>
#include <unistd.h>

const char *progname = "fuzz_wal2json_sql";

#ifndef TEMPLATE_DIR
#error "TEMPLATE_DIR must point at the template cluster built by mayhem/build.sh"
#endif

static char workdir[PATH_MAX];

static void
remove_workdir(void)
{
	char		cmd[PATH_MAX + 32];

	if (workdir[0] == '\0')
		return;
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", workdir);
	if (system(cmd) != 0)
		fprintf(stderr, "could not remove %s\n", workdir);
}

/*
 * Remove the temp clusters of earlier runs that were killed before their atexit hook ran: a
 * w2jsql.<pid>.* directory whose pid no longer exists. Before the directory goes, the SysV
 * shared-memory segment its backend created (line 7 of postmaster.pid: "<key> <shmid>") is removed
 * if nothing is attached to it.
 */
static void
remove_stale_workdirs(const char *tmp)
{
	DIR		   *d = opendir(tmp);
	struct dirent *e;

	if (d == NULL)
		return;
	while ((e = readdir(d)) != NULL)
	{
		long		pid;
		char		path[PATH_MAX];
		char		cmd[PATH_MAX + 32];
		FILE	   *f;

		if (strncmp(e->d_name, "w2jsql.", 7) != 0 || sscanf(e->d_name + 7, "%ld.", &pid) != 1 ||
			pid <= 0 || pid == (long) getpid() || kill((pid_t) pid, 0) == 0 || errno != ESRCH)
			continue;
		snprintf(path, sizeof(path), "%s/%s/data/postmaster.pid", tmp, e->d_name);
		if ((f = fopen(path, "r")) != NULL)
		{
			char		line[PATH_MAX + 64];
			unsigned long key, shmid;
			int			i;

			for (i = 1; fgets(line, sizeof(line), f) != NULL; i++)
			{
				struct shmid_ds ds;

				if (i == 7 && sscanf(line, "%lu %lu", &key, &shmid) == 2 &&
					shmctl((int) shmid, IPC_STAT, &ds) == 0 && ds.shm_nattch == 0)
					shmctl((int) shmid, IPC_RMID, NULL);
			}
			fclose(f);
		}
		snprintf(cmd, sizeof(cmd), "rm -rf '%s/%s'", tmp, e->d_name);
		if (system(cmd) != 0)
			fprintf(stderr, "could not remove stale %s/%s\n", tmp, e->d_name);
	}
	closedir(d);
}

/*
 * Drop the superuser before the first statement: make the template's non-superuser REPLICATION
 * role "fuzz" the authenticated and session user. Runs in the transaction of the preamble's first
 * statement (a constant SELECT that cannot fail, so the session_authorization change commits).
 */
static post_parse_analyze_hook_type prev_post_parse_analyze_hook;
static bool privileges_dropped = false;

static void
drop_superuser(ParseState *pstate, Query *query, JumbleState *jstate)
{
	if (!privileges_dropped)
	{
		Oid			fuzz = get_role_oid("fuzz", true);

		if (!OidIsValid(fuzz))
		{
			fprintf(stderr, "template cluster has no role \"fuzz\"; rebuild it with mayhem/build.sh\n");
			abort();
		}
		InitializeSessionUserId(NULL, fuzz, false);
		privileges_dropped = true;
		if (superuser() || superuser_arg(GetAuthenticatedUserId()))
		{
			fprintf(stderr, "could not drop the superuser\n");
			abort();
		}
	}
	if (prev_post_parse_analyze_hook)
		prev_post_parse_analyze_hook(pstate, query, jstate);
}

static const char *preamble =
	"select 'running the input as role fuzz';\n"
	"select pg_create_logical_replication_slot('fuzz', 'wal2json');\n";

static const char *epilogue =
	"\n"
	"select data from pg_logical_slot_peek_changes('fuzz', NULL, NULL, 'format-version', '1', "
	"'include-xids', '1', 'include-timestamp', '1', 'include-lsn', '1', 'include-origin', '1', "
	"'include-pk', '1', 'include-type-oids', '1', 'include-typmod', '1', 'include-domain-data-type', '1', "
	"'include-column-positions', '1', 'include-not-null', '1', 'include-default', '1', "
	"'numeric-data-types-as-string', '1', 'pretty-print', '1', 'actions', 'insert,update,delete,truncate');\n"
	"select data from pg_logical_slot_get_changes('fuzz', NULL, NULL, 'format-version', '2', "
	"'include-xids', '1', 'include-timestamp', '1', 'include-lsn', '1', 'include-origin', '1', "
	"'include-pk', '1', 'include-type-oids', '1', 'include-typmod', '1', 'include-domain-data-type', '1', "
	"'include-column-positions', '1', 'include-not-null', '1', 'include-default', '1', "
	"'numeric-data-types-as-string', '1', 'include-transaction', '1');\n";

int
main(int argc, char **argv)
{
	const char *tmp = getenv("TMPDIR");
	char		cmd[2 * PATH_MAX + 64];
	char		datadir[PATH_MAX];
	char		script[PATH_MAX];
	char		outlog[PATH_MAX];
	FILE	   *in, *out;
	char		buf[65536];
	size_t		n;
	char	   *pgargv[16];
	int			pgargc = 0;

	if (argc != 2)
	{
		fprintf(stderr, "usage: %s <input.sql>\n", argv[0]);
		return 2;
	}

	/* fresh copy of the pristine template cluster */
	if (!(tmp && *tmp))
		tmp = "/tmp";
	remove_stale_workdirs(tmp);
	snprintf(workdir, sizeof(workdir), "%s/w2jsql.%ld.XXXXXX", tmp, (long) getpid());
	if (mkdtemp(workdir) == NULL)
	{
		perror("mkdtemp");
		return 2;
	}
	atexit(remove_workdir);
	snprintf(datadir, sizeof(datadir), "%s/data", workdir);
	/* the template is world-readable (any uid may run this); postgres wants its datadir 0700 */
	snprintf(cmd, sizeof(cmd), "cp -R '%s' '%s' && chmod -R go-rwx '%s'", TEMPLATE_DIR, datadir, datadir);
	if (system(cmd) != 0)
	{
		fprintf(stderr, "could not copy the template cluster\n");
		return 2;
	}

	/* stdin = preamble + input + epilogue */
	snprintf(script, sizeof(script), "%s/script.sql", workdir);
	if ((in = fopen(argv[1], "rb")) == NULL || (out = fopen(script, "wb")) == NULL)
	{
		perror("open");
		return 2;
	}
	fputs(preamble, out);
	while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
		fwrite(buf, 1, n, out);
	fputs(epilogue, out);
	fclose(in);
	fclose(out);
	/* the backend's query output goes to a scratch file in the temp dir, unless
	 * FUZZ_WAL2JSON_SQL_STDOUT=1 keeps it on stdout (debugging) */
	snprintf(outlog, sizeof(outlog), "%s/stdout.log", workdir);
	if (freopen(script, "rb", stdin) == NULL ||
		(getenv("FUZZ_WAL2JSON_SQL_STDOUT") == NULL && freopen(outlog, "w", stdout) == NULL))
	{
		perror("freopen");
		return 2;
	}

	/* what src/backend/main/main.c does before dispatching to single-user mode */
	progname = get_progname(argv[0]);
	MyProcPid = getpid();
	MemoryContextInit();
	set_pglocale_pgservice(argv[0], PG_TEXTDOMAIN("postgres"));
	pg_perm_setlocale(LC_COLLATE, "C");
	pg_perm_setlocale(LC_CTYPE, "C");
	pg_perm_setlocale(LC_MESSAGES, "C");
	pg_perm_setlocale(LC_MONETARY, "C");
	pg_perm_setlocale(LC_NUMERIC, "C");
	pg_perm_setlocale(LC_TIME, "C");
	unsetenv("LC_ALL");

	pgargv[pgargc++] = argv[0];
	pgargv[pgargc++] = "--single";
	pgargv[pgargc++] = "-D";
	pgargv[pgargc++] = datadir;
	pgargv[pgargc++] = "postgres";
	pgargv[pgargc] = NULL;

	prev_post_parse_analyze_hook = post_parse_analyze_hook;
	post_parse_analyze_hook = drop_superuser;

	PostgresSingleUserMain(pgargc, pgargv, "postgres");	/* exits via proc_exit() */
	return 0;
}
