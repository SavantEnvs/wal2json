/*
 * fuzz_wal2json.c — libFuzzer harness for the wal2json output plugin, hosted in-process.
 *
 * wal2json.c is compiled into this binary and linked against the PostgreSQL backend objects
 * (libpostgres_backend.a, everything but main.o). The harness drives the plugin exactly the way
 * the logical-decoding machinery (src/backend/replication/logical/logical.c) does: it obtains the
 * callbacks through the plugin's public entry point _PG_output_plugin_init(), then calls
 *
 *     startup_cb(options)  -> begin_cb -> message_cb(prefix, content) -> commit_cb -> shutdown_cb
 *
 * The options are what a client passes to pg_logical_slot_{get,peek}_changes() /
 * START_REPLICATION (untrusted), the message is what pg_logical_emit_message() logs (untrusted).
 *
 * Input format (all byte-oriented, no magic):
 *   byte 0          flags: bit0 = transactional message, bit1 = message present
 *   then lines      "key\nvalue\n" option pairs; a key with no following line gets a NULL value
 *                   (as `'include-xids', NULL` does in SQL); a line exactly "\x01" ends the options
 *   after "\x01\n"  "prefix\n" then the rest of the input is the message content (binary)
 *
 * Errors: the plugin reports bad options with ereport(ERROR). Like every backend caller of an output
 * plugin, the harness catches them with the backend's own PG_TRY/PG_CATCH, flushes the error state and
 * resets the per-input memory context — that is normal backend control flow, not a crash.
 *
 * Oracle beyond the sanitizers: wal2json's contract is that format-version 2 emits one complete JSON
 * object per write, so each such write is checked with PostgreSQL's own JSON parser (common/jsonapi);
 * invalid JSON aborts (cf. upstream fix 2e34ba0 "Fix invalid JSON ...").
 *
 * State: TopMemoryContext/ErrorContext and the GMT session timezone are created once and read-only
 * afterwards; every allocation of an input lives in a context deleted at the end of that input.
 */
#include "postgres.h"

#include "common/jsonapi.h"
#include "mb/pg_wchar.h"
#include "nodes/makefuncs.h"
#include "nodes/pg_list.h"
#include "nodes/value.h"
#include "pgtime.h"
#include "replication/logical.h"
#include "replication/output_plugin.h"
#include "replication/reorderbuffer.h"
#include "utils/memutils.h"
#include "utils/timestamp.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* main.c is not linked; these are the globals it would have defined. */
const char *progname = "fuzz_wal2json";

extern void _PG_output_plugin_init(OutputPluginCallbacks *cb);

static OutputPluginCallbacks cb;
static bool print_writes;		/* FUZZ_WAL2JSON_PRINT=1: echo every write to stderr (debugging) */

static void
fuzz_prepare_write(LogicalDecodingContext *ctx, XLogRecPtr lsn, TransactionId xid, bool last_write)
{
	resetStringInfo(ctx->out);
}

static void
fuzz_write(LogicalDecodingContext *ctx, XLogRecPtr lsn, TransactionId xid, bool last_write)
{
	StringInfo	out = ctx->out;

	if (print_writes)
		fprintf(stderr, "write: %.*s\n", out->len, out->data);
	if (out->len >= 10 && strncmp(out->data, "{\"action\":", 10) == 0)
	{
		JsonLexContext lex;
		JsonParseErrorType rc;

		makeJsonLexContextCstringLen(&lex, out->data, out->len, PG_UTF8, true);
		rc = pg_parse_json(&lex, &nullSemAction);
		if (rc != JSON_SUCCESS)
		{
			fprintf(stderr, "wal2json emitted invalid JSON (%d): %.*s\n", rc, out->len, out->data);
			abort();
		}
		freeJsonLexContext(&lex);
	}
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	MemoryContextInit();
	session_timezone = pg_tzset("GMT");
	log_timezone = session_timezone;
	SetDatabaseEncoding(PG_UTF8);
	_PG_output_plugin_init(&cb);
	print_writes = getenv("FUZZ_WAL2JSON_PRINT") != NULL;
	return 0;
}

/* next '\n'-terminated line of [*p, end); NULL at end of input */
static char *
next_line(const uint8_t **p, const uint8_t *end)
{
	const uint8_t *s = *p;
	const uint8_t *nl;

	if (s >= end)
		return NULL;
	nl = memchr(s, '\n', end - s);
	if (nl == NULL)
		nl = end;
	*p = (nl < end) ? nl + 1 : end;
	return pnstrdup((const char *) s, nl - s);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	MemoryContext input_cxt;
	MemoryContext decoding_cxt;
	const uint8_t *p = data, *end = data + size;
	uint8_t		flags;
	List	   *options = NIL;
	char	   *prefix = NULL;
	const char *content = NULL;
	Size		content_size = 0;

	if (size < 1)
		return -1;
	flags = *p++;

	input_cxt = AllocSetContextCreate(TopMemoryContext, "fuzz input", ALLOCSET_DEFAULT_SIZES);
	MemoryContextSwitchTo(input_cxt);

	for (;;)
	{
		char	   *key = next_line(&p, end);
		char	   *val;

		if (key == NULL || strcmp(key, "\x01") == 0)
			break;
		val = next_line(&p, end);
		options = lappend(options, makeDefElem(key, val ? (Node *) makeString(val) : NULL, -1));
	}
	if (flags & 2)
	{
		prefix = next_line(&p, end);
		if (prefix == NULL)
			prefix = pstrdup("");
		content = (const char *) p;
		content_size = end - p;
	}

	PG_TRY();
	{
		LogicalDecodingContext *ctx;
		OutputPluginOptions opt = {0};
		ReorderBufferTXN *txn;

		decoding_cxt = AllocSetContextCreate(input_cxt, "Logical decoding context", ALLOCSET_DEFAULT_SIZES);
		MemoryContextSwitchTo(decoding_cxt);

		ctx = palloc0(sizeof(LogicalDecodingContext));
		ctx->context = decoding_cxt;
		ctx->output_plugin_options = options;
		ctx->out = makeStringInfo();
		ctx->prepare_write = fuzz_prepare_write;
		ctx->write = fuzz_write;
		ctx->update_progress = NULL;
		ctx->accept_writes = true;
		ctx->write_xid = 742;
		ctx->write_location = 0x16B3748;

		txn = palloc0(sizeof(ReorderBufferTXN));
		txn->xid = 742;
		txn->first_lsn = 0x16B3700;
		txn->final_lsn = 0x16B3748;
		txn->end_lsn = 0x16B3778;
		txn->xact_time.commit_time = 0;
		txn->origin_id = 0;

		cb.startup_cb(ctx, &opt, false);

		if (flags & 2)
		{
			bool		transactional = (flags & 1) != 0;

			if (transactional)
				cb.begin_cb(ctx, txn);
			cb.message_cb(ctx, transactional ? txn : NULL, 0x16B3720, transactional,
						  prefix, content_size, content);
			if (transactional)
			{
				txn->nentries = 1;
				txn->nentries_mem = 1;
				cb.commit_cb(ctx, txn, 0x16B3748);
			}
		}
		else
		{
			/* an empty transaction (include-empty-transaction / write-in-chunks paths) */
			cb.begin_cb(ctx, txn);
			cb.commit_cb(ctx, txn, 0x16B3748);
		}

		if (cb.shutdown_cb)
			cb.shutdown_cb(ctx);
	}
	PG_CATCH();
	{
		/* ereport(ERROR) from the plugin: invalid option, the normal rejection path */
		MemoryContextSwitchTo(TopMemoryContext);
		FlushErrorState();
	}
	PG_END_TRY();

	MemoryContextSwitchTo(TopMemoryContext);
	MemoryContextDelete(input_cxt);
	return 0;
}
