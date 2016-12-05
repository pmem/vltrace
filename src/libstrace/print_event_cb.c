/*
 * Copyright 2016, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in
 *	   the documentation and/or other materials provided with the
 *	   distribution.
 *
 *	 * Neither the name of the copyright holder nor the names of its
 *	   contributors may be used to endorse or promote products derived
 *	   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * print_event_cb.c -- print_event_cb() function
 */

#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */

#include <linux/ptrace.h>
#include <linux/limits.h>

#include "main.h"
#include "ebpf_syscalls.h"
#include "print_event_cb.h"

/*
 * XXX A bit of black magic to have some US <-> KS portability.
 * PLEASE do not add any other includes afters this comment.
 */
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

enum { TASK_COMM_LEN = 16 };

#include "trace.h"

static unsigned long long start_ts_nsec = 0;

const char *sc_num2str(const int64_t sc_num);
void fprint_i64(FILE *f, uint64_t x);
char b2hex(char b);

/*
 * Process event.
 *
 * Also it can be a good idea to use cb_cookie for args, for out or for static
 *	 variable above.
 */

/*
 * Print logs header.
 *
 * XXX A blank for human-readable strace-like logs
 */
static void
print_header_strace(int argc, char *argv[])
{
	if (args.timestamp)
		fprintf(out, "%-14s", "TIME(s)");

	fprintf(out, "%-7s %-6s %4s %3s %s\n",
		"SYSCALL", "PID_TID", "ARG1", "ERR", "PATH");

	(void) argc;
	(void) argv;
}

/*
 * Print syscall's log entry.
 *
 * XXX A blank for human-readable strace-like logs
 */
static void
print_event_strace(void *cb_cookie, void *data, int size)
{
	s64 res, err;
	struct ev_dt_t *const event = data;

	/* XXX Check size arg */
	(void) size;

	/* split return value into result and errno */
	res = (event->ret >= 0) ? event->ret : -1;
	err = (event->ret >= 0) ? 0 : -event->ret;

	if (start_ts_nsec == 0)
		start_ts_nsec = event->start_ts_nsec;

	if (args.failed && (event->ret >= 0))
		return;

	if (args.timestamp) {
		unsigned long long delta_nsec =
			event->finish_ts_nsec - start_ts_nsec;
		fprintf(out, "%-14.9f",
				(double)((double)delta_nsec / 1000000000.0));
	}

	if (0 <= event->sc_id)
		fprintf(out, "%-7s ", sc_num2str(event->sc_id));
	else
		fprintf(out, "%-7s ", event->sc_name + 4);

	fprintf(out, "%-6llu %4lld %3lld %s\n",
			event->pid_tid, res, err, event->fl_nm);

	(void) cb_cookie;
}

/* ** Hex logs ** */

/*
 * This function prints header for hexadecimal logs.
 */
static void
print_header_hex(int argc, char *argv[])
{
	for (int i = 0; i < argc; i++) {
		if (i + 1 != argc)
			fprintf(out, "%s%c", argv[i], args.out_sep_ch);
		else
			fprintf(out, "%s\n", argv[i]);
	}

	fprintf(out, "%s%c", "PID_TID", args.out_sep_ch);

	if (args.timestamp)
		fprintf(out, "%s%c", "TIME(nsec)", args.out_sep_ch);

	fprintf(out, "%s%c",  "ERR",	 args.out_sep_ch);
	fprintf(out, "%s%c",  "RES",	 args.out_sep_ch);
	fprintf(out, "%s%c", "SYSCALL", args.out_sep_ch);

	fprintf(out, "%s%c", "ARG1", args.out_sep_ch);
	fprintf(out, "%s%c", "ARG2", args.out_sep_ch);
	fprintf(out, "%s%c", "ARG3", args.out_sep_ch);
	fprintf(out, "%s%c", "ARG4", args.out_sep_ch);
	fprintf(out, "%s%c", "ARG5", args.out_sep_ch);
	fprintf(out, "%s%c", "ARG6", args.out_sep_ch);

	/* For COMM and like */
	fprintf(out, "%s", "AUX_DATA");

	fprintf(out, "\n");
}

/*
 * This function returnss character corresponding to hexadecimal digit.
 */
char
b2hex(char b)
{
	switch (b & 0xF) {
	case   0: return '0';
	case   1: return '1';
	case   2: return '2';
	case   3: return '3';
	case   4: return '4';
	case   5: return '5';
	case   6: return '6';
	case   7: return '7';
	case   8: return '8';
	case   9: return '9';
	case 0xA: return 'A';
	case 0xB: return 'B';
	case 0xC: return 'C';
	case 0xD: return 'D';
	case 0xE: return 'E';
	case 0xF: return 'F';
	}

	return '?';
}

/*
 * This function prints 64-bit integer in hexadecimal forn in stream.
 */
void
fprint_i64(FILE *f, uint64_t x)
{
	char str[2 * sizeof(x)];

	const char *const px = (const char *)&x;

	for (unsigned i = 0; i < sizeof(x); i++) {
		str[sizeof(str) - 1 - 2 * i - 0] = b2hex(px[i]);
		str[sizeof(str) - 1 - 2 * i - 1] = b2hex(px[i]>>4);
	}

	fwrite(str, sizeof(str), 1, f);
}

/*
 * This function returnss syscall's name by number
 */
const char *
sc_num2str(const int64_t sc_num)
{
	static char buf[32];

	if ((0 <= sc_num) && (SC_TBL_SIZE > sc_num)) {
		if (NULL == sc_tbl[sc_num].hlr_name)
			goto out;

		return sc_tbl[sc_num].hlr_name + 4 /* strlen("sys_") */;
	}

out:
	snprintf(buf, sizeof(buf), "sys_%ld", sc_num);

	return buf;
}

/*
 * This function prints syscall's logs entry in stream.
 *
 * WARNING
 *
 *    PLEASE don't use *printf() calls because it will slow down this
 *		 function too much.
 */
static void
print_event_hex(void *cb_cookie, void *data, int size)
{
	s64 res, err;
	struct ev_dt_t *const event = data;

	/* XXX Check size arg */
	(void) size;

	/* split return value into result and errno */
	res = (event->ret >= 0) ? event->ret : -1;
	err = (event->ret >= 0) ? 0 : -event->ret;

	if (start_ts_nsec == 0)
		start_ts_nsec = event->start_ts_nsec;

	if (args.failed && (event->ret >= 0))
		return;

	fprint_i64(out, event->pid_tid);
	fwrite(&args.out_sep_ch, sizeof(args.out_sep_ch), 1, out);

	if (args.timestamp) {
		unsigned long long delta_nsec =
			event->finish_ts_nsec - start_ts_nsec;

		fprint_i64(out, delta_nsec);
		fwrite(&args.out_sep_ch, sizeof(args.out_sep_ch), 1, out);
	}

	fprint_i64(out, (uint64_t)err);
	fwrite(&args.out_sep_ch, sizeof(args.out_sep_ch), 1, out);

	fprint_i64(out, (uint64_t)res);
	fwrite(&args.out_sep_ch, sizeof(args.out_sep_ch), 1, out);

	if (event->sc_id >= 0)
		fwrite(sc_num2str(event->sc_id),
				strlen(sc_num2str(event->sc_id)),
				1, out);
	else
		fwrite(event->sc_name + 4,
				strlen(event->sc_name + 4),
				1, out);
	fwrite(&args.out_sep_ch, sizeof(args.out_sep_ch), 1, out);

	/* "ARG1" */
	switch (event->sc_id) {
	case -2:
		fprint_i64(out, (uint64_t)event->arg_1);
		break;

	case -1:
		/*
		 * XXX Something unexpected happened. Ma be we should issue a
		 * warning or do something better
		 */
		break;

	default:
		if (EM_file == (EM_file & sc_tbl[event->sc_id].masks))
			fwrite(event->fl_nm, strlen(event->fl_nm), 1, out);
		else if (EM_desc == (EM_desc & sc_tbl[event->sc_id].masks))
			fprint_i64(out, (uint64_t)event->arg_1);
		else if (EM_fileat == (EM_fileat & sc_tbl[event->sc_id].masks))
			fprint_i64(out, (uint64_t)event->arg_1);
		else {
			/*
			 * XXX We don't have any idea about this syscall args.
			 *    May be we should expand our table with additional
			 *    syscall descriptions.
			 */
		}
		break;
	}
	fwrite(&args.out_sep_ch, sizeof(args.out_sep_ch), 1, out);

	/* "ARG2" */
	switch (event->sc_id) {
	case -2:
		fprint_i64(out, (uint64_t)event->arg_2);
		break;

	case -1:
		/*
		 * XXX Something unexpected happened. Ma be we should issue a
		 * warning or do something better
		 */
		break;

	default:
		if (EM_fileat == (EM_fileat & sc_tbl[event->sc_id].masks))
			fwrite(event->fl_nm, strlen(event->fl_nm), 1, out);
		break;
	}
	fwrite(&args.out_sep_ch, sizeof(args.out_sep_ch), 1, out);

	/* "ARG3" */
	switch (event->sc_id) {
	case -2:
		fprint_i64(out, (uint64_t)event->arg_3);
		break;

	case -1:
		/*
		 * XXX Something unexpected happened. Ma be we should issue a
		 * warning or do something better
		 */
		break;

	default:
		break;
	}
	fwrite(&args.out_sep_ch, sizeof(args.out_sep_ch), 1, out);

	/* "ARG4" */
	switch (event->sc_id) {
	case -2:
		fprint_i64(out, (uint64_t)event->arg_4);
		break;

	case -1:
		/*
		 * XXX Something unexpected happened. Ma be we should issue a
		 * warning or do something better
		 */
		break;

	default:
		break;
	}
	fwrite(&args.out_sep_ch, sizeof(args.out_sep_ch), 1, out);

	/* "ARG5" */
	switch (event->sc_id) {
	case -2:
		fprint_i64(out, (uint64_t)event->arg_5);
		break;

	case -1:
		/*
		 * XXX Something unexpected happened. Ma be we should issue a
		 * warning or do something better
		 */
		break;

	default:
		break;
	}
	fwrite(&args.out_sep_ch, sizeof(args.out_sep_ch), 1, out);

	/* "ARG6" */
	switch (event->sc_id) {
	case -2:
		fprint_i64(out, (uint64_t)event->arg_6);
		break;

	case -1:
		/*
		 * XXX Something unexpected happened. Ma be we should issue a
		 * warning or do something better
		 */
		break;

	default:
		break;
	}
	fwrite(&args.out_sep_ch, sizeof(args.out_sep_ch), 1, out);

	/* "AUX_DATA". For COMM and like. XXX */
	/* fwrite(event->comm, strlen(event->comm), 1, out); */
	fwrite("\n", 1, 1, out);

	(void) cb_cookie;
}

/* ** Binary logs ** */

/*
 * This function writes header in stream.
 */
static void
print_header_bin(int argc, char *argv[])
{
	size_t  argv_size = 0;

	struct ev_dt_t d = { .sc_id = -1 };

	const size_t d_size = sizeof(d);
	d.header.argc = argc;

	/*
	 * here we assume that our command line will not be longer
	 * than 255 bytes
	 */
	for (int i = 0; i < argc; i++) {
		strcpy(d.header.argv + argv_size, argv[i]);
		argv_size += strlen(argv[i]) + 1;
	}

	if (1 != fwrite(&d_size, sizeof(d_size), 1, out)) {
		/* ERROR */
		cont = false;
	}

	if (1 != fwrite(&d, sizeof(d), 1, out)) {
		/* ERROR */
		cont = false;
	}
}

/*
 * This function writes syscall's log entry in stream
 */
static void
print_event_bin(void *cb_cookie, void *data, int size)
{
	struct ev_dt_t *const event = data;

	/* XXX Check size arg */

	if (args.failed && (event->ret >= 0))
		return;

	if (1 != fwrite(data, (size_t)size, 1, out)) {
		/* ERROR */
		cont = false;
	}

	(void) cb_cookie;
}

/*
 * This function parsess log's type
 */
enum out_fmt
out_fmt_str2enum(const char *str)
{
	if (!strcasecmp("bin", str) || !strcasecmp("binary", str))
		return EOF_BIN;

	if (!strcasecmp("strace", str))
		return EOF_STRACE;

	if (!strcasecmp("hex", str))
		return EOF_HEX;

	return EOF_HEX;
}

perf_reader_raw_cb print_event_cb[EOF_QTY + 1] = {
	[EOF_HEX]	= print_event_hex,
	[EOF_BIN]	= print_event_bin,
	[EOF_STRACE] = print_event_strace,
};

print_header_t print_header[EOF_QTY + 1] = {
	[EOF_HEX]	= print_header_hex,
	[EOF_BIN]	= print_header_bin,
	[EOF_STRACE] = print_header_strace,
};
