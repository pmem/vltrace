/*
 * Copyright 2016-2017, Intel Corporation
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
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */

#include <linux/ptrace.h>
#include <linux/limits.h>

#include "strace.ebpf.h"
#include "ebpf_syscalls.h"
#include "print_event_cb.h"

/*
 * XXX A bit of black magic to have some US <-> KS portability.
 *
 * PLEASE do not add any other includes after this comment.
 */
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

enum { TASK_COMM_LEN = 16 };
enum { LEN_SYS = 4 }; /* = strlen("SyS_") */

#include "ebpf/trace.h"

static unsigned long long start_ts_nsec = 0;

static inline const char *sc_num2str(const int64_t sc_num);
static inline void fprint_i64(FILE *f, uint64_t x);
static inline char b2hex(char b);

unsigned Arg_is_path[6] = {
	/* syscall has fs path as a first arg */
	EM_fs_path_1,
	/* syscall has fs path as second arg */
	EM_fs_path_2,
	/* syscall has fs path as third arg */
	EM_fs_path_3,
	/* syscall has fs path as fourth arg */
	EM_fs_path_4,
	/* syscall has fs path as fifth arg - for future syscalls */
	EM_fs_path_5,
	/* syscall has fs path as sixth arg - for future syscalls */
	EM_fs_path_6
};

/*
 * Process event.
 *
 * Also it can be a good idea to use cb_cookie for Args, for Out_lf or for
 *    static variable above.
 */

/*
 * print_header_strace -- print logs header in human-readable strace-like logs
 */
static int
print_header_strace(int argc, char *const argv[])
{
	(void) argc;
	(void) argv;

	if (Args.timestamp)
		fprintf(Out_lf, "%-14s", "TIME(s)");

	fprintf(Out_lf, "%-7s %-6s %4s %3s %s\n",
			"SYSCALL", "PID_TID", "ARG1", "ERR", "PATH");

	return 0;
}

/*
 * print_event_strace -- Print syscall's log entry.
 *    Single-line mode only.
 *
 * XXX A blank for human-readable strace-like logs
 */
static void
print_event_strace(void *cb_cookie, void *data, int size)
{
	s64 res = 0, err = 0;
	struct data_entry_t *const event = data;

	/* XXX Check size arg */
	(void) size;

	if (start_ts_nsec == 0)
		start_ts_nsec = event->start_ts_nsec;

	if (Args.failed /* && (event->ret >= 0) */)
		return;

	if (Args.timestamp) {
		unsigned long long delta_nsec =
			event->start_ts_nsec - start_ts_nsec;
		fprintf(Out_lf, "%-14.9f",
				(double)((double)delta_nsec / 1000000000.0));
	}

	fprintf(Out_lf, "%-7s ", sc_num2str(event->sc_id));

	if (0 == event->packet_type)
		/*
		 * XXX Check presence of aux_str by checking sc_id
		 *    and size arg
		 */
		fprintf(Out_lf, "%-6llu %4lld %3lld %s\n",
				event->pid_tid, res, err, event->aux_str);
	else
		fprintf(Out_lf, "%-6llu %4lld %3lld %s\n",
				event->pid_tid, res, err, event->str);

	(void) cb_cookie;
}

/* ** Hex logs ** */

/*
 * print_header_hex -- print header for hexadecimal logs
 */
static int
print_header_hex(int argc, char *const argv[])
{
	for (int i = 0; i < argc; i++) {
		if (i + 1 != argc)
			fprintf(Out_lf, "%s%c", argv[i],
					Args.out_lf_fld_sep_ch);
		else
			fprintf(Out_lf, "%s\n", argv[i]);
	}

	fprintf(Out_lf, "%s%c", "PID_TID", Args.out_lf_fld_sep_ch);

	if (Args.timestamp)
		fprintf(Out_lf, "%s%c", "TIME(nsec)", Args.out_lf_fld_sep_ch);

	fprintf(Out_lf, "%s%c",  "ERR",	 Args.out_lf_fld_sep_ch);
	fprintf(Out_lf, "%s%c",  "RES",	 Args.out_lf_fld_sep_ch);
	fprintf(Out_lf, "%s%c", "SYSCALL", Args.out_lf_fld_sep_ch);

	fprintf(Out_lf, "%s%c", "ARG1", Args.out_lf_fld_sep_ch);
	fprintf(Out_lf, "%s%c", "ARG2", Args.out_lf_fld_sep_ch);
	fprintf(Out_lf, "%s%c", "ARG3", Args.out_lf_fld_sep_ch);
	fprintf(Out_lf, "%s%c", "ARG4", Args.out_lf_fld_sep_ch);
	fprintf(Out_lf, "%s%c", "ARG5", Args.out_lf_fld_sep_ch);
	fprintf(Out_lf, "%s%c", "ARG6", Args.out_lf_fld_sep_ch);

	/* For COMM and like */
	fprintf(Out_lf, "%s", "AUX_DATA");

	fprintf(Out_lf, "\n");

	return 0;
}

/*
 * b2hex -- This function returns character corresponding to hexadecimal digit.
 */
static inline char
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
 * fprint_i64 -- This function prints 64-bit integer in hexadecimal form
 *     in stream.
 */
static inline void
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
 * sc_num2str -- This function returns syscall's name by number
 */
static inline const char *
sc_num2str(const int64_t sc_num)
{
	int res;
	static char buf[32];

	if ((0 <= sc_num) && (SC_TBL_SIZE > sc_num)) {
		if (NULL == Syscall_array[sc_num].handler_name)
			goto out;
		return Syscall_array[sc_num].handler_name + LEN_SYS;
	}

out:
	res = snprintf(buf, sizeof(buf), "sys_%ld", sc_num);

	assert(res > 0);

	return buf;
}

/*
 * fwrite_sc_name -- write syscall's name to stream
 */
static void
fwrite_sc_name(FILE *f, const s64 sc_id)
{
	assert(sc_id >= 0 && sc_id < SC_TBL_SIZE &&
		Syscall_array[sc_id].handler_name != NULL);

	fwrite(Syscall_array[sc_id].handler_name + LEN_SYS,
		Syscall_array[sc_id].name_length - LEN_SYS, 1, f);
}

/*
 * get_type_of_arg -- return argument's type code for syscall number
 */
static int
is_path(int argn, unsigned sc_num)
{
	if ((Syscall_array[sc_num].masks & Arg_is_path[argn]) ==
							Arg_is_path[argn])
		return 1;
	else
		return 0;
}

/*
 * fprint_path -- return argument's type code for syscall number
 */
static void
fprint_path(int path, FILE *f, struct data_entry_t *const event, int size)
{
	(void) size;

	switch (path) {
	case 0: /* print the first string */
		if (event->packet_type == 0) {
			fwrite(event->aux_str,
				strnlen(event->aux_str, NAME_MAX), 1, f);
		} else {
			/* this packet contains only single string */
			fwrite(event->str, strnlen(event->str, NAME_MAX), 1, f);
		}
		break;
	case 1: /* print the second string */
		if (event->packet_type == 0) {
			char *str = event->aux_str + (NAME_MAX / 2);
			size_t len = strnlen(str, NAME_MAX - (NAME_MAX / 2));
			fwrite(str, len, 1, f);
		} else {
			assert(event->packet_type == 0);
		}
		break;
	}

}

/*
 * fprint_arg_hex -- print argument in hex form
 */
static void
fprint_arg_hex(int argn, FILE *f, struct data_entry_t *const event, int size,
		int *path)
{
	switch (event->sc_id) {
	case -2:
		fprint_i64(f, (uint64_t)event->args[argn]);
		break;

	case -1:
		/*
		 * XXX Something unexpected happened. Maybe we should issue a
		 *    warning or do something better
		 */
		break;

	default:
		if (is_path(argn, (unsigned)event->sc_id)) {
			fprint_path((*path)++, f, event, size);
		} else {
			fprint_i64(f, (uint64_t)event->args[argn]);
		}
		break;
	}
}

/*
 * fwrite_out_lf_fld_sep -- write out logfile field separator for hex mode.
 */
static inline void
fwrite_out_lf_fld_sep(FILE *f)
{
	size_t res;

	res = fwrite(&Args.out_lf_fld_sep_ch, sizeof(Args.out_lf_fld_sep_ch),
			1, f);
	assert(1 == res);
}

static char *Str_entry; /* will be initialized by init_printing_events() */
static size_t Len_str_entry; /* will be initialized by init_printing_events() */

/*
 * init_printing_events -- initialize Str_entry and Len_str_entry
 */
void
init_printing_events(void)
{
	static char str[] = "_----------------_----------------_";

	str[0]  = Args.out_lf_fld_sep_ch;
	str[17] = Args.out_lf_fld_sep_ch;
	str[34] = Args.out_lf_fld_sep_ch;

	Str_entry = str;
	Len_str_entry = strlen(str);
}

/*
 * print_event_hex_entry -- print syscall's logs entry in stream
 */
static void
print_event_hex_entry(FILE *f, void *data, int size)
{
	struct data_entry_t *const event = data;
	int paths = 0;
	int nargs;

	/* XXX Check size arg */
	(void) size;

	if (event->sc_id >= 0 && event->sc_id < SC_TBL_SIZE) {
		nargs = Syscall_array[event->sc_id].args_qty;
	} else {
		nargs = 6;
	}

	if (start_ts_nsec == 0)
		start_ts_nsec = event->start_ts_nsec;

	if (Args.timestamp) {
		unsigned long long delta_nsec =
			event->start_ts_nsec - start_ts_nsec;

		fprint_i64(f, delta_nsec);
		fwrite_out_lf_fld_sep(f);
	}

	/* PID & TID */
	fprint_i64(f, event->pid_tid);

	/* "_----------------_----------------_" */
	fwrite(Str_entry, Len_str_entry, 1, f);

	/* syscall's name */
	fwrite_sc_name(f, event->sc_id);

	/* syscall's arguments */
	for (int i = 0; i < nargs; i++) {
		fwrite_out_lf_fld_sep(f);
		fprint_arg_hex(i, f, event, size, &paths);
	}

	/* "AUX_DATA". For COMM and like. XXX */
	/* fwrite(event->comm, strlen(event->comm), 1, f); */

	fwrite("\n", 1, 1, f);
}

/*
 * print_event_hex_exit -- This function prints syscall's logs entry in stream.
 *
 * WARNING
 *
 *    PLEASE don't use *printf() calls because it will slow down this
 *		 function too much.
 */
static void
print_event_hex_exit(FILE *f, void *data, int size)
{
	s64 res, err;
	struct data_exit_t *const event = data;

	/* XXX Check size arg */
	(void) size;

	/* split return value into result and errno */
	res = (event->ret >= 0) ? event->ret : -1;
	err = (event->ret >= 0) ? 0 : -event->ret;

	if (start_ts_nsec == 0)
		start_ts_nsec = event->finish_ts_nsec;

	if (Args.failed && (event->ret >= 0))
		return;

	if (Args.timestamp) {
		unsigned long long delta_nsec =
			event->finish_ts_nsec - start_ts_nsec;

		fprint_i64(f, delta_nsec);
		fwrite_out_lf_fld_sep(f);
	}

	fprint_i64(f, event->pid_tid);
	fwrite_out_lf_fld_sep(f);

	fprint_i64(f, (uint64_t)err);
	fwrite_out_lf_fld_sep(f);

	fprint_i64(f, (uint64_t)res);
	fwrite_out_lf_fld_sep(f);

	fwrite_sc_name(f, event->sc_id);

	fwrite("\n", 1, 1, f);
}

/*
 * print_event_hex_tp -- This function prints syscall's logs entry in stream.
 *
 * WARNING
 *
 *    PLEASE don't use *printf() calls because it will slow down this
 *		 function too much.
 */
static void
print_event_hex_tp(FILE *f, void *data, int size)
{
	s64 res, err;
	struct tp_s *const event = data;
	const char *str_sys_exit = "sys_exit ";
	const size_t len_sys_exit = 9; /* length of the string above */

	/* XXX Check size arg */
	(void) size;

	/* split return value into result and errno */
	res = (event->ret >= 0) ? event->ret : -1;
	err = (event->ret >= 0) ? 0 : -event->ret;

	if (start_ts_nsec == 0)
		start_ts_nsec = event->finish_ts_nsec;

	if (Args.timestamp) {
		unsigned long long delta_nsec =
			event->finish_ts_nsec - start_ts_nsec;

		fprint_i64(f, delta_nsec);
		fwrite_out_lf_fld_sep(f);
	}

	fprint_i64(f, event->pid_tid);
	fwrite_out_lf_fld_sep(f);

	fprint_i64(f, (uint64_t)err);
	fwrite_out_lf_fld_sep(f);

	fprint_i64(f, (uint64_t)res);
	fwrite_out_lf_fld_sep(f);

	if (event->id >= 0 && event->id < SC_TBL_SIZE) {
		fwrite(Syscall_names[event->id].name,
			Syscall_names[event->id].length, 1, f);
	} else {
		fwrite(str_sys_exit, len_sys_exit, 1, f);
		fprint_i64(f, (uint64_t)(event->id));
	}

	fwrite("\n", 1, 1, f);
}

/*
 * print_event_hex -- This function prints syscall's logs entry in stream.
 *
 * WARNING
 *
 *    PLEASE don't use *printf() calls because it will slow down this
 *		 function too much.
 */
static void
print_event_hex(FILE *f, void *data, int size)
{
	s64 *type = data;
	const char *str = "ERROR: Unknown type of event\n";

	switch (*type) {
	case E_SC_ENTRY:
		print_event_hex_entry(f, data, size);
		break;
	case E_SC_EXIT:
		print_event_hex_exit(f, data, size);
		break;
	case E_SC_TP:
		print_event_hex_tp(f, data, size);
		break;
	default:
		fwrite(str, strlen(str), 1, f);
		break;
	}
}

/*
 * print_event_hex_raw -- This function prints syscall's logs entry in stream.
 *
 * WARNING
 *
 *    PLEASE don't use *printf() calls because it will slow down this
 *		 function too much.
 */
static void
print_event_hex_raw(void *cb_cookie, void *data, int size)
{
	print_event_hex(Out_lf, data, size);

	(void) cb_cookie;
}

/*
 * print_event_hex_sl -- This function prints syscall's logs entry in stream.
 *    This logger should assemble multi-packet data in one line.
 *
 * XXX Finish implementation
 *
 * WARNING
 *
 *    PLEASE don't use *printf() calls because it will slow down this
 *		 function too much.
 */
static void
print_event_hex_sl(void *cb_cookie, void *data, int size)
{
	print_event_hex(Out_lf, data, size);

	(void) cb_cookie;
}

/* ** Binary logs ** */

/*
 * print_header_bin -- write header into stream
 */
static int
print_header_bin(int argc, char *const argv[])
{
#define MAX_LEN_STR 1024

	struct header_s {
		s64 argc;
		char argv[MAX_LEN_STR];
	} header;

	int data_size = 0;
	int next_size = 0;

	for (int i = 0; i < argc; i++) {
		next_size = strlen(argv[i]) + 1;
		if (data_size + next_size >= MAX_LEN_STR)
			return -1;
		strcpy(header.argv + data_size, argv[i]);
		data_size += next_size;
	}

	header.argc = argc;
	data_size += offsetof(struct header_s, argv);

	if (1 != fwrite(&data_size, sizeof(int), 1, Out_lf)) {
		return -1;
	}

	if (1 != fwrite(&header, data_size, 1, Out_lf)) {
		return -1;
	}

	return 0;
}

/*
 * print_event_bin -- write syscall's log entry into stream
 */
static void
print_event_bin(void *cb_cookie, void *data, int size)
{
	(void) cb_cookie;

	if (1 != fwrite(&size, sizeof(int), 1, Out_lf)) {
		OutputError = 1;
	}

	if (1 != fwrite(data, (size_t)size, 1, Out_lf)) {
		OutputError = 1;
	}
}

/*
 * out_fmt_str2enum -- This function parses log's type
 */
enum out_lf_fmt
out_fmt_str2enum(const char *str)
{
	if (!strcasecmp("bin", str) || !strcasecmp("binary", str))
		return EOF_BIN;

	if (!strcasecmp("strace", str))
		return EOF_STRACE;

	if (!strcasecmp("hex", str) || !strcasecmp("hex_raw", str))
		return EOF_HEX_RAW;

	if (!strcasecmp("hex_sl", str))
		return EOF_HEX_SL;

	return EOF_HEX_RAW;
}

perf_reader_raw_cb Print_event_cb[EOF_QTY + 1] = {
	[EOF_HEX_RAW]	= print_event_hex_raw,
	[EOF_HEX_SL]	= print_event_hex_sl,
	[EOF_BIN]	= print_event_bin,
	[EOF_STRACE]	= print_event_strace,
};

print_header_t Print_header[EOF_QTY + 1] = {
	[EOF_HEX_RAW]	= print_header_hex,
	[EOF_HEX_SL]	= print_header_hex,
	[EOF_BIN]	= print_header_bin,
	[EOF_STRACE]	= print_header_strace,
};
