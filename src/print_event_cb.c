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

#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "strace.ebpf.h"
#include "ebpf_syscalls.h"
#include "print_event_cb.h"
#include "utils.h"

#include "ebpf/trace.h"

static char *Str_entry; /* will be initialized by init_printing_events() */
static size_t Len_str_entry; /* will be initialized by init_printing_events() */

static const char *Warning = "[WARNING: string truncated]";
static size_t Len_Warning;

enum { TASK_COMM_LEN = 16 };
enum { LEN_SYS = 4 }; /* = strlen("SyS_") */

static unsigned long long start_ts_nsec = 0;

static inline const char *sc_num2str(const int64_t sc_num);
static inline void fprint_i64(FILE *f, uint64_t x);
static inline char b2hex(char b);

static unsigned Arg_is_str[6] = {
	/* syscall has string as a first arg */
	EM_str_1,
	/* syscall has string as second arg */
	EM_str_2,
	/* syscall has string as third arg */
	EM_str_3,
	/* syscall has string as fourth arg */
	EM_str_4,
	/* syscall has string as fifth arg */
	EM_str_5,
	/* syscall has string as sixth arg */
	EM_str_6
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
	int64_t res = 0, err = 0;
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
		fprintf(Out_lf, "%-6lu %4ld %3ld %s\n",
				event->pid_tid, res, err, event->aux_str);
	else
		fprintf(Out_lf, "%-6lu %4ld %3ld %s\n",
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
	(void) res;

	return buf;
}

/*
 * fwrite_sc_name -- write syscall's name to stream
 */
static inline void
fwrite_sc_name(FILE *f, const int64_t sc_id)
{
	fwrite(Syscall_array[sc_id].handler_name + LEN_SYS,
		Syscall_array[sc_id].name_length - LEN_SYS, 1, f);
}

/*
 * is_path -- checks if the argument is a path
 */
static int
is_path(int argn, unsigned sc_num)
{
	if ((Syscall_array[sc_num].mask & Arg_is_str[argn]) ==
							Arg_is_str[argn])
		return 1;
	else
		return 0;
}

/*
 * fprint_path -- return argument's type code for syscall number
 */
static void
fprint_path(unsigned path, int *str_fini, FILE *f,
		struct data_entry_t *const event, int size)
{
	char *str = NULL;
	size_t len = 0;
	size_t max_len = 0;

	(void) size;

	unsigned nstrings = Syscall_array[event->sc_id].nstrings;

	if (event->packet_type != 0) {
		max_len = STR_MAX_1;
		str = event->aux_str;
	} else {
		switch (nstrings) {
		case 0:
			assert(nstrings > 0);
			break;
		case 1:
			max_len = STR_MAX_1;
			str = event->aux_str;
			break;
		case 2:
			max_len = STR_MAX_2;
			switch (path) {
			case 1:
				str = event->aux_str;
				break;
			case 2:
				str = event->aux_str + (BUF_SIZE / 2);
				break;
			default:
				assert(path <= nstrings);
				break;
			}
			break;
		case 3:
			max_len = STR_MAX_3;
			switch (path) {
			case 1:
				str = event->aux_str;
				break;
			case 2:
				str = event->aux_str + (BUF_SIZE / 3);
				break;
			case 3:
				str = event->aux_str + 2 * (BUF_SIZE / 3);
				break;
			default:
				assert(path <= nstrings);
				break;
			}
			break;
		default:
			assert(nstrings <= MAX_STR_ARG);
			break;
		}
	}

	if (str == NULL)
		return;

	len = strnlen(str, (max_len + 1)); /* + 1 for terminating '\0' */
	/* check if string is truncated */
	if (len == (max_len + 1)) {
		int str_will_be_continued = 0;
		if (event->packet_type) {
			/* bit 7 of packet_type = string will be continued */
			str_will_be_continued = (event->packet_type >> 7) & 0x1;
		}
		if (!str_will_be_continued) {
			/* print warning that string is truncated */
			fwrite(Warning, Len_Warning, 1, f);
		}
		*str_fini = 0;
	} else {
		*str_fini = 1;
	}

	fwrite(str, len, 1, f);
}

/*
 * fprint_arg_hex -- print argument in hex form
 */
static void
fprint_arg_hex(int argn, FILE *f, struct data_entry_t *const event, int size,
		int *n_str, int *str_fini)
{
	if (is_path(argn, (unsigned)event->sc_id)) {
		(*n_str)++;
		fprint_path(*n_str, str_fini, f, event, size);
	} else {
		fprint_i64(f, (uint64_t)event->args[argn]);
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
	(void) res;
}

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

	Len_Warning = strlen(Warning);
}

/*
 * print_event_hex_entry -- print syscall's logs entry in stream
 */
static void
print_event_hex_entry(FILE *f, void *data, int size)
{
	struct data_entry_t *const event = data;
	static int str_fini = 1; /* printing last string was finished */
	static int n_str = 0; /* counter of string arguments */

	/* XXX Check size arg */
	(void) size;

	if (start_ts_nsec == 0)
		start_ts_nsec = event->start_ts_nsec;

	int arg_begin = 0;
	int arg_end = 7;
	int arg_cont = 0;

	/* multi-packet: read arg_begin and arg_end */
	unsigned packets = event->packet_type;
	if (packets) {
		arg_begin = packets & 0x7;	 /* bits 0-2 */
		arg_end =  (packets >> 3) & 0x7; /* bits 3-5 */
		arg_cont = (packets >> 6) & 0x1; /* bit 6 (is a continuation) */
	}

	/* is it a continuation of a string ? */
	if (arg_begin == arg_end) {
		assert(arg_cont == 1);
		if (str_fini == 0) {
			unsigned max_len = BUF_SIZE - 1;
			unsigned len = strnlen(event->aux_str, max_len);
			fwrite(event->aux_str, len, 1, f);
			if (len < max_len)
				str_fini = 1;
		}
		return;
	}

	/* print timestamp, PID_TID and syscall's name */
	if (arg_begin == 0) {
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
	}

	/* is it a continuation of last argument (full name mode)? */
	if (arg_cont) {
		/* it is a continuation of last argument */
		if (str_fini) {
			/* printing string was already finished, so skip it */
			arg_begin++;
			arg_cont = 0;
			str_fini = 0;
		}
	} else {
		/* arg_begin argument was printed in the previous packet */
		arg_begin++;
	}

	/* should we print EOL ? */
	int print_eol;
	if (arg_end == 7) {
		print_eol = 1;
		/* and set the true value of the last argument */
		arg_end = Syscall_array[event->sc_id].args_qty;
	} else {
		print_eol = 0;
	}

	/* print syscall's arguments */
	for (int i = (arg_begin - 1); i <= (arg_end - 1); i++) {
		if ((i > arg_begin - 1) || !arg_cont || str_fini)
			fwrite_out_lf_fld_sep(f);
		fprint_arg_hex(i, f, event, size, &n_str, &str_fini);
	}

	/* should we print EOL ? */
	if (print_eol) {
		n_str = 0; /* reset counter of string arguments */
		str_fini = 1;
		fwrite("\n", 1, 1, f);
	}
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
	int64_t res, err;
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
	int64_t res, err;
	struct tp_s *const event = data;
	static const char *str_sys_exit = "sys_exit ";
	static const size_t len_sys_exit = 9; /* length of the string above */

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
		fwrite_sc_name(f, event->id);
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
	uint64_t *type = data;
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
#define MAX_LEN_STR 4096

	struct header_s {
		int argc;
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

void
choose_fnr_mode(const char *filename_length,
		enum fnr_mode *mode, unsigned *n_str_packets)
{
	unsigned len = atoi(filename_length);

	if (len <= STR_MAX_3) {
		*mode = E_FNR_FAST;
		*n_str_packets = 1;
		NOTICE("FAST filename read mode "
			"(1 packet per syscall, "
			"max string length = %i)", STR_MAX_3);

	} else if (len <= STR_MAX_1) {
		*mode = E_FNR_STR_MAX;
		*n_str_packets = 1;
		NOTICE("BUF_SIZE filename read mode "
			"(1 packet per string argument, "
			"max string length = %i)", STR_MAX_1);

	} else {
		*mode = E_FNR_FULL;
		unsigned np = (len + 1) / (BUF_SIZE - 1);
		if (np * (BUF_SIZE - 1) < (len + 1))
			np++;
		*n_str_packets = np;
		NOTICE("FULL filename read mode "
			"(%i packets per string argument, "
			"max string length = %i)", np, np * (BUF_SIZE - 1) - 1);
	}
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
