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

#include "ebpf/trace.h"

static unsigned long long start_ts_nsec = 0;

static inline const char *sc_num2str(const int64_t sc_num);
static inline void fprint_i64(FILE *f, uint64_t x);
static inline char b2hex(char b);

/*
 * Process event.
 *
 * Also it can be a good idea to use cb_cookie for Args, for Out_lf or for
 *    static variable above.
 */

/*
 * print_header_strace -- Print logs header.
 *
 * XXX A blank for human-readable strace-like logs
 */
static void
print_header_strace(int argc, char *const argv[])
{
	if (Args.timestamp)
		fprintf(Out_lf, "%-14s", "TIME(s)");

	fprintf(Out_lf, "%-7s %-6s %4s %3s %s\n",
		"SYSCALL", "PID_TID", "ARG1", "ERR", "PATH");

	(void) argc;
	(void) argv;
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

	if (0 <= event->sc_id)
		fprintf(Out_lf, "%-7s ", sc_num2str(event->sc_id));
	else
		fprintf(Out_lf, "%-7s ", event->sc_name + 4);

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
 * print_header_hex -- This function prints header for hexadecimal logs.
 */
static void
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
 * fprint_first_str -- This function prints first string from event
 *     in stream.
 */
static inline void
fprint_first_str(FILE *f, struct data_entry_t *const event, int size)
{
	/*
	 * XXX Check presence of string body by cheking sc_id
	 *    and size arg
	 */
	(void) size;

	/* This packet contains only single string. Let's write it */
	if (0 != event->packet_type) {
		fwrite(event->str, strnlen(event->str, NAME_MAX), 1, f);
		return;
	}


	/* Half-lenth strings */
	if (EM_fs_path_1_2_arg == (EM_fs_path_1_2_arg &
				Syscall_array[event->sc_id].masks)) {
		fwrite(event->aux_str,
				strnlen(event->aux_str, NAME_MAX / 2), 1, f);
		return;
	}

	if (EM_fs_path_1_3_arg == (EM_fs_path_1_3_arg &
				Syscall_array[event->sc_id].masks)) {
		fwrite(event->aux_str,
				strnlen(event->aux_str, NAME_MAX / 2), 1, f);
		return;
	}

	if (EM_fs_path_2_4_arg == (EM_fs_path_2_4_arg &
				Syscall_array[event->sc_id].masks)) {
		fwrite(event->aux_str,
				strnlen(event->aux_str, NAME_MAX / 2), 1, f);
		return;
	}

	/* Full-length strings */
	fwrite(event->aux_str, strnlen(event->aux_str, NAME_MAX), 1, f);
}

/*
 * fprint_second_str -- This function prints second string from event
 *     in stream.
 */
static inline void
fprint_second_str(FILE *f, struct data_entry_t *const event, int size)
{
	/* This packet doesn't contain second string */
	if (0 != event->packet_type)
		/* XXX assert(false); */
		return;

	/*
	 * XXX Check presence of string body by checking sc_id
	 *    and size arg
	 */
	(void) size;

	/* Half-lenth strings */
	if (EM_fs_path_1_2_arg == (EM_fs_path_1_2_arg &
				Syscall_array[event->sc_id].masks)) {
		const char *const p = event->aux_str + (NAME_MAX / 2);
		fwrite(p, strnlen(p, NAME_MAX - (NAME_MAX / 2)), 1, f);
		return;
	}

	if (EM_fs_path_1_3_arg == (EM_fs_path_1_3_arg &
				Syscall_array[event->sc_id].masks)) {
		const char *const p = event->aux_str + (NAME_MAX / 2);
		fwrite(p, strnlen(p, NAME_MAX - (NAME_MAX / 2)), 1, f);
		return;
	}

	if (EM_fs_path_2_4_arg == (EM_fs_path_2_4_arg &
				Syscall_array[event->sc_id].masks)) {
		const char *const p = event->aux_str + (NAME_MAX / 2);
		fwrite(p, strnlen(p, NAME_MAX - (NAME_MAX / 2)), 1, f);
		return;
	}

	/* Full-length strings */
	/* XXX assert(false); */
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

		return Syscall_array[sc_num].handler_name +
			4 /* strlen("sys_") */;
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
fwrite_sc_name(FILE *f, const s64 sc_id, char const *sc_name, int size)
{
	/* XXX Temporarily */
	(void) size;

	if (sc_id >= 0) {
		fwrite(sc_num2str(sc_id), strlen(sc_num2str(sc_id)), 1, f);
	} else {
		/* XXX Check presence of string body by checking size arg */
		fwrite(sc_name + 4, strlen(sc_name + 4), 1, f);
	}
}

/*
 * get_type_of_arg1 -- return first arg's type code for syscall num.
 */
static enum sc_arg_type
get_type_of_arg1(unsigned sc_num)
{
	if (EM_fs_path_1_2_arg == (EM_fs_path_1_2_arg &
				Syscall_array[sc_num].masks))
		return EAT_path;

	if (EM_fs_path_1_3_arg == (EM_fs_path_1_3_arg &
				Syscall_array[sc_num].masks))
		return EAT_path;

	if (EM_file == (EM_file & Syscall_array[sc_num].masks))
		return EAT_path;

	if (EM_desc == (EM_desc & Syscall_array[sc_num].masks))
		return EAT_file_descriptor;

	if (EM_fileat == (EM_fileat & Syscall_array[sc_num].masks))
		return EAT_file_descriptor;

	if (Syscall_array[sc_num].args_qty >= 1)
		return EAT_int;

	/* Syscall doesn't have this arg. Don't print anything. */
	return EAT_absent;
}

/*
 * fprint_arg1_hex -- If syscall has first arg print it in hex form.
 */
static void
fprint_arg1_hex(FILE *f, struct data_entry_t *const event, int size)
{
	switch (event->sc_id) {
	case -2:
		fprint_i64(f, (uint64_t)event->arg_1);
		break;

	case -1:
		/*
		 * XXX Something unexpected happened. Maybe we should issue a
		 *    warning or do something better
		 */
		break;

	default:
		switch (get_type_of_arg1((unsigned)event->sc_id)) {
		case EAT_path:
			fprint_first_str(f, event, size);
			break;

		case EAT_pointer:
		case EAT_file_descriptor:
		case EAT_int:
		default:
			fprint_i64(f, (uint64_t)event->arg_1);
			break;

		case EAT_absent:
			/* syscall doesn't have this argument */
			break;
		}
		break;
	}
}

/*
 * get_type_of_arg2 -- return second arg's type code for syscall num.
 */
static enum sc_arg_type
get_type_of_arg2(unsigned sc_num)
{
	if (EM_fs_path_1_2_arg == (EM_fs_path_1_2_arg &
				Syscall_array[sc_num].masks))
		return EAT_path;

	if (EM_fs_path_2_4_arg == (EM_fs_path_2_4_arg &
				Syscall_array[sc_num].masks))
		return EAT_path;

	if (EM_fileat == (EM_fileat & Syscall_array[sc_num].masks))
		return EAT_path;

	if (Syscall_array[sc_num].args_qty >= 2)
		return EAT_int;

	/* syscall doesn't have this argument */
	return EAT_absent;
}

/*
 * fprint_arg2_path -- If syscall has path in second arg print it as ascii str
 */
static void
fprint_arg2_path(FILE *f, struct data_entry_t *const event, int size)
{
	if (EM_fs_path_1_2_arg == (EM_fs_path_1_2_arg &
				Syscall_array[event->sc_id].masks)) {
		if (0 == event->packet_type)
			fprint_second_str(f, event, size);
		else
			fprint_first_str(f, event, size);
	} else if (EM_fs_path_2_4_arg == (EM_fs_path_2_4_arg &
				Syscall_array[event->sc_id].masks)) {
		fprint_first_str(f, event, size);
	} else if (EM_fileat == (EM_fileat &
				Syscall_array[event->sc_id].masks)) {
		fprint_first_str(f, event, size);
	}
}

/*
 * fprint_arg2_hex -- If syscall has second arg print it in hex form.
 */
static void
fprint_arg2_hex(FILE *f, struct data_entry_t *const event, int size)
{
	switch (event->sc_id) {
	case -2:
		fprint_i64(f, (uint64_t)event->arg_2);
		break;

	case -1:
		/*
		 * XXX Something unexpected happened. Ma be we should issue a
		 *    warning or do something better
		 */
		break;

	default:
		switch (get_type_of_arg2((unsigned)event->sc_id)) {
		case EAT_path:
			fprint_arg2_path(f, event, size);
			break;

		case EAT_pointer:
		case EAT_file_descriptor:
		case EAT_int:
		default:
			fprint_i64(f, (uint64_t)event->arg_2);
			break;

		case EAT_absent:
			/* syscall doesn't have this argument */
			break;
		}
		break;
	}
}

/*
 * get_type_of_arg3 -- return third arg's type code for syscall num.
 */
static enum sc_arg_type
get_type_of_arg3(unsigned sc_num)
{
	if (EM_fs_path_1_3_arg == (EM_fs_path_1_3_arg &
				Syscall_array[sc_num].masks))
		return EAT_path;

	if (Syscall_array[sc_num].args_qty >= 3)
		return EAT_int;

	/* syscall doesn't have this argument */
	return EAT_absent;
}

/*
 * fprint_arg3_path -- If syscall has path in third arg print it as ascii str
 */
static void
fprint_arg3_path(FILE *f, struct data_entry_t *const event, int size)
{
	if (EM_fs_path_1_3_arg == (EM_fs_path_1_3_arg &
				Syscall_array[event->sc_id].masks)) {
		if (0 == event->packet_type)
			fprint_second_str(f, event, size);
		else
			fprint_first_str(f, event, size);
	}
}

/*
 * fprint_arg3_hex -- If syscall has third arg print it in hex form.
 */
static void
fprint_arg3_hex(FILE *f, struct data_entry_t *const event, int size)
{
	/* XXX Temporarily */
	(void) size;

	switch (event->sc_id) {
	case -2:
		fprint_i64(f, (uint64_t)event->arg_3);
		break;

	case -1:
		/*
		 * XXX Something unexpected happened. Ma be we should issue a
		 *    warning or do something better
		 */
		break;

	default:
		switch (get_type_of_arg3((unsigned)event->sc_id)) {
		case EAT_path:
			fprint_arg3_path(f, event, size);
			break;

		case EAT_pointer:
		case EAT_file_descriptor:
		case EAT_int:
		default:
			fprint_i64(f, (uint64_t)event->arg_3);
			break;

		case EAT_absent:
			/* syscall doesn't have this argument */
			break;
		}
		break;
	}
}

/*
 * get_type_of_arg4 -- return fourth arg's type code for syscall num.
 */
static enum sc_arg_type
get_type_of_arg4(unsigned sc_num)
{
	if (EM_fs_path_2_4_arg == (EM_fs_path_2_4_arg &
				Syscall_array[sc_num].masks))
		return EAT_path;

	if (Syscall_array[sc_num].args_qty >= 4)
		return EAT_int;

	/* syscall doesn't have this argument */
	return EAT_absent;
}

/*
 * fprint_arg4_path -- If syscall has path in fourth arg print it as ascii str
 */
static void
fprint_arg4_path(FILE *f, struct data_entry_t *const event, int size)
{
	if (EM_fs_path_2_4_arg == (EM_fs_path_2_4_arg &
				Syscall_array[event->sc_id].masks)) {
		if (0 == event->packet_type)
			fprint_second_str(f, event, size);
		else
			fprint_first_str(f, event, size);
	}
}

/*
 * fprint_arg4_hex -- If syscall has fourth arg print it in hex form.
 */
static void
fprint_arg4_hex(FILE *f, struct data_entry_t *const event, int size)
{
	/* XXX Temporarily */
	(void) size;

	switch (event->sc_id) {
	case -2:
		fprint_i64(f, (uint64_t)event->arg_4);
		break;

	case -1:
		/*
		 * XXX Something unexpected happened. Ma be we should issue a
		 *    warning or do something better
		 */
		break;

	default:
		switch (get_type_of_arg4((unsigned)event->sc_id)) {
		case EAT_path:
			fprint_arg4_path(f, event, size);
			break;

		case EAT_pointer:
		case EAT_file_descriptor:
		case EAT_int:
		default:
			fprint_i64(f, (uint64_t)event->arg_4);
			break;

		case EAT_absent:
			/* syscall doesn't have this argument */
			break;
		}
		break;
	}
}

/*
 * get_type_of_arg5 -- return fifth arg's type code for syscall num.
 */
static enum sc_arg_type
get_type_of_arg5(unsigned sc_num)
{
	if (Syscall_array[sc_num].args_qty >= 5)
		return EAT_int;

	/* Syscall doesn't have this arg. Don't print anything. */
	return EAT_absent;
}

/*
 * fprint_arg5_path -- If syscall has path in fifth arg print it as ascii str
 */
static void
fprint_arg5_path(FILE *f, struct data_entry_t *const event, int size)
{
	(void) f;
	(void) event;
	(void) size;

	assert(false);
}


/*
 * fprint_arg5_hex -- If syscall has fifth arg print it in hex form.
 */
static void
fprint_arg5_hex(FILE *f, struct data_entry_t *const event, int size)
{
	/* XXX Temporarily */
	(void) size;

	switch (event->sc_id) {
	case -2:
		fprint_i64(f, (uint64_t)event->arg_5);
		break;

	case -1:
		/*
		 * XXX Something unexpected happened. Ma be we should issue a
		 *    warning or do something better
		 */
		break;

	default:
		switch (get_type_of_arg5((unsigned)event->sc_id)) {
		case EAT_path:
			fprint_arg5_path(f, event, size);
			break;

		case EAT_pointer:
		case EAT_file_descriptor:
		case EAT_int:
		default:
			fprint_i64(f, (uint64_t)event->arg_5);
			break;

		case EAT_absent:
			/* syscall doesn't have this argument */
			break;
		}
		break;
	}
}

/*
 * get_type_of_arg6 -- return sixth arg's type code for syscall num.
 */
static enum sc_arg_type
get_type_of_arg6(unsigned sc_num)
{
	if (Syscall_array[sc_num].args_qty >= 6)
		return EAT_int;

	/* syscall doesn't have this argument */
	return EAT_absent;
}

/*
 * fprint_arg6_path -- If syscall has path in sixth arg print it as ascii str
 */
static void
fprint_arg6_path(FILE *f, struct data_entry_t *const event, int size)
{
	(void) f;
	(void) event;
	(void) size;

	assert(false);
}


/*
 * fprint_arg6_hex -- If syscall has sixth arg print it in hex form.
 */
static void
fprint_arg6_hex(FILE *f, struct data_entry_t *const event, int size)
{
	/* XXX Temporarily */
	(void) size;

	switch (event->sc_id) {
	case -2:
		fprint_i64(f, (uint64_t)event->arg_6);
		break;

	case -1:
		/*
		 * XXX Something unexpected happened. May be we should issue a
		 *    warning or do something better
		 */
		break;

	default:
		switch (get_type_of_arg6((unsigned)event->sc_id)) {
		case EAT_path:
			fprint_arg6_path(f, event, size);
			break;

		case EAT_pointer:
		case EAT_file_descriptor:
		case EAT_int:
		default:
			fprint_i64(f, (uint64_t)event->arg_6);
			break;

		case EAT_absent:
			/* syscall doesn't have this argument */
			break;
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

/*
 * print_event_hex_entry -- This function prints syscall's logs entry in stream.
 *
 * WARNING
 *
 *    PLEASE don't use *printf() calls because it will slow down this
 *		 function too much.
 */
static void
print_event_hex_entry(FILE *f, void *data, int size)
{
	struct data_entry_t *const event = data;
	char *str = "----------------";
	size_t lenstr = strlen(str);

	/* XXX Check size arg */
	(void) size;

	if (start_ts_nsec == 0)
		start_ts_nsec = event->start_ts_nsec;

	if (Args.timestamp) {
		unsigned long long delta_nsec =
			event->start_ts_nsec - start_ts_nsec;

		fprint_i64(f, delta_nsec);
		fwrite_out_lf_fld_sep(f);
	}

	fprint_i64(f, event->pid_tid);
	fwrite_out_lf_fld_sep(f);

	fwrite(str, lenstr, 1, f);
	fwrite_out_lf_fld_sep(f);

	fwrite(str, lenstr, 1, f);
	fwrite_out_lf_fld_sep(f);

	fwrite_sc_name(f, event->sc_id, event->sc_name, size);
	fwrite_out_lf_fld_sep(f);

	/* "ARG1" */
	fprint_arg1_hex(f, event, size);
	fwrite_out_lf_fld_sep(f);

	/* "ARG2" */
	fprint_arg2_hex(f, event, size);
	fwrite_out_lf_fld_sep(f);

	/* "ARG3" */
	fprint_arg3_hex(f, event, size);
	fwrite_out_lf_fld_sep(f);

	/* "ARG4" */
	fprint_arg4_hex(f, event, size);
	fwrite_out_lf_fld_sep(f);

	/* "ARG5" */
	fprint_arg5_hex(f, event, size);
	fwrite_out_lf_fld_sep(f);

	/* "ARG6" */
	fprint_arg6_hex(f, event, size);
	fwrite_out_lf_fld_sep(f);

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

	fwrite_sc_name(f, event->sc_id, event->sc_name, size);

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
	char *str = "sys_exit";
	size_t lenstr = strlen(str);

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

	fwrite(str, lenstr, 1, f);
	fwrite_out_lf_fld_sep(f);

	fprint_i64(f, event->id);

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
 * XXX We should think about writing 64-bit packet number before length
 *    of packet, but there is probability that counting packets will be very
 *    expensive, because we run in multi-thread environment.
 */

/*
 * print_header_bin -- This function writes header in stream.
 */
static void
print_header_bin(int argc, char *const argv[])
{
	size_t  argv_size = 0;

	struct data_entry_t d = { .sc_id = -1 };

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

	if (1 != fwrite(&d_size, sizeof(d_size), 1, Out_lf)) {
		/* ERROR */
		OutputError = 1;
	}

	if (1 != fwrite(&d, sizeof(d), 1, Out_lf)) {
		/* ERROR */
		OutputError = 1;
	}
}

/*
 * print_event_bin -- This function writes syscall's log entry in stream
 */
static void
print_event_bin(void *cb_cookie, void *data, int size)
{
	struct data_entry_t *const event = data;

	/* XXX Check size arg */

	if (Args.failed /* && (event->ret >= 0) */)
		return;

	if (1 != fwrite(&size, sizeof(size), 1, Out_lf)) {
		/* ERROR */
		OutputError = 1;
	}

	if (1 != fwrite(data, (size_t)size, 1, Out_lf)) {
		/* ERROR */
		OutputError = 1;
	}

	(void) cb_cookie;
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
	[EOF_STRACE] = print_event_strace,
};

print_header_t Print_header[EOF_QTY + 1] = {
	[EOF_HEX_RAW]	= print_header_hex,
	[EOF_HEX_SL]	= print_header_hex,
	[EOF_BIN]	= print_header_bin,
	[EOF_STRACE] = print_header_strace,
};
