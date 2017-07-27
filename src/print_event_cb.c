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
#include <sys/utsname.h>
#include <linux/limits.h>

#include "vltrace.h"
#include "ebpf_syscalls.h"
#include "print_event_cb.h"
#include "utils.h"
#include "config.h"

#include "ebpf/trace.h"

/* vltrace syscall table signature */
#define VLTRACE_TAB_SIGNATURE	"VLTRACE_TAB"

/* vltrace log signature */
#define VLTRACE_LOG_SIGNATURE	"VLTRACE_LOG"

#define STR_ARCH_x86_64		"x86_64"

#define COMPILE_ERROR_ON(cond) ((void)sizeof(char[(cond) ? -1 : 1]))

static char *Str_entry; /* will be initialized by init_printing_events() */
static size_t Len_str_entry; /* will be initialized by init_printing_events() */

static const char *Warning = "[WARNING: string truncated]";
static size_t Len_Warning;

enum { TASK_COMM_LEN = 16 };
enum { LEN_SYS = 4 }; /* = strlen("SyS_") */

static unsigned long long start_ts_nsec = 0;

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
 * Also it can be a good idea to use cb_cookie for Args, for OutputFile or for
 *    static variable above.
 */

/* ** Hex logs ** */

/*
 * print_header_hex -- print header for hexadecimal logs
 */
static int
print_header_hex(int argc, char *const argv[])
{
	for (int i = 0; i < argc; i++) {
		if (i + 1 != argc)
			fprintf(OutputFile, "%s%c", argv[i], Args.separator);
		else
			fprintf(OutputFile, "%s\n", argv[i]);
	}

	fprintf(OutputFile, "%s%c", "PID_TID", Args.separator);

	if (Args.timestamp)
		fprintf(OutputFile, "%s%c", "TIME(nsec)", Args.separator);

	fprintf(OutputFile, "%s%c", "ERR", Args.separator);
	fprintf(OutputFile, "%s%c", "RES", Args.separator);
	fprintf(OutputFile, "%s%c", "SYSCALL", Args.separator);
	fprintf(OutputFile, "%s%c", "ARG1", Args.separator);
	fprintf(OutputFile, "%s%c", "ARG2", Args.separator);
	fprintf(OutputFile, "%s%c", "ARG3", Args.separator);
	fprintf(OutputFile, "%s%c", "ARG4", Args.separator);
	fprintf(OutputFile, "%s%c", "ARG5", Args.separator);
	fprintf(OutputFile, "%s%c", "ARG6", Args.separator);

	/* For COMM and like */
	fprintf(OutputFile, "%s", "AUX_DATA");

	fprintf(OutputFile, "\n");

	return 0;
}

/*
 * b2hex -- return character corresponding to hexadecimal digit
 */
static inline char
b2hex(char b)
{
	return "0123456789ABCDEF"[b & 0xf];
}

/*
 * fprint_i64 -- print 64-bit integer in hexadecimal form
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
 * fwrite_sc_name -- write syscall's name to stream
 */
static inline void
fwrite_sc_name(FILE *f, const int64_t sc_id)
{
	fwrite(Syscall_array[sc_id].syscall_name + LEN_SYS,
		Syscall_array[sc_id].name_length - LEN_SYS, 1, f);
}

/*
 * is_path -- checks if the argument is a path
 */
static int
is_path(int argn, unsigned sc_num)
{
	return (Syscall_array[sc_num].mask & Arg_is_str[argn]) ==
							Arg_is_str[argn];
}

/*
 * fprint_path -- return argument's type code for syscall number
 */
static void
fprint_path(unsigned path, int *str_fini, FILE *f,
		struct data_entry_s *const event, int size)
{
	char *str = NULL;
	size_t len = 0;
	size_t max_len = 0;

	(void) size;

	unsigned nstrings = Syscall_array[event->sc_id].nstrings;

	if (event->info_all & ARG_MASK) {
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
		if (!event->info.will_be_cont) {
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
fprint_arg_hex(int argn, FILE *f, struct data_entry_s *const event, int size,
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

	res = fwrite(&Args.separator, sizeof(Args.separator), 1, f);
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

	str[0]  = Args.separator;
	str[17] = Args.separator;
	str[34] = Args.separator;

	Str_entry = str;
	Len_str_entry = strlen(str);

	Len_Warning = strlen(Warning);
}

/*
 * print_event_text_kp_entry -- print syscall's logs on Kprobe's entry
 */
static void
print_event_text_kp_entry(FILE *f, void *data, int size)
{
	struct data_entry_s *const event = data;
	static int str_fini = 1; /* printing last string was finished */
	static int n_str = 0; /* counter of string arguments */

	/* XXX Check size arg */
	(void) size;

	if (start_ts_nsec == 0)
		start_ts_nsec = event->start_ts_nsec;

	int arg_first = FIRST_PACKET;
	int arg_last = LAST_PACKET;
	int is_cont = 0;

	if (event->info_all & ARG_MASK) {
		/* multi-packet: read arg_first and arg_last */
		arg_first = event->info.arg_first;
		arg_last = event->info.arg_last;
		is_cont = event->info.is_cont;
	}

	/* is it a continuation of a string ? */
	if (arg_first == arg_last) {
		assert(is_cont == 1);
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
	if (arg_first == FIRST_PACKET) {
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
	if (is_cont) {
		/* it is a continuation of last argument */
		if (str_fini) {
			/* printing string was already finished, so skip it */
			arg_first++;
			is_cont = 0;
			str_fini = 0;
		}
	} else {
		/* arg_first argument was printed in the previous packet */
		arg_first++;
	}

	int end_of_syscall = 0;
	if (arg_last == LAST_PACKET) {
		end_of_syscall = 1;
		/* and set the true value of the last argument */
		arg_last = Syscall_array[event->sc_id].args_qty;
	}

	/* print syscall's arguments */
	for (int i = (arg_first - 1); i <= (arg_last - 1); i++) {
		if ((i > arg_first - 1) || !is_cont || str_fini)
			fwrite_out_lf_fld_sep(f);
		fprint_arg_hex(i, f, event, size, &n_str, &str_fini);
	}

	if (event->info.bpf_read_error) {
		fwrite(" [Warning: bpf read error occurred] ",
			35 /* strlen of the message */, 1, f);
	}

	if (end_of_syscall) {
		n_str = 0; /* reset counter of string arguments */
		str_fini = 1;
		fwrite("\n", 1, 1, f);
	}
}

/*
 * print_event_text_kp_exit -- print syscall's logs on Kprobe's exit
 */
static void
print_event_text_kp_exit(FILE *f, void *data, int size)
{
	int64_t res, err;
	struct data_exit_s *const event = data;

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
 * print_event_text_tp_exit -- print syscall's logs on Tracepoint's exit
 */
static void
print_event_text_tp_exit(FILE *f, void *data, int size)
{
	int64_t res, err;
	struct data_exit_s *const event = data;
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

	if (event->sc_id < SC_TBL_SIZE) {
		fwrite_sc_name(f, event->sc_id);
	} else {
		fwrite(str_sys_exit, len_sys_exit, 1, f);
		fprint_i64(f, (uint64_t)(event->sc_id));
	}

	fwrite("\n", 1, 1, f);
}

/*
 * print_event_text -- print syscall's logs
 */
static void
print_event_text(void *cb_cookie, void *data, int size)
{
#define STR_LEN 30
	const char *str = "ERROR: unknown type of event: ";
	uint32_t *size_s = data;
	uint32_t *info_all = size_s + 1;
	uint32_t packet_type = *info_all & E_MASK; /* bits 0-1 */

	(void) cb_cookie;

	switch (packet_type) {
	case E_KP_ENTRY:
		print_event_text_kp_entry(OutputFile, data, size);
		break;
	case E_KP_EXIT:
		print_event_text_kp_exit(OutputFile, data, size);
		break;
	case E_TP_EXIT:
		print_event_text_tp_exit(OutputFile, data, size);
		break;
	default:
		fwrite(str, STR_LEN, 1, OutputFile);
		fprint_i64(OutputFile, packet_type);
		fwrite("\n", 1, 1, OutputFile);
		break;
	}
#undef STR_LEN
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
		uint32_t argc;
		char argv[MAX_LEN_STR];
	} header;

	uint32_t data_size = 0;
	uint32_t next_size = 0;

	/* save command line in struct header */
	for (int i = 0; i < argc; i++) {
		next_size = strlen(argv[i]) + 1;
		if (data_size + next_size >= MAX_LEN_STR)
			return -1;
		strcpy(header.argv + data_size, argv[i]);
		data_size += next_size;
	}

	header.argc = argc;
	data_size += offsetof(struct header_s, argv);

	/* get current working directory */
	char cwd[PATH_MAX];
	if (getcwd(cwd, PATH_MAX) == NULL) {
		perror("getcwd");
		return -1;
	}

	/* get hardware identifier (utsname.machine) */
	struct utsname buf;
	if (uname(&buf)) {
		perror("uname");
		return -1;
	}

	/* check architecture - currently only x86_64 is supported */
	uint32_t architecture;
	if (strcmp(buf.machine, STR_ARCH_x86_64) == 0) {
		architecture = ARCH_x86_64;
	} else {
		ERROR("unknown architecture: %s", buf.machine);
		return -1;
	}

	/*
	 *               *** FORMAT OF VLTRACE BINARY LOG ***
	 *
	 *	* first 80036 bytes is the same for all logs:
	 *
	 *	char [12]		- syscall table signature "VLTRACE_TAB"
	 *	uint32_t		- major version number
	 *	uint32_t		- minor version number
	 *	uint32_t		- patch version number
	 *	uint32_t		- hardware architecture
	 *	struct sc_desc [1000]	- syscall table
	 *
	 *	* offset 80036 bytes is here
	 *
	 *	char [12]		- log signature "VLTRACE_LOG"
	 *	uint32_t		- BUF_SIZE
	 *	uint32_t		- length of CWD (cwd_len)
	 *	char [cwd_len]		- current working directory
	 *	uint32_t		- size of the following struct header
	 *	struct header		- structure containing the command line
	 *
	 *	* Here follows actual log consisting of pairs:
	 *
	 *	uint32_t		- size of the packet
	 *	struct data_*		- data packet
	 */

	/* save syscall table signature */
	char tab_signature[] = VLTRACE_TAB_SIGNATURE;
	COMPILE_ERROR_ON(sizeof(tab_signature) != 12);
	if (fwrite(tab_signature, sizeof(tab_signature), 1, OutputFile) != 1) {
		return -1;
	}

	/* save version number */
	uint32_t major = VLTRACE_VERSION_MAJOR;
	uint32_t minor = VLTRACE_VERSION_MINOR;
	uint32_t patch = VLTRACE_VERSION_PATCH;
	if (fwrite(&major, sizeof(major), 1, OutputFile) != 1 ||
	    fwrite(&minor, sizeof(minor), 1, OutputFile) != 1 ||
	    fwrite(&patch, sizeof(patch), 1, OutputFile) != 1) {
		return -1;
	}

	/* save hardware architecture */
	if (fwrite(&architecture, sizeof(architecture), 1, OutputFile) != 1) {
		return -1;
	}

	/* save syscall table */
	if (dump_syscalls_table(OutputFile)) {
		return -1;
	}

	/*   *** HERE COMES LOG ***   */

	/* save log signature */
	char log_signature[] = VLTRACE_LOG_SIGNATURE;
	COMPILE_ERROR_ON(sizeof(log_signature) != 12);
	if (fwrite(log_signature, sizeof(log_signature), 1, OutputFile) != 1) {
		return -1;
	}

	/* save BUF_SIZE */
	uint32_t buf_size = BUF_SIZE;
	if (fwrite(&buf_size, sizeof(buf_size), 1, OutputFile) != 1) {
		return -1;
	}

	/* save length of CWD */
	uint32_t cwd_len = strlen(cwd) + 1;
	if (fwrite(&cwd_len, sizeof(cwd_len), 1, OutputFile) != 1) {
		return -1;
	}

	/* save CWD */
	if (fwrite(cwd, cwd_len, 1, OutputFile) != 1) {
		return -1;
	}

	/* save header's size */
	if (fwrite(&data_size, sizeof(data_size), 1, OutputFile) != 1) {
		return -1;
	}

	/* save header */
	if (fwrite(&header, data_size, 1, OutputFile) != 1) {
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

	if (fwrite(data, (size_t)size, 1, OutputFile) != 1) {
		OutputError = 1;
	}
}

/*
 * out_fmt_str2enum -- parse log's type
 */
enum out_format
out_fmt_str2enum(const char *str)
{
	if (strcasecmp("bin", str) == 0)
		return EOF_BIN;

	if (strcasecmp("text", str) == 0)
		return EOF_TEXT;

	return EOF_TEXT;
}

/*
 * available_bpf_probe_read_str -- check if kernel version is >= 4.11,
 *                                 because bpf_probe_read_str() is available
 *                                 starting from kernel 4.11
 */
static int
available_bpf_probe_read_str()
{
/* bpf_probe_read_str() is available starting from kernel 4.11 */
#define AVAILABLE_KERNEL_VERSION 411
	struct utsname buf;
	uname(&buf);

	int kv = 100 * atoi(strtok(buf.release, "."));
	kv += atoi(strtok(NULL, "."));
	return kv >= AVAILABLE_KERNEL_VERSION;
#undef AVAILABLE_KERNEL_VERSION
}

/*
 * choose_fnr_mode -- choose mode of reading string arguments
 */
void
choose_fnr_mode(const char *str_len,
		enum fnr_mode *mode, unsigned *n_str_packets)
{
	unsigned len = atoi(str_len);

	if (len <= STR_MAX_3) {
		*mode = E_STR_FAST;
		*n_str_packets = 1;
		NOTICE(
			"FAST string read mode (1 packet per syscall, max string length = %i)",
			STR_MAX_3);

	} else if (len <= STR_MAX_1) {
		*mode = E_STR_STR_MAX;
		*n_str_packets = 1;
		NOTICE(
			"PACKET string read mode (1 packet per string argument, max string length = %i)",
			STR_MAX_1);

	} else {
		unsigned np = (len + 1) / (BUF_SIZE - 1);
		if (np * (BUF_SIZE - 1) < (len + 1))
			np++;
		*n_str_packets = np;
		if (available_bpf_probe_read_str()) {
			*mode = E_STR_FULL;
			NOTICE(
				"FULL string read mode (maximum %i packets per string argument, max string length = %i)",
				np, np * (BUF_SIZE - 1) - 1);
		} else {
			*mode = E_STR_FULL_CONST_N;
			NOTICE(
				"CONST string read mode (always %i packets per string argument, max string length = %i)",
				np, np * (BUF_SIZE - 1) - 1);
		}
	}
}

perf_reader_raw_cb Print_event_cb[EOF_QTY + 1] = {
	[EOF_TEXT]	= print_event_text,
	[EOF_BIN]	= print_event_bin,
};

print_header_t Print_header[EOF_QTY + 1] = {
	[EOF_TEXT]	= print_header_hex,
	[EOF_BIN]	= print_header_bin,
};
