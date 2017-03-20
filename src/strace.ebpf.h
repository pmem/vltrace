/*
 * Copyright 2016-2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the copyright holder nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
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
 * strace.ebpf.h -- application-wide stuff
 */

#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

enum out_lf_fmt {
	/* Write syscall's data packets "as is" */
	EOF_HEX_RAW = 0,
	/* Assemble multi-packet syscall data into single line */
	EOF_HEX_SL,
	EOF_BIN,
	EOF_STRACE,


	EOF_QTY, /* Should be last */
};

/* follow fork modes */
enum ff_mode {
	E_FF_DISABLED = 0,
	E_FF_FULL,
	E_FF_FAST,
};

/* filenames reading modes */
enum fnr_mode {
	E_FNR_FAST = 0,
	E_FNR_NAME_MAX,
	E_FNR_FULL,
};

/* 8 Megabytes should be something close to reasonable */
enum { OUT_BUF_SIZE = 8 * 1024 * 1024 };

/*
 * The default size of ring buffers in 4k pages. Must be a power of two.
 *    The lowest possible value is 64. The compromise is 4096.
 */
enum { STRACE_READER_PAGE_CNT_DEFAULT = 4096 };

/*
 * This structure contains default and parsed values for command-line options
 */
struct cl_options {
	/* Mark output lines with timestamp */
	bool timestamp;
	/* Print only failed syscalls */
	bool failed;
	/* We have command to run on command line */
	bool command;

	/* We run in debug mode */
	unsigned debug;

	/* Pid of process to trace */
	pid_t pid;

	/* The name of output log file */
	const char *out_fn;
	/* string constant with type of output log format */
	const char *out_fmt_str;
	/* Field separator for hexadecimal logs */
	char out_lf_fld_sep_ch;
	/* Expression */
	const char *expr;

	/*
	 * XXX Set this variable using Args and
	 *    command line options
	 */
	unsigned pr_arr_max;
	/* follow-fork mode */
	enum ff_mode ff_mode;
	/*
	 * Split logs in per-pid way or, may be, in per pid_tid way,
	 * like strace does.
	 */
	bool ff_separate_logs;
	/* filenames reading mode */
	enum fnr_mode fnr_mode;

	/* XXX Should be configurable through command line */
	unsigned out_buf_size;

	const char *ebpf_src_dir;

	/*
	 * The size of ring buffers in 4k pages. Must be a power of two.
	 * The lowest possible value is 64.
	 */
	int strace_reader_page_cnt;
};

extern struct cl_options Args;
extern int OutputError;
extern int AbortTracing;

/* Output logfile */
extern FILE *Out_lf;
/* Output logfile format */
extern enum out_lf_fmt Out_lf_fmt;

#endif /* MAIN_H */
