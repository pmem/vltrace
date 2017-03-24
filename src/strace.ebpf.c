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
 * strace.ebpf.c -- trace syscalls using eBPF linux kernel feature
 */

#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include <linux/sched.h>
#include <linux/limits.h>

#include <bcc/libbpf.h>
#include <bcc/bpf_common.h>
#include <bcc/perf_reader.h>

#include "strace.ebpf.h"
#include "bpf_ctx.h"
#include "txt.h"
#include "utils.h"
#include "cl_parser.h"
#include "attach_probes.h"
#include "ebpf_syscalls.h"
#include "generate_ebpf.h"
#include "print_event_cb.h"
#include "ebpf/ebpf_file_set.h"

struct cl_options Args;		/* command-line arguments */
FILE *Out_lf;			/* output file */
enum out_lf_fmt Out_lf_fmt;	/* format of output */
int OutputError;		/* I/O error in perf callback occured */
int AbortTracing;		/* terminating signal received */

int
main(const int argc, char *const argv[])
{
	int tracing_PID = 0;
	int st_optind;

	Args.pid = -1;
	Args.out_lf_fld_sep_ch = ' ';

	/* XXX set using command-line options */
	Args.pr_arr_max = 1000;

	/* XXX set using command-line options */
	Args.out_buf_size = OUT_BUF_SIZE;

	/* enlarge ring buffers	- XXX set using command-line options */
	Args.strace_reader_page_cnt = STRACE_READER_PAGE_CNT_DEFAULT;

	/* parse command-line options */
	st_optind = cl_parser(&Args, argc, argv);

	if (Args.command && Args.pid > 0) {
		fprintf(stderr, "ERROR: command and PID cannot be set together."
			" Exiting.\n");
		fprint_help(stderr);
		exit(EXIT_FAILURE);
	}

	setup_out_lf();
	if (NULL == Out_lf) {
		fprintf(stderr, "ERROR: failed to set up the output file. "
				"Exiting\n");
		exit(errno);
	}

	/* check JIT acceleration of BPF */
	check_bpf_jit_status(stderr);

	if (Args.ff_mode) { /* only in follow-fork mode */
		/*
		 * Set the "child subreaper" attribute to be able
		 * to wait for all children and grandchildren.
		 */
		if (prctl(PR_SET_CHILD_SUBREAPER, 1) == -1) {
			fprintf(stderr, "ERROR: failed to set the 'child "
					"subreaper' attribute. Exiting\n");
			exit(errno);
		}
	}

	if (Args.command) {
		/* run the command */
		Args.pid = start_command_with_signals(argc - st_optind,
							argv + st_optind);
		if (Args.pid == -1) {
			fprintf(stderr, "ERROR: failed to start the command. "
					"Exiting.\n");
			exit(errno);
		}
	} else if (Args.pid > 0) {
		/* check if process with given PID exists */
		if (kill(Args.pid, 0) == -1) {
			fprintf(stderr,	"ERROR: process with PID '%d'"
					" does not exist: '%m'.\n", Args.pid);
			exit(errno);
		} else {
			tracing_PID = 1;
		}

	}

	/* init array of syscalls */
	init_sc_tbl();

	/* generate BPF program */
	char *bpf_str = generate_ebpf();

	apply_process_attach_code(&bpf_str);

	/* simulate preprocessor, because it's safer */
	apply_trace_h_header(&bpf_str);

	/* print resulting code in debug mode */
	if (Args.debug)
		fprint_ebpf_code_with_debug_marks(stderr, bpf_str);

	/* XXX should be done only by user request */
	save_trace_h();

	/* initialize BPF */
	struct bpf_ctx *b = calloc(1, sizeof(*b));
	if (b == NULL) {
		fprintf(stderr, "ERROR: out of memory. Exiting.\n");
		return EXIT_FAILURE;
	}

	/* compile generated eBPF code */
	b->module = bpf_module_create_c_from_string(bpf_str, 0, NULL, 0);
	b->debug  = Args.debug;

	free(bpf_str);

	if (!attach_probes(b)) {
		/* no probes were attached */
		fprintf(stderr, "ERROR: no probes were attached. Exiting.\n");
		if (Args.command) {
			/* kill the started child */
			kill(Args.pid, SIGKILL);
		}
		return EXIT_FAILURE;
	}

	/* header */
	Print_header[Out_lf_fmt](argc, argv);

	/*
	 * Attach callback to perf output. "events" is a name of class declared
	 * with BPF_PERF_OUTPUT() in ebpf/trace_head.c.
	 *
	 * XXX We should use str_replace here.
	 */
#define PERF_OUTPUT_NAME "events"
	int res = attach_callback_to_perf_output(b, PERF_OUTPUT_NAME,
						Print_event_cb[Out_lf_fmt]);
	if (res == 0) {
		if (Args.command) {
			/* let child go */
			kill(Args.pid, SIGCONT);
		}
	} else {
		fprintf(stderr, "ERROR: can't attach callbacks to perf output"
				" '%s'. Exiting.\n", PERF_OUTPUT_NAME);
		if (Args.command) {
			/* kill the started child */
			kill(Args.pid, SIGKILL);
		}
		detach_all(b);
		return EXIT_FAILURE;
	}

	struct perf_reader *readers[b->pr_arr_qty];

	for (unsigned i = 0; i < b->pr_arr_qty; i++)
		readers[i] = b->pr_arr[i]->pr;

	/* trace until all children exit */
	while ((waitpid(-1, NULL, WNOHANG) != -1) || (errno != ECHILD)) {

		(void) perf_reader_poll((int)b->pr_arr_qty, readers, -1);

		/* check if the process traced by PID exists */
		if (tracing_PID && kill(Args.pid, 0) == -1) {
			fprintf(stderr, "ERROR: traced process with PID '%d'"
					" disappeared : '%m'.\n", Args.pid);
				break;
		}

		if (OutputError) {
			fprintf(stderr, "ERROR: error writing output. "
					"Exiting...\n");
			break;
		}

		if (AbortTracing) {
			fprintf(stderr, "Notice: terminated by signal. "
					"Exiting...\n");
			break;
		}
	}

	detach_all(b);

	return EXIT_SUCCESS;
}
