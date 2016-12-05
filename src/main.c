/*
 * Copyright 2016, Intel Corporation
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
 * main.c -- Trace syscalls. For Linux, uses BCC, ebpf.
 */

#include <errno.h>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <sys/types.h>

#include <linux/sched.h>
#include <linux/limits.h>

/* from bcc import BPF */
#include <bcc/libbpf.h>
#include <bcc/bpf_common.h>
#include <bcc/perf_reader.h>

#include "bpf.h"

#include "main.h"
#include "utils.h"
#include "attach_probes.h"
#include "ebpf_syscalls.h"
#include "generate_ebpf.h"
#include "print_event_cb.h"

static const char help_text[] = "\
\n\
Run the specified command and trace syscalls.\n\
\n\
USAGE:\n\
\tstrace.ebpf [-h] [-t] [-X] [-p PID] [command [arg ...]]\n\
\n\
\t-t, --timestamp include timestamp in output\n\
\t-X, --failed    only show failed syscalls\n\
\t-d, --debug     enable debug output\n\
\t-p, --pid       trace this PID only. Command arg should be missing\n\
\t-o, --output    filename\n\
\t-l, --format    output logs format. Possible values:\n\
\t                    'bin', 'binary', 'hex', 'strace', 'list' & 'help'.\n\
\t                    'bin'/'binary' file format is described in trace.h.\n\
\t                Default: 'hex'\n\
\t-K, --hex-separator\n\
\t                set field separator for hex logs. Default is '\\t'.\n\
\t-e, --expr      expression, 'help' or 'list' for supported list.\n\
\t                Default: trace=kp-kern-all.\n\
\t-L, --list      Print a list of all traceable syscalls\n\
\t                of the running kernel.\n\
\t-R, --ll-list   Print a list of all traceable low-level funcs\n\
\t                of the running kernel.\n\
\t                WARNING: really long. ~45000 functions.\n\
\t-b, --builtin-list\n\
\t                Print a list of all syscalls known by glibc.\n\
\t-h, --help      print help\n\
\n\
examples:\n\
    ./strace.ebpf -l hex           # trace all syscalls in the system\n\
    ./strace.ebpf -l hex ls        # trace syscalls of ls command\n\
    ./strace.ebpf -l hex -t ls     # include timestamps\n\
    ./strace.ebpf -l hex -X ls     # only show failed syscalls\n\
    ./strace.ebpf -l hex -p 342    # only trace PID 342\n\
\n\
WARNING: System-wide tracing can fillout your disk really fast.\n\
";

static const char trace_list_text[] = "\
List of supported sets:\n"
	" * Help:\n"
	"\t - 'help', 'list'    This list.\n"
	"\n"
	" * Intercepting using KProbe:\n"
	"\t - 'kp-pmemfile'        PMemFile - actual SCs\n"
	"\t - 'kp-file'            SCs with path in args\n"
	"\t - 'kp-desc'            SCs with fdesd in args\n"
	"\t - 'kp-kern-all'        All syscalls provided by kernel.\n"
	"\t -                      A bit slower.\n"
	"\t - 'kp-libc-all'        All syscalls provided by glibc.\n"
	"\t                        This list is 36%% shorter\n"
	"\t                        than previous and loads faster.\n"
	"\t - 'kp-sc_glob:*'       Choose SCs by glob pattern, such as 'set*'\n"
	"\t - 'kp-sc_re:.*'        Choose SCs by re pattern, such as 'set.*'\n"
	"\t - 'kp-raw_glob:*'      Choose low-level funcs by glob pattern,\n"
	"\t                        such as 'raw_glob:ext4_*'\n"
	"\t - 'kp-raw_re:.*'       Choose low-level funcs by re pattern,\n"
	"\t                        such as 'raw_glob:ext4_*'\n"
	"\t - 'kp-XXXX'            Choose exact single SC by name,\n"
	"\t                        such as 'open'\n"
	"\t - 'kp-raw:XXXX'        Choose exact single low-level func by\n"
	"\t                        name, such as 'raw:ext4_mkdir'\n"
	"\n"
	" * Intercepting using TracePoints:\n"
	"   Currently malfunctions because of this bug:\n"
	"   https://github.com/iovisor/bcc/issues/748\n"
	"\t - 'tp-all'             All syscalls provided by kernel.\n"
	"\t                        This option starts many times faster than\n"
	"\t                        corresponding kprobe ones, but can eat\n"
	"\t                        more of CPU resource.\n"
	"\n";

/*
 * This function prints help message in stream.
 */
static void
fprint_help(FILE *f)
{
	fwrite(help_text, sizeof(help_text)-1, 1, f);
}

/*
 * This function prints description of expressions in stream.
 */
static void
fprint_trace_list(FILE *f)
{
	fwrite(trace_list_text, sizeof(trace_list_text)-1, 1, f);
}

struct args_t args;
bool cont = true;
FILE *out;
enum out_fmt out_fmt;

/* HACK Should be fixed in libbcc */
extern int perf_reader_page_cnt;

/* 8 Megabytes should be something close to reasonable */
static unsigned out_buf_size = 8 * 1024 * 1024;

/*
 * Tool's entry point
 */
int
main(int argc, char *argv[])
{
	args.pid = -1;
	args.out_sep_ch = '\t';

	/*
	 * XXX Should be set by cl options
	 *    if we need something over syscalls
	 */
	args.pr_arr_max = 1000;

	/*
	 * XXX Let's enlarge ring buffers. It's really improve situation
	 *    with lost events. In the future we should do it via cl options.
	 */
	perf_reader_page_cnt *= perf_reader_page_cnt;
	perf_reader_page_cnt *= perf_reader_page_cnt;

	while (1) {
		int c;
		int option_index = 0;

		static struct option long_options[] = {
			{"timestamp",	no_argument,	   0, 't'},
			{"failed",		no_argument,	   0, 'X'},
			{"help",		no_argument,	   0, 'h'},
			{"debug",		no_argument,	   0, 'd'},
			{"list",		no_argument,	   0, 'L'},
			{"ll-list",		no_argument,	   0, 'R'},
			{"builtin-list", no_argument,	   0, 'b'},

			{"pid",		   required_argument, 0, 'p'},
			{"format",		required_argument, 0, 'l'},
			{"expr",		required_argument, 0, 'e'},
			{"output",		required_argument, 0, 'o'},
			{"hex-separator", required_argument, 0, 'K'},
			{0,	   0,	 0,  0 }
		};

		c = getopt_long(argc, argv, "+tXhdp:o:l:K:e:LRb",
				long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
			case 't':
				args.timestamp = true;
				break;

			case 'X':
				args.failed = true;
				break;

			case 'h':
				fprint_help(stdout);
				exit(EXIT_SUCCESS);

			case 'd':
				args.debug = true;
				break;

			case 'p':
				args.pid = atoi(optarg);
				break;

			case 'o':
				args.out_fn = optarg;
				break;

			case 'K':
				args.out_sep_ch = *optarg;
				break;

			case 'e':
				if (!strcasecmp(optarg, "list") ||
						!strcasecmp(optarg, "help")) {
					fprintf(stderr,
						"List of supported expressions:"
						" 'help', 'list', 'trace=set'"
						"\n");
					exit(EXIT_SUCCESS);
				} else if (!strcasecmp(optarg, "trace=help") ||
						!strcasecmp(optarg,
							"trace=list")) {
					fprint_trace_list(stderr);
					fprintf(stderr,
						"You can combine sets"
						" by using comma.\n");
					exit(EXIT_SUCCESS);
				}
				args.expr = optarg;
				break;

			case 'l':
				if (!strcasecmp(optarg, "list") ||
						!strcasecmp(optarg, "help")) {
					fprintf(stderr,
						"List of supported expressions:"
						"'bin', 'binary', 'hex', "
						"'strace', 'list' & 'help'\n");
					exit(EXIT_SUCCESS);
				}
				args.out_fmt_str = optarg;
				out_fmt = out_fmt_str2enum(args.out_fmt_str);
				break;

			case 'L':
				get_sc_list(stdout, is_a_sc);
				exit(EXIT_SUCCESS);

			case 'R':
				get_sc_list(stdout, NULL);
				exit(EXIT_SUCCESS);

			case 'b':
				for (unsigned i = 0; i < SC_TBL_SIZE; i++)
					if (NULL != sc_tbl[i].hlr_name)
						fprintf(stdout,
							"%03d: %-20s\t %s\n",
							sc_tbl[i].num,
							sc_tbl[i].num_name,
							sc_tbl[i].hlr_name);
				exit(EXIT_SUCCESS);

			case ':':
				fprintf(stderr, "ERROR: "
					"Missing mandatory option's "
					"argument\n");
				fprint_help(stderr);
				exit(EXIT_FAILURE);

			default:
				fprintf(stderr, "ERROR: "
					"Unknown option: '-%c'\n", c);
			case '?':
				fprint_help(stderr);
				exit(EXIT_FAILURE);
		}
	}

	if (optind < argc)
		args.command = true;

	/* Check for JIT acceleration of BPF */
	check_bpf_jit_status(stderr);

	if (NULL != args.out_fn) {
		out = fopen(args.out_fn, "w");

		if (NULL == out) {
			fprintf(stderr, "ERROR: "
				"Failed to open '%s' for appending: '%m'\n",
				args.out_fn);

			exit(errno);
		}
	} else {
		out = stdout;
	}

	/* XXX We should improve it. May be we should use fd directly */
	/* setbuffer(out, NULL, out_buf_size); */
	(void) out_buf_size;

	if (args.pid != -1 && args.command) {
		fprintf(stderr, "ERROR: "
				"It is currently unsupported to watch for PID"
				" and command simultaneously.\n");
		fprint_help(stderr);
		exit(EXIT_FAILURE);
	}

	if (args.command) {
		struct sigaction sa;

		args.pid = start_command(argc - optind, argv + optind);

		if (args.pid == -1) {
			fprintf(stderr, "ERROR: "
				"Failed to run: '%s': %m. Exiting.\n",
				argv[optind]);
			exit(errno);
		}

		sa.sa_sigaction = sig_chld_handler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_RESTART | SA_SIGINFO |
			SA_NOCLDSTOP | SA_NOCLDWAIT;

		(void) sigaction(SIGCHLD, &sa, NULL);

		sa.sa_sigaction = sig_transmit_handler;
		sa.sa_flags = SA_RESTART;

		(void) sigaction(SIGINT, &sa, NULL);
		(void) sigaction(SIGHUP, &sa, NULL);
		(void) sigaction(SIGQUIT, &sa, NULL);
		(void) sigaction(SIGTERM, &sa, NULL);

		sa.sa_flags = (int)(SA_RESTART | SA_RESETHAND);
		(void) sigaction(SIGSEGV, &sa, NULL);
	}

	/* define BPF program */
	char *bpf_str = generate_ebpf();

	if (0 < args.pid) {
		char str[128];

		snprintf(str, sizeof(str),
				"if ((pid_tid >> 32) != %d) { return 0; }",
				args.pid);

		str_replace_all(&bpf_str, "PID_CHECK_HOOK", str);

		if (!args.command) {
			if (kill(args.pid, 0) == -1) {
				fprintf(stderr,
					"ERROR: Process with pid '%d'"
					" does not exist: '%m'.\n", args.pid);

				exit(errno);
			}
		}
	} else {
		str_replace_all(&bpf_str, "PID_CHECK_HOOK", "");
	}

	char *trace_h = load_file(ebpf_trace_h_file);

	str_replace_all(&bpf_str, "#include \"trace.h\"\n", trace_h);

	free(trace_h);

	if (args.debug) {
		fprintf(stderr, "\t>>>>> Generated eBPF code <<<<<\n");

		if (bpf_str)
			fwrite(bpf_str, strlen(bpf_str), 1, stderr);

		fprintf(stderr, "\t>>>>> EndOf generated eBPF code <<<<<<\n");
	}

	save_trace_h();

	/* initialize BPF */
	struct bpf_ctx *b = calloc(1, sizeof(*b));

	/* Compiling of generated eBPF code */
	b->module = bpf_module_create_c_from_string(bpf_str, 0, NULL, 0);
	b->debug  = args.debug;

	free(bpf_str);

	if (!attach_probes(b)) {
		/* No probes were attached */
		fprintf(stderr,
			"ERROR: No probes were attached. Exiting.\n");

		if (args.command) {
			/* let's KILL child */
			kill(args.pid, SIGKILL);
		}

		return EXIT_FAILURE;
	}

	/* header */
	print_header[out_fmt](argc, argv);

	/*
	 * Attach callback to perf output. "events" is a name of class declared
	 * with BPF_PERF_OUTPUT() in trace.c.
	 *
	 * XXX Most likely we should utilise here str_replace for consistence
	 *    increasing.
	 */
#define PERF_OUTPUT_NAME "events"
	int res = attach_callback_to_perf_output(b,
			PERF_OUTPUT_NAME, print_event_cb[out_fmt]);

	if (!res) {
		if (args.command) {
			/* let's child go */
			kill(args.pid, SIGCONT);
		}
	} else {
		fprintf(stderr,
			"ERROR: Can't attach to perf output '%s'. Exiting.\n",
			PERF_OUTPUT_NAME);

		if (args.command) {
			/* let's KILL child */
			kill(args.pid, SIGKILL);
		}

		detach_all(b);
		return EXIT_FAILURE;
	}

	struct perf_reader *readers[b->pr_arr_qty];

	for (unsigned i = 0; i < b->pr_arr_qty; i++)
		readers[i] = b->pr_arr[i]->pr;

	while (cont) {
		(void) perf_reader_poll((int)b->pr_arr_qty, readers, -1);

		if (!args.command && 0 < args.pid) {
			if (kill(args.pid, 0) == -1) {
				cont = false;

				fprintf(stderr,
					"ERROR: Process with pid '%d'"
					" has disappeared : '%m'.\n",
					args.pid);

				fprintf(stderr, "Exit.\n");
			}
		}
	}


	detach_all(b);
	return EXIT_SUCCESS;
}
