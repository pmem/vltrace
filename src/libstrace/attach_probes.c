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
 * attach_probes.c -- attach_probes() function
 */

#include <string.h>

#include <bcc/bpf_common.h>

#include "bpf.h"
#include "main.h"
#include "utils.h"
#include "attach_probes.h"
#include "ebpf_syscalls.h"

enum { HANDLER_NAME_MAX_SIZE = 128 };

/*
 * This function attaches eBPF handler to each syscall known to libc.
 *
 * It can be useful because kernel has a lot of "unused" syscalls.
 */
static bool
attach_kp_libc_all(struct bpf_ctx *b)
{
	unsigned succ_counter = 0;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		int res;
		char kprobe[HANDLER_NAME_MAX_SIZE];
		char kretprobe[HANDLER_NAME_MAX_SIZE];

		if (NULL == sc_tbl[i].hlr_name)
			continue;

		snprintf(kprobe, sizeof(kprobe),
			"kprobe__%s",
			sc_tbl[i].hlr_name);

		snprintf(kretprobe, sizeof(kretprobe),
			"kretprobe__%s",
			sc_tbl[i].hlr_name);

		/* KRetProbe should be first to prevent race condition */
		res = load_fn_and_attach_to_kretp(b,
				sc_tbl[i].hlr_name, kretprobe,
				args.pid, 0, -1);

		if (res == -1) {
			fprintf(stderr,
				"ERROR:%s:Can't attach %s to '%s'. Ignoring.\n",
				__func__, kretprobe, sc_tbl[i].hlr_name);

			/* Kretprobe fails. There is no reason to try probe */
			continue;
		}

		res = load_fn_and_attach_to_kp(b, sc_tbl[i].hlr_name, kprobe,
				args.pid, 0, -1);

		if (res == -1) {
			fprintf(stderr,
				"ERROR:%s:Can't attach %s to '%s'. Ignoring.\n",
				__func__, kprobe, sc_tbl[i].hlr_name);

			continue;
		}

		succ_counter ++;
	}

	return succ_counter > 0;
}

/* XXX HACK: this syscall is exported by kernel twice. */
static unsigned SyS_sigsuspend = 0;

/*
 * This function attaches eBPF handler to all existing syscalls in running
 * kernel. It consume more time than attach_kp_libc_all().
 */
static bool
attach_kp_kern_all(struct bpf_ctx *b)
{
	unsigned succ_counter = 0;

	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	FILE *in = fopen(debug_tracing_aff, "r");

	if (NULL == in) {
		fprintf(stderr, "%s: ERROR: '%m'\n", __func__);
		return false;
	}

	while ((read = getline(&line, &len, in)) != -1) {
		int res;
		char kprobe[HANDLER_NAME_MAX_SIZE];
		char kretprobe[HANDLER_NAME_MAX_SIZE];

		if (!is_a_sc(line, read - 1))
			continue;

		line [read - 1] = '\0';

		/* XXX HACK: this syscall is exported by kernel twice. */
		if (!strcasecmp("SyS_sigsuspend", line)) {
			if (SyS_sigsuspend)
				continue;

			SyS_sigsuspend ++;
		}

		snprintf(kprobe, sizeof(kprobe),
			"kprobe__%s", line);

		snprintf(kretprobe, sizeof(kretprobe),
			"kretprobe__%s", line);

		/* KRetProbe should be first to prevent race condition */
		res = load_fn_and_attach_to_kretp(b, line, kretprobe,
				args.pid, 0, -1);

		if (res == -1) {
			fprintf(stderr,
				"ERROR:%s:Can't attach %s to '%s'. Ignoring.\n",
				__func__, kretprobe, line);

			/* Kretprobe fails. There is no reason to try probe */
			continue;
		}

		res = load_fn_and_attach_to_kp(b, line, kprobe,
				args.pid, 0, -1);

		if (res == -1) {
			fprintf(stderr,
				"ERROR:%s:Can't attach %s to '%s'. Ignoring.\n",
				__func__, kprobe, line);

			continue;
		}

		succ_counter ++;
	}

	free(line);
	fclose(in);

	return succ_counter > 0;
}

/*
 * This function attaches eBPF handler to each syscall which operates on file
 * descriptor. Inspired by: 'strace -e trace=desc'
 */
static bool
attach_kp_desc(struct bpf_ctx *b)
{
	unsigned succ_counter = 0;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		int res;
		char kprobe[HANDLER_NAME_MAX_SIZE];
		char kretprobe[HANDLER_NAME_MAX_SIZE];

		if (NULL == sc_tbl[i].hlr_name)
			continue;

		if (EM_desc != (EM_desc & sc_tbl[i].masks))
			continue;

		snprintf(kprobe, sizeof(kprobe),
			"kprobe__%s",
			sc_tbl[i].hlr_name);

		snprintf(kretprobe, sizeof(kretprobe),
			"kretprobe__%s",
			sc_tbl[i].hlr_name);

		/* KRetProbe should be first to prevent race condition */
		res = load_fn_and_attach_to_kretp(b,
				sc_tbl[i].hlr_name, kretprobe,
				args.pid, 0, -1);

		if (res == -1) {
			fprintf(stderr,
				"ERROR:%s:Can't attach %s to '%s'. Ignoring.\n",
				__func__, kretprobe, sc_tbl[i].hlr_name);

			/* Kretprobe fails. There is no reason to try probe */
			continue;
		}

		res = load_fn_and_attach_to_kp(b, sc_tbl[i].hlr_name, kprobe,
				args.pid, 0, -1);

		if (res == -1) {
			fprintf(stderr,
				"ERROR:%s:Can't attach %s to '%s'. Ignoring.\n",
				__func__, kprobe, sc_tbl[i].hlr_name);

			continue;
		}

		succ_counter ++;
	}

	return succ_counter > 0;
}

/*
 * This function attaches eBPF handler to each syscall which operates on
 * filenames. Inspired by 'strace -e trace=file'.
 */
static bool
attach_kp_file(struct bpf_ctx *b)
{
	unsigned succ_counter = 0;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		int res;
		char kprobe[HANDLER_NAME_MAX_SIZE];
		char kretprobe[HANDLER_NAME_MAX_SIZE];

		if (NULL == sc_tbl[i].hlr_name)
			continue;

		if (EM_file != (EM_file & sc_tbl[i].masks))
			continue;

		snprintf(kprobe, sizeof(kprobe),
			"kprobe__%s",
			sc_tbl[i].hlr_name);

		snprintf(kretprobe, sizeof(kretprobe),
			"kretprobe__%s",
			sc_tbl[i].hlr_name);

		/* KRetProbe should be first to prevent race condition */
		res = load_fn_and_attach_to_kretp(b,
				sc_tbl[i].hlr_name, kretprobe,
				args.pid, 0, -1);

		if (res == -1) {
			fprintf(stderr,
				"ERROR:%s:Can't attach %s to '%s'. Ignoring.\n",
				__func__, kretprobe, sc_tbl[i].hlr_name);

			/* Kretprobe fails. There is no reason to try probe */
			continue;
		}

		res = load_fn_and_attach_to_kp(b, sc_tbl[i].hlr_name, kprobe,
				args.pid, 0, -1);

		if (res == -1) {
			fprintf(stderr,
				"ERROR:%s:Can't attach %s to '%s'. Ignoring.\n",
				__func__, kprobe, sc_tbl[i].hlr_name);

			continue;
		}

		succ_counter ++;
	}

	return succ_counter > 0;
}

/*
 * This function attaches eBPF handler to each syscall which operates on
 * relative file path. There are no equivalents in strace.
 */
static bool
attach_kp_fileat(struct bpf_ctx *b)
{
	unsigned succ_counter = 0;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		int res;
		char kprobe[HANDLER_NAME_MAX_SIZE];
		char kretprobe[HANDLER_NAME_MAX_SIZE];

		if (NULL == sc_tbl[i].hlr_name)
			continue;

		if (EM_fileat != (EM_fileat & sc_tbl[i].masks))
			continue;

		snprintf(kprobe, sizeof(kprobe),
			"kprobe__%s",
			sc_tbl[i].hlr_name);

		snprintf(kretprobe, sizeof(kretprobe),
			"kretprobe__%s",
			sc_tbl[i].hlr_name);

		/* KRetProbe should be first to prevent race condition */
		res = load_fn_and_attach_to_kretp(b,
				sc_tbl[i].hlr_name, kretprobe,
				args.pid, 0, -1);

		if (res == -1) {
			fprintf(stderr,
				"ERROR:%s:Can't attach %s to '%s'. Ignoring.\n",
				__func__, kretprobe, sc_tbl[i].hlr_name);

			/* Kretprobe fails. There is no reason to try probe */
			continue;
		}

		res = load_fn_and_attach_to_kp(b, sc_tbl[i].hlr_name, kprobe,
				args.pid, 0, -1);

		if (res == -1) {
			fprintf(stderr,
				"ERROR:%s:Can't attach %s to '%s'. Ignoring.\n",
				__func__, kprobe, sc_tbl[i].hlr_name);

			continue;
		}

		succ_counter ++;
	}

	return succ_counter > 0;
}

/*
 * Attach eBPF handlers to all file-related syscalls. Inspired by:
 * 'strace -e trace=desc,file'
 */
static bool
attach_kp_pmemfile(struct bpf_ctx *b)
{
	bool res = false;

	res |= attach_kp_desc(b);
	res |= attach_kp_file(b);
	res |= attach_kp_fileat(b);

	return res;
}

static const char tp_all_category[] = "raw_syscalls";
static const char tp_all_enter_name[] = "sys_enter";
static const char tp_all_exit_name[]  = "sys_exit";
static const char tp_all_enter_fn[] = "tracepoint__sys_enter";
static const char tp_all_exit_fn[]  = "tracepoint__sys_exit";

/*
 * Intercept all syscalls of running kernel using TracePoint way.
 * Should be faster and better but require at kernel at least 4.6.
 *
 * XXX Not tested.
 */
static bool
attach_tp_all(struct bpf_ctx *b)
{
	int res;

	/* 'sys_exit' should be first to prevent race condition */
	res = load_fn_and_attach_to_tp(b, tp_all_category, tp_all_enter_name,
			tp_all_enter_fn, args.pid, 0, -1);

	if (res == -1) {
		fprintf(stderr,
			"ERROR:%s:Can't attach %s to '%s:%s'. Exiting.\n",
			__func__, tp_all_enter_fn,
			tp_all_category, tp_all_enter_name);

		/* Tracepoint fails. There is no reason to try continue */
		return false;
	}

	res = load_fn_and_attach_to_tp(b, tp_all_category, tp_all_exit_name,
			tp_all_exit_fn, args.pid, 0, -1);

	if (res == -1) {
		fprintf(stderr,
			"ERROR:%s:Can't attach %s to '%s:%s'. Ignoring.\n",
			__func__, tp_all_exit_fn,
			tp_all_category, tp_all_exit_name);
	}

	return true;
}

/*
 * This function parses and processes expression.
 *
 * XXX Think about applying 'fn_name' via str_replace_all()
 *     to be more consistent
 */
bool
attach_probes(struct bpf_ctx *b)
{
	if (NULL == args.expr)
		goto DeFault;

	if (!strcasecmp(args.expr, "trace=kp-libc-all")) {
		return attach_kp_libc_all(b);
	} else if (!strcasecmp(args.expr, "trace=kp-kern-all")) {
		return attach_kp_kern_all(b);
	} else if (!strcasecmp(args.expr, "trace=kp-file")) {
		return attach_kp_file(b);
	} else if (!strcasecmp(args.expr, "trace=kp-desc")) {
		return attach_kp_desc(b);
	} else if (!strcasecmp(args.expr, "trace=kp-pmemfile")) {
		return attach_kp_pmemfile(b);
	} else if (!strcasecmp(args.expr, "trace=tp-all")) {
		return attach_tp_all(b);
	}

DeFault:
	return attach_kp_kern_all(b);
}
