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
 * attach_probes.c -- attach_probes() function
 */

#include <assert.h>
#include <string.h>

#include <bcc/bpf_common.h>

#include "vltrace.h"
#include "utils.h"
#include "bpf_ctx.h"
#include "attach_probes.h"
#include "ebpf_syscalls.h"

enum { HANDLER_NAME_MAX_SIZE = 128 };

static void
print_kprobe_name(char *str, size_t size, const char *name)
{
	int res;

	res = snprintf(str, size, "kprobe__%s", name);

	assert(res > 0);
	(void) res;
}

static void
print_kretprobe_name(char *str, size_t size, const char *name)
{
	int res;

	res = snprintf(str, size, "kretprobe__%s", name);

	assert(res > 0);
	(void) res;
}

static int
attach_single_sc(struct bpf_ctx *b, const char *handler_name)
{
	int res = -1;
	char kprobe[HANDLER_NAME_MAX_SIZE];
	char kretprobe[HANDLER_NAME_MAX_SIZE];

	if (NULL == handler_name)
		return -1;

	print_kprobe_name(kprobe, sizeof(kprobe),
		handler_name);

	print_kretprobe_name(kretprobe, sizeof(kretprobe),
		handler_name);

	/* KRetProbe should be first to prevent race condition */
	res = load_fn_and_attach_to_kretp(b,
			handler_name, kretprobe,
			Args.pid, 0, -1);

	if (res == -1) {
		NOTICE("%s: Can't attach %s to '%s'. Ignoring.",
			__func__, kretprobe, handler_name);

		/* Kretprobe fails. There is no reason to try probe */
		return res;
	}

	res = load_fn_and_attach_to_kp(b, handler_name,
			kprobe,
			Args.pid, 0, -1);

	if (res == -1) {
		NOTICE("%s: Can't attach %s to '%s'. Ignoring.",
			__func__, kprobe, handler_name);
	}

	return res;
}

static int
attach_single_sc_enter(struct bpf_ctx *b, const char *handler)
{
	int res = -1;
	char kprobe[HANDLER_NAME_MAX_SIZE];

	if (NULL == handler)
		return -1;

	print_kprobe_name(kprobe, sizeof(kprobe), handler);

	res = load_fn_and_attach_to_kp(b, handler, kprobe, Args.pid, 0, -1);
	if (res == -1) {
		ERROR("%s: Can't attach %s to '%s'", __func__, kprobe, handler);
	}

	return res;
}

/* XXX HACK: this syscall is exported by kernel twice. */
static unsigned SyS_sigsuspend = 0;

/*
 * attach_kp_kern -- attach eBPF handler to all syscalls in running kernel
 */
static bool
attach_kp_kern(struct bpf_ctx *b, int (*attach)(struct bpf_ctx *, const char *))
{
	unsigned counter = 0;

	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	FILE *in = fopen(Debug_tracing_aff, "r");

	if (NULL == in) {
		ERROR("%s: '%m'", __func__);
		return false;
	}

	while ((read = getline(&line, &len, in)) != -1) {
		int res;

		if (!is_a_sc(line, read - 1))
			continue;

		line [read - 1] = '\0';

		/* XXX HACK: this syscall is exported by kernel twice. */
		if (!strcasecmp("SyS_sigsuspend", line)) {
			if (SyS_sigsuspend)
				continue;

			SyS_sigsuspend ++;
		}

		res = (*attach)(b, line);

		if (res >= 0)
			counter ++;
	}

	free(line);
	fclose(in);

	return counter > 0;
}

/*
 * attach_kp_all -- attach eBPF handler to all existing
 *                       syscalls in running kernel.
 */
static bool
attach_kp_all(struct bpf_ctx *b)
{
	return attach_kp_kern(b, attach_single_sc);
}

/*
 * attach_kp_all_enter -- attach eBPF handler to entry of all existing
 *                             syscalls in running kernel.
 */
static bool
attach_kp_all_enter(struct bpf_ctx *b)
{
	return attach_kp_kern(b, attach_single_sc_enter);
}

/*
 * attach_kp_mask -- attach eBPF handler to each syscall that matches the mask
 */
static int
attach_kp_mask(struct bpf_ctx *b, unsigned mask)
{
	unsigned counter = 0;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		int res;

		if (NULL == Syscall_array[i].handler_name)
			continue;

		if ((mask & Syscall_array[i].mask) == 0)
			continue;

		res = attach_single_sc(b, Syscall_array[i].handler_name);

		if (res >= 0)
			counter ++;
	}

	return counter;
}

static const char tp_all_category[] = "raw_syscalls";
static const char tp_all_enter_name[] = "sys_enter";
static const char tp_all_exit_name[]  = "sys_exit";
static const char tp_all_enter_fn[] = "tracepoint__sys_enter";
static const char tp_all_exit_fn[]  = "tracepoint__sys_exit";

/*
 * attach_tp_exit -- intercept raw syscall sys_exit using TracePoints.
 *
 * Should be faster and better but requires kernel >= v4.7
 *
 */
static bool
attach_tp_exit(struct bpf_ctx *b)
{
	int res;

	res = load_fn_and_attach_to_tp(b, tp_all_category, tp_all_exit_name,
					tp_all_exit_fn, Args.pid, 0, -1);
	if (res == -1) {
		ERROR("%s: Can't attach %s to '%s:%s'. Exiting.",
			__func__, tp_all_exit_fn,
			tp_all_category, tp_all_exit_name);
		return false;
	}

	return true;
}

/*
 * attach_tp_all -- intercept all syscalls using TracePoints.
 *
 * Should be faster and better but requires kernel >= v4.7
 *
 */
static bool
attach_tp_all(struct bpf_ctx *b)
{
	int res;

	/* 'sys_exit' should be first to prevent race condition */
	res = load_fn_and_attach_to_tp(b, tp_all_category, tp_all_exit_name,
					tp_all_exit_fn, Args.pid, 0, -1);

	if (res == -1) {
		ERROR("%s: Can't attach %s to '%s:%s'. Exiting.",
			__func__, tp_all_exit_fn,
			tp_all_category, tp_all_exit_name);

		return false;
	}

	res = load_fn_and_attach_to_tp(b, tp_all_category, tp_all_enter_name,
			tp_all_enter_fn, Args.pid, 0, -1);

	if (res == -1) {
		NOTICE("%s: Can't attach %s to '%s:%s'. Ignoring.",
			__func__, tp_all_enter_fn,
			tp_all_category, tp_all_enter_name);
	}

	return true;
}

/*
 * attach_all_kp_tp -- intercept all syscalls using kprobes and tracepoints
 *
 * Requires kernel >= v4.7
 *
 */
static bool
attach_all_kp_tp(struct bpf_ctx *b)
{
	bool res = attach_kp_all_enter(b);

	if (res)
		res = attach_tp_exit(b);

	return res;
}

/*
 * attach_probes -- parse and processe expression
 *
 * XXX Think about applying 'fn_name' via str_replace_all()
 *     to be more consistent
 */
bool
attach_probes(struct bpf_ctx *b)
{
	if (NULL == Args.expr)
		goto default_option;

	if (!strcasecmp(Args.expr, "trace=all")) {
		return attach_all_kp_tp(b);
	} else if (!strcasecmp(Args.expr, "trace=kp-all")) {
		return attach_kp_all(b);
	} else if (!strcasecmp(Args.expr, "trace=kp-file")) {
		return attach_kp_mask(b, EM_file);
	} else if (!strcasecmp(Args.expr, "trace=kp-desc")) {
		return attach_kp_mask(b, EM_desc);
	} else if (!strcasecmp(Args.expr, "trace=kp-fileio")) {
		return attach_kp_mask(b, EM_str_1 | EM_str_2 | EM_fd_1);
	} else if (!strcasecmp(Args.expr, "trace=tp-all")) {
		return attach_tp_all(b);
	} else {
		ERROR("%s: unknown option: '%s'", __func__, Args.expr);
		return false;
	}

default_option:
	return attach_all_kp_tp(b);
}
