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

#include "strace.ebpf.h"
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
}

static void
print_kretprobe_name(char *str, size_t size, const char *name)
{
	int res;

	res = snprintf(str, size, "kretprobe__%s", name);

	assert(res > 0);
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
		fprintf(stderr,
			"ERROR:%s:Can't attach %s to '%s'. Ignoring.\n",
			__func__, kretprobe,
			handler_name);

		/* Kretprobe fails. There is no reason to try probe */
		return res;
	}

	res = load_fn_and_attach_to_kp(b, handler_name,
			kprobe,
			Args.pid, 0, -1);

	if (res == -1) {
		fprintf(stderr,
			"ERROR:%s:Can't attach %s to '%s'. Ignoring.\n",
			__func__, kprobe,
			handler_name);
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
		fprintf(stderr, "ERROR:%s:Can't attach %s to '%s'.\n",
				__func__, kprobe, handler);
	}

	return res;
}

/*
 * attach_kp_libc_all -- This function attaches eBPF handler to each syscall
 *     known to libc.
 *
 * It can be useful because kernel has a lot of "unused" syscalls.
 */
static bool
attach_kp_libc_all(struct bpf_ctx *b)
{
	unsigned succ_counter = 0;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		int res;

		res = attach_single_sc(b, Syscall_array[i].handler_name);

		if (res >= 0)
			succ_counter++;
	}

	return succ_counter > 0;
}

/* XXX HACK: this syscall is exported by kernel twice. */
static unsigned SyS_sigsuspend = 0;

/*
 * attach_kp_kern -- This function attaches eBPF handler
 *                   to syscalls in running kernel.
 *
 * It consumes more time than attach_kp_libc_all().
 */
static bool
attach_kp_kern(struct bpf_ctx *b, int (*attach)(struct bpf_ctx *, const char *))
{
	unsigned succ_counter = 0;

	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	FILE *in = fopen(Debug_tracing_aff, "r");

	if (NULL == in) {
		fprintf(stderr, "%s: ERROR: '%m'\n", __func__);
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
			succ_counter ++;
	}

	free(line);
	fclose(in);

	return succ_counter > 0;
}

/*
 * attach_kp_kern_all -- This function attaches eBPF handler to all existing
 *     syscalls in running kernel.
 *
 * It consumes more time than attach_kp_libc_all().
 */
static bool
attach_kp_kern_all(struct bpf_ctx *b)
{
	return attach_kp_kern(b, attach_single_sc);
}

/*
 * attach_kp_kern_all -- This function attaches eBPF handler to all existing
 *     syscalls in running kernel.
 *
 * It consumes more time than attach_kp_libc_all().
 */
static bool
attach_kp_kern_all_enter(struct bpf_ctx *b)
{
	return attach_kp_kern(b, attach_single_sc_enter);
}

/*
 * attach_kp_desc -- This function attaches eBPF handler to each syscall which
 *     operates on file descriptor.
 *
 * Inspired by: 'strace -e trace=desc'
 */
static bool
attach_kp_desc(struct bpf_ctx *b)
{
	unsigned succ_counter = 0;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		int res;

		if (NULL == Syscall_array[i].handler_name)
			continue;

		if (EM_desc != (EM_desc & Syscall_array[i].masks))
			continue;

		res = attach_single_sc(b, Syscall_array[i].handler_name);

		if (res >= 0)
			succ_counter ++;
	}

	return succ_counter > 0;
}

/*
 * attach_kp_file -- This function attaches eBPF handler to each syscall which
 *     operates on filenames.
 *
 * Inspired by 'strace -e trace=file'.
 */
static bool
attach_kp_file(struct bpf_ctx *b)
{
	unsigned succ_counter = 0;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		int res;

		if (NULL == Syscall_array[i].handler_name)
			continue;

		if (EM_file != (EM_file & Syscall_array[i].masks))
			continue;

		res = attach_single_sc(b, Syscall_array[i].handler_name);

		if (res >= 0)
			succ_counter ++;
	}

	return succ_counter > 0;
}

/*
 * attach_kp_fileat -- This function attaches eBPF handler to each syscall
 *     which operates on relative file path.
 *
 * There are no equivalents in strace.
 */
static bool
attach_kp_fileat(struct bpf_ctx *b)
{
	unsigned succ_counter = 0;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		int res;

		if (NULL == Syscall_array[i].handler_name)
			continue;

		if (EM_fileat != (EM_fileat & Syscall_array[i].masks))
			continue;

		res = attach_single_sc(b, Syscall_array[i].handler_name);

		if (res >= 0)
			succ_counter ++;
	}

	return succ_counter > 0;
}

/*
 * attach_kp_fileio -- Attach eBPF handlers to all file-related syscalls.
 *
 * Inspired by: 'strace -e trace=desc,file'
 */
static bool
attach_kp_fileio(struct bpf_ctx *b)
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
 * attach_tp_exit -- intercept raw syscall sys_exit using TracePoints.
 *
 * Should be faster and better but requires kernel >= 4.6.
 *
 */
static bool
attach_tp_exit(struct bpf_ctx *b)
{
	int res;

	res = load_fn_and_attach_to_tp(b, tp_all_category, tp_all_exit_name,
					tp_all_exit_fn, Args.pid, 0, -1);
	if (res == -1) {
		fprintf(stderr,
			"ERROR:%s:Can't attach %s to '%s:%s'. Exiting.\n",
			__func__, tp_all_exit_fn,
			tp_all_category, tp_all_exit_name);
		return false;
	}

	return true;
}

/*
 * attach_tp_all -- Intercept all syscalls using TracePoints.
 *
 * Should be faster and better but requires kernel >= 4.6.
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
		fprintf(stderr,
			"ERROR:%s:Can't attach %s to '%s:%s'. Exiting.\n",
			__func__, tp_all_exit_fn,
			tp_all_category, tp_all_exit_name);

		return false;
	}

	res = load_fn_and_attach_to_tp(b, tp_all_category, tp_all_enter_name,
			tp_all_enter_fn, Args.pid, 0, -1);

	if (res == -1) {
		fprintf(stderr,
			"ERROR:%s:Can't attach %s to '%s:%s'. Ignoring.\n",
			__func__, tp_all_enter_fn,
			tp_all_category, tp_all_enter_name);
	}

	return true;
}

/*
 * attach_common -- intercept all syscalls using kprobes and tracepoints.
 *
 * Requires kernel >= 4.6.
 *
 */
static bool
attach_common(struct bpf_ctx *b)
{
	bool res = attach_kp_kern_all_enter(b);

	if (res)
		res = attach_tp_exit(b);

	return res;
}

/*
 * attach_probes -- This function parses and processes expression.
 *
 * XXX Think about applying 'fn_name' via str_replace_all()
 *     to be more consistent
 */
bool
attach_probes(struct bpf_ctx *b)
{
	if (NULL == Args.expr)
		goto DeFault;

	if (!strcasecmp(Args.expr, "trace=kp-libc-all")) {
		return attach_kp_libc_all(b);
	} else if (!strcasecmp(Args.expr, "trace=kp-kern-all")) {
		return attach_kp_kern_all(b);
	} else if (!strcasecmp(Args.expr, "trace=kp-file")) {
		return attach_kp_file(b);
	} else if (!strcasecmp(Args.expr, "trace=kp-desc")) {
		return attach_kp_desc(b);
	} else if (!strcasecmp(Args.expr, "trace=kp-fileio")) {
		return attach_kp_fileio(b);
	} else if (!strcasecmp(Args.expr, "trace=tp-all")) {
		return attach_tp_all(b);
	} else if (!strcasecmp(Args.expr, "trace=common")) {
		return attach_common(b);
	}

DeFault:
	return attach_kp_kern_all(b);
}
