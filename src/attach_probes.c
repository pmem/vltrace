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

typedef int (*attach_f)(struct bpf_ctx *, const char *);

enum { HANDLER_NAME_MAX_SIZE = 128 };

/*
 * print_kprobe_name -- snprintf kprobe name
 */
static void
print_kprobe_name(char *str, size_t size, const char *name)
{
	int res;

	res = snprintf(str, size, "kprobe__%s", name);

	assert(res > 0);
	(void) res;
}

/*
 * print_kretprobe_name -- snprintf kretprobe name
 */
static void
print_kretprobe_name(char *str, size_t size, const char *name)
{
	int res;

	res = snprintf(str, size, "kretprobe__%s", name);

	assert(res > 0);
	(void) res;
}

/*
 * attach_single_sc -- attach single syscall (entry and exit handlers)
 */
static int
attach_single_sc(struct bpf_ctx *b, const char *handler_name)
{
	int res = -1;
	char kprobe[HANDLER_NAME_MAX_SIZE];
	char kretprobe[HANDLER_NAME_MAX_SIZE];

	if (handler_name == NULL)
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
		NOTICE("cannot attach %s to '%s'. Ignoring.",
			kretprobe, handler_name);

		/* Kretprobe fails. There is no reason to try probe */
		return res;
	}

	res = load_fn_and_attach_to_kp(b, handler_name,
			kprobe,
			Args.pid, 0, -1);

	if (res == -1) {
		NOTICE("cannot attach %s to '%s'. Ignoring.",
			kprobe, handler_name);
	}

	return res;
}

/*
 * attach_single_sc -- attach the entry handler of a single syscall
 */
static int
attach_single_sc_enter(struct bpf_ctx *b, const char *handler)
{
	int res = -1;
	char kprobe[HANDLER_NAME_MAX_SIZE];

	if (handler == NULL)
		return -1;

	print_kprobe_name(kprobe, sizeof(kprobe), handler);

	res = load_fn_and_attach_to_kp(b, handler, kprobe, Args.pid, 0, -1);
	if (res == -1) {
		ERROR("cannot attach %s to '%s'", kprobe, handler);
	}

	return res;
}

/*
 * attach_kp_mask -- attach eBPF handler to each syscall that matches the mask
 *                   using Kprobes
 */
static int
attach_kp_mask(struct bpf_ctx *b, attach_f attach, unsigned mask)
{
	unsigned counter = 0;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		int res;

		if (!Syscall_array[i].available)
			continue;

		if (mask && ((mask & Syscall_array[i].mask) == 0))
			continue;

		res = (*attach)(b, Syscall_array[i].syscall_name);
		if (res)
			return res;
	}

	return 0;
}

static const char tp_all_category[] = "raw_syscalls";
static const char tp_all_exit_name[]  = "sys_exit";
static const char tp_all_exit_fn[]  = "tracepoint__sys_exit";

/*
 * attach_tp_exit -- attach eBPF handler to raw syscall sys_exit
 *                   using Tracepoints
 *
 * Should be faster and better but requires kernel >= v4.7
 *
 */
static int
attach_tp_exit(struct bpf_ctx *b)
{
	int res;

	res = load_fn_and_attach_to_tp(b, tp_all_category, tp_all_exit_name,
					tp_all_exit_fn, Args.pid, 0, -1);
	if (res == -1) {
		ERROR("cannot attach %s to '%s:%s'. Exiting.",
			tp_all_exit_fn, tp_all_category, tp_all_exit_name);
		return -1;
	}

	return 0;
}

/*
 * attach_all_kp_tp -- attach eBPF handlers to all syscalls using:
 *                     - Kprobes for entry handlers and
 *                     - Tracepoints for exit handlers
 *
 * Requires kernel >= v4.7
 *
 */
static int
attach_all_kp_tp(struct bpf_ctx *b)
{
	int res;

	res = attach_kp_mask(b, attach_single_sc_enter, 0);
	if (res)
		return res;

	return attach_tp_exit(b);
}

/*
 * attach_probes -- attach eBPF handlers to all syscalls
 *                  according to the expression
 */
int
attach_probes(struct bpf_ctx *b)
{
	if (Args.expr == NULL || strcasecmp(Args.expr, "all") == 0)
		return attach_all_kp_tp(b);

	if (strcasecmp(Args.expr, "kp-all") == 0)
		return attach_kp_mask(b, attach_single_sc, 0);

	if (strcasecmp(Args.expr, "kp-file") == 0)
		return attach_kp_mask(b, attach_single_sc, EM_str_1);

	if (strcasecmp(Args.expr, "kp-desc") == 0)
		return attach_kp_mask(b, attach_single_sc, EM_fd_1);

	if (strcasecmp(Args.expr, "kp-fileio") == 0)
		return attach_kp_mask(b, attach_single_sc,
					EM_str_1 | EM_str_2 | EM_fd_1);

	ERROR("unknown option: '%s'", Args.expr);
	return -1;
}
