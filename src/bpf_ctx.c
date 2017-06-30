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
 * bpf_ctx.c -- functions related to struct bpf_ctx
 */

#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <linux/bpf.h>
#include <bcc/libbpf.h>
#include <bcc/bpf_common.h>
#include <bcc/perf_reader.h>

#include "utils.h"
#include "vltrace.h"
#include "bpf_ctx.h"
#include "ebpf_syscalls.h"

/*
 * pr_arr_check_quota -- check possibility of intercepting one more syscall
 */
static bool
pr_arr_check_quota(struct bpf_ctx *sbcp, unsigned new_pr_qty)
{
	return sbcp->pr_arr_qty + new_pr_qty <= Args.pr_arr_max;
}

/*
 * append_item_to_pr_arr -- save reference to handler of intercepted syscall
 *                          in pr_arr
 */
static int
append_item_to_pr_arr(struct bpf_ctx *sbcp, const char *name,
		struct perf_reader *probe, enum perf_reader_type_t type)
{
	if (sbcp->pr_arr == NULL) {
		sbcp->pr_arr = calloc(Args.pr_arr_max, sizeof(*sbcp->pr_arr));
		if (sbcp->pr_arr == NULL) {
			return -1;
		}
	}

	struct bpf_pr *item = calloc(1, sizeof(*item) + strlen(name) + 1);
	if (item == NULL)
		return -1;

	item->pr = probe;
	item->type = type;
	strcpy(item->key, name);

	sbcp->pr_arr[sbcp->pr_arr_qty++] = item;

	return 0;
}

/*
 * attach_callback_to_perf_output -- register callback to capture stream of
 *                                   events
 */
int
attach_callback_to_perf_output(struct bpf_ctx *sbcp,
		const char *name, perf_reader_raw_cb callback)
{
	int map_fd = bpf_table_fd(sbcp->module, name);
	if (map_fd < 0) {
		ERROR("cannot attach to perf output '%s':%m", name);
		return -1;
	}

	size_t map_id = bpf_table_id(sbcp->module, name);
	int ttype = bpf_table_type_id(sbcp->module, map_id);
	if (ttype != BPF_MAP_TYPE_PERF_EVENT_ARRAY) {
		ERROR("unknown table type %d", ttype);
		return -1;
	}

	/*
	 * XXX It can be reasonable to replace sysconf with sched_getaffinity().
	 *    It will allow us to ignore non-actual CPUs.
	 */
	long cpu_qty = sysconf(_SC_NPROCESSORS_ONLN);
	if (cpu_qty == -1) {
		perror("sysconf");
		return -1;
	}

	if (!pr_arr_check_quota(sbcp, (unsigned)cpu_qty)) {
		ERROR("number of perf readers would exceed global quota: %d",
			Args.pr_arr_max);
		return -1;
	}

#define SIZE_READER_NAME 32 /* reader name's format is: 0x24a6ba0:11 */
	for (int cpu = 0; cpu < cpu_qty; cpu++) {
		char reader_name[SIZE_READER_NAME];
		struct perf_reader *reader;

		reader = bpf_open_perf_buffer(callback, NULL, NULL, -1, cpu,
						Args.strace_reader_page_cnt);
		if (reader == NULL) {
			WARNING(
				"cannot open perf buffer on CPU %d, skipping this CPU",
				cpu);
			continue;
		}

		int fd = perf_reader_fd(reader);

		int res = bpf_update_elem(map_fd, &cpu, &fd, 0);
		if (res < 0) {
			/*
			 * Cannot create an element in the BPF map on this CPU,
			 * so the CPU will not be used (skip it).
			 */
			WARNING(
				"cannot update BPF map on CPU %d, skipping this CPU: %m",
				cpu);
			perf_reader_free(reader);
			continue;
		}

		res = snprintf(reader_name, sizeof(reader_name),
				"%p:%d", sbcp, cpu);
		assert(res > 0);
		(void) res;

		if (append_item_to_pr_arr(sbcp, reader_name, reader,
							PERF_TYPE_READER)) {
			perf_reader_free(reader);
			return -1;
		}
	}

	return 0;
}

/*
 * detach_all -- overall cleanup of resources
 */
void
detach_all(struct bpf_ctx *b)
{
	char *tp_category;
	char *tp_name;

	INFO("Finished tracing.\n"
		"Detaching probes... (please wait, it can take few tens of seconds) ...");

	for (unsigned i = 0; i < b->pr_arr_qty; i++) {
		perf_reader_free(b->pr_arr[i]->pr);

		switch (b->pr_arr[i]->type) {
		case PERF_TYPE_KPROBE:
			bpf_detach_kprobe(b->pr_arr[i]->key);
			break;
		case PERF_TYPE_TRACEPOINT:
			tp_category = b->pr_arr[i]->key;
			tp_name = strchr(b->pr_arr[i]->key, ':');
			*tp_name++ = 0;
			bpf_detach_tracepoint(tp_category, tp_name);
			break;
		default:
			/* no action required */
			break;
		}

		free(b->pr_arr[i]);

		if (Args.do_not_print_progress == 0)
			fprintf(stderr, "\r%i%% (%i of %i done)",
				(100 * (i + 1)) / b->pr_arr_qty,
				i + 1, b->pr_arr_qty);
	}

	bpf_module_destroy(b->module);
	INFO("\rDone.                    ");

	free(b->pr_arr);
}

/*
 * load_obj_code_into_ebpf_vm -- load eBPF object code to kernel VM and
 *                               obtain a file descriptor
 */
static int
load_obj_code_into_ebpf_vm(struct bpf_ctx *sbcp, const char *func_name,
		enum bpf_prog_type prog_type)
{
	void *bfs_res = bpf_function_start(sbcp->module, func_name);

	if (bfs_res == NULL) {
		ERROR("unknown program %s", func_name);
		return -1;
	}

	unsigned log_buf_size = 0;
	char *log_buf = NULL;

	if (sbcp->debug) {
		log_buf_size = 65536;
		log_buf = calloc(1, log_buf_size);

		if (log_buf == NULL)
			log_buf_size = 0;
	}

	int fd = bpf_prog_load(prog_type,
			bfs_res,
			(int)bpf_function_size(sbcp->module, func_name),
			bpf_module_license(sbcp->module),
			bpf_module_kern_version(sbcp->module),
			log_buf, log_buf_size);

	if (sbcp->debug && (log_buf != NULL)) {
		/* XXX Command line options to save it to separate file */
		fprintf(stderr, "DEBUG: %s('%s'):\n%s\n",
				__func__, func_name, log_buf);

		free(log_buf);
	}

	if (fd < 0) {
		ERROR("failed to load BPF program %s: %m", func_name);
		return -1;
	}

	return fd;
}

/*
 * chr_replace -- replace character 'tmpl' in string 'str' with 'ch'.
 */
static void
chr_replace(char *str, const char tmpl, const char ch)
{
	if (str == NULL)
		return;

	for (; *str; str++)
		if (*str == tmpl)
			*str = ch;
}

/*
 * event2ev_name -- convert event to ev_name
 */
static char *
event2ev_name(enum bpf_prog_type type, const char *prefix, const char *name)
{
	char *ev_name;

	switch (type) {
	case BPF_PROG_TYPE_KPROBE:
		if (asprintf(&ev_name, "%s_%s", prefix, name) == -1)
			return NULL;
		chr_replace(ev_name, '+', '_');
		chr_replace(ev_name, '.', '_');
		break;
	case BPF_PROG_TYPE_TRACEPOINT:
		if (asprintf(&ev_name, "%s:%s", prefix, name) == -1)
			return NULL;
		break;
	default:
		return NULL;
	}

	return ev_name;
}

static int
load_fn_and_attach_common(struct bpf_ctx *sbcp,
		enum bpf_prog_type prog_type, int probe_type,
		const char *category, const char *event, const char *fn_name,
		pid_t pid, unsigned cpu, int group_fd)
{
	const char *probe_name = NULL;
	const char *prefix = NULL;

	switch (prog_type) {
	case BPF_PROG_TYPE_KPROBE:
		probe_name = "kprobe";
		switch (probe_type) {
		case BPF_PROBE_ENTRY:
			prefix = "p";
			break;
		case BPF_PROBE_RETURN:
			prefix = "r";
			break;
		}
		break;
	case BPF_PROG_TYPE_TRACEPOINT:
		probe_name = "tracepoint";
		prefix = category;
		break;
	}

	char *ev_name = event2ev_name(prog_type, prefix, event);
	if (ev_name == NULL)
		return -1;

	int ret = -1;
	if (!pr_arr_check_quota(sbcp, 1)) {
		ERROR("number of perf readers would exceed global quota: %d",
			Args.pr_arr_max);
		goto exit_free;
	}

	int fn_fd = load_obj_code_into_ebpf_vm(sbcp, fn_name, prog_type);
	if (fn_fd == -1) {
		goto exit_free;
	}

	struct perf_reader *probe = NULL;
	switch (prog_type) {
	case BPF_PROG_TYPE_KPROBE:
		probe = bpf_attach_kprobe(fn_fd, probe_type, ev_name, event,
					pid, (int)cpu, group_fd, NULL, NULL);
		break;
	case BPF_PROG_TYPE_TRACEPOINT:
		probe = bpf_attach_tracepoint(fn_fd, category, event,
					pid, (int)cpu, group_fd, NULL, NULL);
		break;
	}

	if (probe == NULL) {
		ERROR("failed to attach eBPF function '%s' to %s '%s': %m",
			probe_name, fn_name, event);
		goto exit_free;
	}

	if (append_item_to_pr_arr(sbcp, ev_name, probe, prog_type)) {
		perf_reader_free(probe);
		goto exit_free;
	}

	ret = 0;

exit_free:
	free(ev_name);
	return ret;
}

/*
 * load_fn_and_attach_to_kp -- load ebpf function code into VM and attach it
 *                             to syscall entry point using Kprobe
 */
int
load_fn_and_attach_to_kp(struct bpf_ctx *sbcp,
		const char *event, const char *fn_name,
		pid_t pid, unsigned cpu, int group_fd)
{
	return load_fn_and_attach_common(sbcp,
				BPF_PROG_TYPE_KPROBE, BPF_PROBE_ENTRY,
				NULL, event, fn_name,
				pid, cpu, group_fd);
}

/*
 * load_fn_and_attach_to_kretp -- load ebpf function code into VM and attach it
 *                                to syscall exit point using Kprobe
 */
int
load_fn_and_attach_to_kretp(struct bpf_ctx *sbcp,
		const char *event, const char *fn_name,
		pid_t pid, unsigned cpu, int group_fd)
{
	return load_fn_and_attach_common(sbcp,
				BPF_PROG_TYPE_KPROBE, BPF_PROBE_RETURN,
				NULL, event, fn_name,
				pid, cpu, group_fd);
}

/*
 * load_fn_and_attach_to_tp -- load ebpf function code into VM and attach it
 *                             to syscall exit point using Tracepoint.
 */
int
load_fn_and_attach_to_tp(struct bpf_ctx *sbcp,
		const char *tp_category, const char *tp_name,
		const char *fn_name,
		int pid, unsigned cpu, int group_fd)
{
	return load_fn_and_attach_common(sbcp,
				BPF_PROG_TYPE_TRACEPOINT, 0,
				tp_category, tp_name, fn_name,
				pid, cpu, group_fd);
}
