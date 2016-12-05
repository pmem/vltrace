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
 * bpf.c -- functions related to struct bpf_ctx
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <linux/bpf.h>
#include <bcc/libbpf.h>
#include <bcc/bpf_common.h>
#include <bcc/perf_reader.h>

#include "bpf.h"
#include "main.h"


/*
 * This function checks possibility of intercepting one more syscall.
 * Should be actual if we will intercept something more low-level than regular
 * syscalls.
 */
static bool pr_arr_check_quota(struct bpf_ctx *sbcp, unsigned new_pr_qty)
{
	return sbcp->pr_arr_qty + new_pr_qty <= args.pr_arr_max;
}

/*
 * Save reference to hendler of intercepted syscall in pr_arr.
 */
static void append_item_to_pr_arr(struct bpf_ctx *sbcp, const char *name,
		struct perf_reader *probe, bool attached)
{
	struct bpf_pr *item =
		calloc(1, sizeof(*item) + strlen(name) + 1);
	item->pr = probe;
	item->attached = attached;
	strcpy(item->key, name);

	if (NULL == sbcp->pr_arr)
		sbcp->pr_arr =
			calloc(args.pr_arr_max, sizeof(*sbcp->pr_arr));

	sbcp->pr_arr[sbcp->pr_arr_qty] = item;
	sbcp->pr_arr_qty += 1;
}

/*
 * Register callback to capture stream of events.
 */
int
attach_callback_to_perf_output(struct bpf_ctx *sbcp,
		const char *name, perf_reader_raw_cb callback)
{
	int map_fd = bpf_table_fd(sbcp->module, name);

	if (map_fd < 0) {
		fprintf(stderr,
			"ERROR:%s:Can't attach to perf output '%s':%m.\n",
			__func__, name);
		return -1;
	}

	size_t map_id = bpf_table_id(sbcp->module, name);
	int ttype = bpf_table_type_id(sbcp->module, map_id);

	if (ttype != BPF_MAP_TYPE_PERF_EVENT_ARRAY) {
		fprintf(stderr, "ERROR:%s:Unknown table type %d.\n",
				__func__, ttype);
		return -1;
	}

	/*
	 * XXX It can be reasonable to replace sysconf with sched_getaffinity().
	 *    It will allow us to ignore non-actual CPUs.
	 */
	long cpu_qty = sysconf(_SC_NPROCESSORS_ONLN);

	if (!pr_arr_check_quota(sbcp, (unsigned)cpu_qty)) {
		fprintf(stderr,
			"ERROR:%s:Number of perf readers would exceed"
			" global quota: %d\n",
			__func__, args.pr_arr_max);

		return -1;
	}

	for (int cpu = 0; cpu < cpu_qty; cpu++) {
		char reader_name[128];

		struct perf_reader *reader =
			bpf_open_perf_buffer(callback, NULL, -1, cpu);

		if (NULL == reader) {
			fprintf(stderr,
				"WARNING:%s:"
				"Could not open perf buffer on cpu %d."
				" Ignored.\n",
				__func__, cpu);
			continue;
		}

		int fd = perf_reader_fd(reader);

		int res = bpf_update_elem(map_fd, &cpu, &fd, 0);

		if (res < 0) {
			fprintf(stderr,
				"WARNING:%s:"
				"Could not update table on cpu %d: %m."
				" Ignored.\n",
				__func__, cpu);
		}

		snprintf(reader_name, sizeof(reader_name), "%p:%d", sbcp, cpu);
		append_item_to_pr_arr(sbcp, reader_name, reader, false);
	}

	return 0;
}

/*
 * Overall resource cleanup.
 *
 * WARNING We really need explicit cleanup to prevent in-kernel memory leaks.
 *         Yes, there still are kernel bugs related to eBPF.
 */
void
detach_all(struct bpf_ctx *b)
{
	fprintf(stderr,
		"INFO: Detaching. PLEASE wait."
		" It can hold few tens of seconds.\n");

	for (unsigned i = 0; i < b->pr_arr_qty; i++) {
		perf_reader_free(b->pr_arr[i]->pr);

		/* non-attached keys here include the perf_events reader */
		if (b->pr_arr[i]->attached) {
			char desc[256];

			snprintf(desc, sizeof(desc),
				"-:kprobes/%s", b->pr_arr[i]->key);
			bpf_detach_kprobe(desc);
		}

		free(b->pr_arr[i]);
	}

	bpf_module_destroy(b->module);

	free(b->pr_arr);
	free(b);
}

/*
 *  Load eBPF object code to kernel VM and obtaining a fd
 */
static int
load_obj_code_into_ebpf_vm(struct bpf_ctx *sbcp, const char *func_name,
		enum bpf_prog_type prog_type)
{
	int fd = -1;
	void *bfs_res = bpf_function_start(sbcp->module, func_name);

	if (NULL == bfs_res) {
		fprintf(stderr, "%s: Unknown program %s\n",
				__func__, func_name);
		return -1;
	}

	const unsigned log_buf_size = sbcp->debug ? 65536 : 0;
	char *const log_buf = sbcp->debug ? calloc(1, log_buf_size) : NULL;

	fd = bpf_prog_load(prog_type,
			bfs_res,
			(int)bpf_function_size(sbcp->module, func_name),
			bpf_module_license(sbcp->module),
			bpf_module_kern_version(sbcp->module),
			log_buf, log_buf_size);

	if (sbcp->debug) {
		/* XXX Command line options to save it to separate file */
		fprintf(stderr, "DEBUG:%s('%s'):\n%s\n",
				__func__, func_name, log_buf);
	}

	if (fd < 0) {
		fprintf(stderr,
			"ERROR:%s:Failed to load BPF program %s: %m\n",
			__func__, func_name);

		return -1;
	}

	return fd;
}

/*
 * This function replaces character 'tmpl' in string 'str' with 'ch'.
 */
static void
chr_replace(char *str, const char tmpl, const char ch)
{
	if (NULL == str)
		return;

	for (; *str; str++)
		if (tmpl == *str)
			*str = ch;
}

/*
 * Load ebpf function code into VM and attach it to syscall exit point using
 *    KProbe.
 */
int
load_fn_and_attach_to_kp(struct bpf_ctx *sbcp,
		const char *event, const char *fn_name,
		pid_t pid, unsigned cpu, int group_fd)
{
	char desc[256];
	struct perf_reader *pr;
	int fn_fd;

	if (!pr_arr_check_quota(sbcp, 1)) {
		fprintf(stderr,
			"ERROR:%s:Number of perf readers would exceed"
			" global quota: %d\n",
			__func__, args.pr_arr_max);

		return -1;
	}

	fn_fd = load_obj_code_into_ebpf_vm(sbcp, fn_name, BPF_PROG_TYPE_KPROBE);
	if (fn_fd == -1) {
		return -1;
	}

	char *ev_name = calloc(1, 2 + strlen(event) + 1);

	strcpy(ev_name, "p_");
	strcat(ev_name, event);
	chr_replace(ev_name, '+', '_');
	chr_replace(ev_name, '.', '_');

	snprintf(desc, sizeof(desc), "p:kprobes/%s %s", ev_name, event);

	pr = bpf_attach_kprobe(fn_fd, ev_name, desc, pid, (int)cpu, group_fd,
				NULL, NULL);

	if (NULL == pr) {
		fprintf(stderr,
			"ERROR:%s:Failed to attach eBPF function '%s'"
			" to kprobe '%s': %m\n",
			__func__, fn_name, event);

		free(ev_name);

		return -1;
	}

	append_item_to_pr_arr(sbcp, ev_name, pr, true);

	free(ev_name);

	return 0;
}

/*
 * Load ebpf function code into VM and attach it to syscall exit point using
 *    KProbe.
 */
int
load_fn_and_attach_to_kretp(struct bpf_ctx *sbcp,
		const char *event, const char *fn_name,
		pid_t pid, unsigned cpu, int group_fd)
{
	char desc[256];
	struct perf_reader *pr;
	int fn_fd;

	if (!pr_arr_check_quota(sbcp, 1)) {
		fprintf(stderr,
			"ERROR:%s:Number of perf readers would exceed"
			" global quota: %d\n",
			__func__, args.pr_arr_max);

		return -1;
	}

	fn_fd = load_obj_code_into_ebpf_vm(sbcp, fn_name, BPF_PROG_TYPE_KPROBE);
	if (fn_fd == -1) {
		return -1;
	}

	char *ev_name = calloc(1, 2 + strlen(event) + 1);

	strcpy(ev_name, "r_");
	strcat(ev_name, event);
	chr_replace(ev_name, '+', '_');
	chr_replace(ev_name, '.', '_');

	snprintf(desc, sizeof(desc), "r:kprobes/%s %s", ev_name, event);

	pr = bpf_attach_kprobe(fn_fd, ev_name, desc, pid, (int)cpu, group_fd,
				NULL, NULL);

	if (NULL == pr) {
		fprintf(stderr,
			"ERROR:%s:Failed to attach eBPF function '%s'"
			" to kprobe '%s': %m\n",
			__func__, fn_name, event);

		return -1;
	}

	append_item_to_pr_arr(sbcp, ev_name, pr, true);

	free(ev_name);

	return 0;
}

/*
 * Load ebpf function code into VM and attach it to syscall exit point using
 *    TracePoint.
 */
int
load_fn_and_attach_to_tp(struct bpf_ctx *sbcp,
		const char *tp_category, const char *tp_name,
		const char *fn_name,
		int pid, unsigned cpu, int group_fd)
{
	if (!pr_arr_check_quota(sbcp, 1)) {
		fprintf(stderr,
			"ERROR:%s:Number of perf readers would exceed"
			" global quota: %d\n",
			__func__, args.pr_arr_max);

		return -1;
	}

	int fn_fd = load_obj_code_into_ebpf_vm(sbcp,
			fn_name, BPF_PROG_TYPE_TRACEPOINT);

	struct perf_reader *pr = bpf_attach_tracepoint(fn_fd,
			tp_category, tp_name,
			pid, (int)cpu, group_fd, NULL, NULL);

	if (NULL == pr) {
		fprintf(stderr,
			"ERROR:%s:Failed to attach eBPF function '%s'"
			" to tracepoint '%s:%s': %m\n",
			__func__, fn_name, tp_category, tp_name);

		return -1;
	}

	char *ev_name = calloc(1,
			strlen(tp_category) + 1 + strlen(tp_name) + 1);

	strcpy(ev_name, tp_category);
	strcat(ev_name, ":");
	strcat(ev_name, tp_name);

	/* XXX May be we should mark this pr with some specific numeric code */
	append_item_to_pr_arr(sbcp, ev_name, pr, false);

	free(ev_name);

	return 0;
}
