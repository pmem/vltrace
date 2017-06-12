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
 * bpf_ctx.h -- Key bpf_ctx structure and related functions
 */

#ifndef BPF_CTX_H
#define BPF_CTX_H

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>

#include <bcc/libbpf.h>

/* This struct represent perf reader object */
struct bpf_pr {
	/* A pointer to corresponding libbcc's perf reader object */
	struct perf_reader *pr;

	/*
	 * The state of our perf reader.
	 *
	 * XXX May be we should replace this field with some
	 *    enum perf_reader_type_t as soon as tracepoints
	 *    will be fixed.
	 */
	bool  attached;

	/* The unique key associated with our perf reader */
	char  key[];
};

/* eBPF context */
struct bpf_ctx {
	/* A pointer to compiled ebpf code */
	void			 *module;
	/* debug mode */
	unsigned		  debug;
	/* A pointer to array of perf readers */
	struct bpf_pr   **pr_arr;
	/* A qty of perf readers in array above */
	unsigned		  pr_arr_qty;
};

int attach_callback_to_perf_output(struct bpf_ctx *sbcp,
		const char *perf_event, perf_reader_raw_cb callback);

int load_fn_and_attach_to_kp(struct bpf_ctx *sbcp,
		const char *event, const char *fn_name,
		pid_t pid, unsigned cpu, int group_fd);

int load_fn_and_attach_to_kretp(struct bpf_ctx *sbcp,
		const char *event, const char *fn_name,
		pid_t pid, unsigned cpu, int group_fd);

int load_fn_and_attach_to_tp(struct bpf_ctx *sbcp,
		const char *tp_category, const char *tp_name,
		const char *fn_name,
		int pid, unsigned cpu, int group_fd);

void detach_all(struct bpf_ctx *b);

#endif /* BPF_CTX_H */
