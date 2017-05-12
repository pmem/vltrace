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
 * template_tracepoints.c -- trace syscalls using tracepoints
 */

/*
 * tracepoint__sys_enter -- syscall's entry handler
 */
int
tracepoint__sys_enter(struct tracepoint__raw_syscalls__sys_enter *args)
{
	/* NOT IMPLEMENTED */
	return 0;
}

/*
 * tracepoint__sys_exit -- syscall's exit handler
 */
int
tracepoint__sys_exit(struct tracepoint__raw_syscalls__sys_exit *args)
{
	struct data_exit_s tp;
	uint64_t pid_tid = bpf_get_current_pid_tgid();

	tp.finish_ts_nsec = bpf_ktime_get_ns();
	tp.sc_id = args->id;
	tp.ret = args->ret;

	PID_CHECK_HOOK

	if (tp.sc_id == __NR_clone ||
	    tp.sc_id == __NR_fork  ||
	    tp.sc_id == __NR_vfork) {
		if (tp.ret > 0) {
			uint64_t one = 1;
			children_map.update(&tp.ret, &one);
		}
	}

	tp.type = E_TP_EXIT;
	tp.pid_tid = pid_tid;

	events.perf_submit(args, &tp, sizeof(tp));

	return 0;
}
