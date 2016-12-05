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
 * trace_libc_tmpl.c -- Trace syscalls with numbers known from libc.
 *    Uses BCC, eBPF.
 */

/*
 * SYSCALL_NAME() entry handler
 */
int
kprobe__SYSCALL_NAME(struct pt_regs *ctx)
{
	struct first_step_t fs = {};
	u64 pid_tid = bpf_get_current_pid_tgid();

	PID_CHECK_HOOK

	fs.start_ts_nsec = bpf_ktime_get_ns();
	fs.arg_1 = PT_REGS_PARM1(ctx);
	fs.arg_2 = PT_REGS_PARM2(ctx);
	fs.arg_3 = PT_REGS_PARM3(ctx);
	fs.arg_4 = PT_REGS_PARM4(ctx);
	fs.arg_5 = PT_REGS_PARM5(ctx);
	fs.arg_5 = PT_REGS_PARM6(ctx);

	tmp_i.update(&pid_tid, &fs);

	return 0;
};

/*
 * SYSCALL_NAME() exit handler
 */
int
kretprobe__SYSCALL_NAME(struct pt_regs *ctx)
{
	struct first_step_t *fsp;
	struct ev_dt_t ev = {};

	u64 cur_nsec = bpf_ktime_get_ns();

	u64 pid_tid = bpf_get_current_pid_tgid();
	fsp = tmp_i.lookup(&pid_tid);
	if (fsp == 0)
		return 0;

	ev.sc_id = SYSCALL_NR; /* SysCall ID */
	ev.arg_1 = fsp->arg_1;
	ev.arg_2 = fsp->arg_2;
	ev.arg_3 = fsp->arg_3;
	ev.arg_4 = fsp->arg_4;
	ev.arg_5 = fsp->arg_5;
	ev.arg_6 = fsp->arg_6;
	ev.pid_tid = pid_tid;
	ev.start_ts_nsec = fsp->start_ts_nsec;
	ev.finish_ts_nsec = cur_nsec;
	ev.ret = PT_REGS_RC(ctx);

	const size_t ev_size = offsetof(struct ev_dt_t, sc_name);
	events.perf_submit(ctx, &ev, ev_size);

	tmp_i.delete(&pid_tid);

	return 0;
}
