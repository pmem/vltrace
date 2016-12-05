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
 * trace_tp_all.c -- Trace syscalls. Uses BCC, eBPF.
 */

/*
 * Syscall's entry handler.
 */
int
tracepoint__sys_enter(struct pt_regs *ctx)
{
	struct first_step_t fs = {};
	u64 pid_tid = bpf_get_current_pid_tgid();

	PID_CHECK_HOOK

	if (!bpf_get_current_comm(&fs.comm, sizeof(fs.comm)))
		return;

	fs.start_ts_nsec = bpf_ktime_get_ns();
	tmp_i.update(&pid_tid, &fs);

	return 0;
};

/*
 * Syscall's exit handler.
 */
int
tracepoint__sys_exit(struct pt_regs *ctx)
{
	struct first_step_t *fsp;
	struct ev_dt_t ev = {};

	u64 cur_nsec = bpf_ktime_get_ns();

	u64 pid_tid = bpf_get_current_pid_tgid();
	fsp = tmp_i.lookup(&pid_tid);
	if (fsp == 0)
		return 0;

	bpf_probe_read(&ev.comm, sizeof(ev.comm), fsp->comm);
	bpf_probe_read(&ev.open.fl_nm,
			sizeof(ev.open.fl_nm),
			(void *)fsp->fl_nm);
	/* SysCall ID */
	/* ev.sc_id = __NR_open; */
	ev.pid_tid = pid_tid;
	ev.start_ts_nsec = fsp->start_ts_nsec;
	ev.finish_ts_nsec = cur_nsec;
	ev.ret = PT_REGS_RC(ctx);

	events.perf_submit(ctx, &ev, sizeof(ev));
	tmp_i.delete(&pid_tid);

	return 0;
}
