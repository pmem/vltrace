/*
 * Copyright 2017, Intel Corporation
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
 * trace_fs_path_1_2_arg_tmpl-ml.c -- trace syscalls with filename
 *                                    as the 1st and the 2nd argument,
 *                                    multi-packet version.
 */

/*
 * kprobe__SYSCALL_NAME -- SYSCALL_NAME() entry handler
 */
int
kprobe__SYSCALL_NAME(struct pt_regs *ctx)
{
	struct first_step_t fs;
	u64 pid_tid = bpf_get_current_pid_tgid();

	PID_CHECK_HOOK

	fs.start_ts_nsec = bpf_ktime_get_ns();
	fs.args[0] = PT_REGS_PARM1(ctx);
	fs.args[1] = PT_REGS_PARM2(ctx);
	fs.args[2] = PT_REGS_PARM3(ctx);
	fs.args[3] = PT_REGS_PARM4(ctx);
	fs.args[4] = PT_REGS_PARM5(ctx);
	fs.args[5] = PT_REGS_PARM6(ctx);

	tmp_i.update(&pid_tid, &fs);

	return 0;
};

/*
 * kretprobe__SYSCALL_NAME -- SYSCALL_NAME() exit handler
 */
int
kretprobe__SYSCALL_NAME(struct pt_regs *ctx)
{
	struct first_step_t *fsp;

	enum { _pad_size = offsetof(struct data_entry_t, str) + NAME_MAX };

	union {
		struct data_entry_t ev;
		char _pad[_pad_size];
	} u;

	u64 cur_nsec = bpf_ktime_get_ns();

	u64 pid_tid = bpf_get_current_pid_tgid();
	fsp = tmp_i.lookup(&pid_tid);
	if (fsp == 0)
		return 0;

	u.ev.packet_type = 2; /* 2 additional packets */
	u.ev.sc_id = SYSCALL_NR; /* SysCall ID */
	u.ev.args[0] = fsp->arg_1;
	u.ev.args[1] = fsp->arg_2;
	u.ev.args[2] = fsp->arg_3;
	u.ev.args[3] = fsp->arg_4;
	u.ev.args[4] = fsp->arg_5;
	u.ev.args[5] = fsp->arg_6;
	u.ev.pid_tid = pid_tid;
	u.ev.start_ts_nsec = fsp->start_ts_nsec;
	u.ev.finish_ts_nsec = cur_nsec;
	u.ev.ret = PT_REGS_RC(ctx);
	/* XXX enum ??? */
	// const size_t ev_size = offsetof(struct data_entry_t, aux_str);
	// events.perf_submit(ctx, &u.ev, ev_size);
	events.perf_submit(ctx, &u.ev, offsetof(struct data_entry_t, aux_str));

	u.ev.packet_type = -1; /* first additional packet */
	bpf_probe_read(&u.ev.str, NAME_MAX, (void *)fsp-.args[0]);
	events.perf_submit(ctx, &u.ev, _pad_size);

	u.ev.packet_type = -2; /* second additional packet */
	bpf_probe_read(&u.ev.str, NAME_MAX, (void *)fsp-.args[1]);
	events.perf_submit(ctx, &u.ev, _pad_size);

	tmp_i.delete(&pid_tid);

	return 0;
}
