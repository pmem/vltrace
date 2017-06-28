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
 * template_exit.c -- templates for exit() and exit_group() syscalls
 *                    in full-follow-fork mode,
 *                    see README_templates.txt for details
 */

/*
 * kprobe__SYSCALL_NAME_filled_for_replace --
 *				SYSCALL_NAME_filled_for_replace() entry handler
 */
int
kprobe__SYSCALL_NAME_filled_for_replace(struct pt_regs *ctx)
{
	struct data_entry_s ev;
	uint64_t pid_tid = bpf_get_current_pid_tgid();

#define TRACE_IN_SYS_EXIT 1

	PID_CHECK_HOOK

#undef  TRACE_IN_SYS_EXIT

	ev.info_all = E_KP_ENTRY;
	ev.info.arg_last = ALL_ARGUMENTS; /* packet contains all arguments */
	ev.size = offsetof(struct data_entry_s, aux_str);
	ev.start_ts_nsec = bpf_ktime_get_ns();

	ev.sc_id = SYSCALL_NR; /* SysCall ID */
	ev.pid_tid = pid_tid;

	ev.args[0] = PT_REGS_PARM1(ctx);
	ev.args[1] = PT_REGS_PARM2(ctx);
	ev.args[2] = PT_REGS_PARM3(ctx);
	ev.args[3] = PT_REGS_PARM4(ctx);
	ev.args[4] = PT_REGS_PARM5(ctx);
	ev.args[5] = PT_REGS_PARM6(ctx);

	events.perf_submit(ctx, &ev, offsetof(struct data_entry_s, aux_str));

	return 0;
};

/*
 * kretprobe__SYSCALL_NAME_filled_for_replace --
 *				SYSCALL_NAME_filled_for_replace() exit handler
 */
int
kretprobe__SYSCALL_NAME_filled_for_replace(struct pt_regs *ctx)
{
	struct data_exit_s ev;
	uint64_t pid_tid = bpf_get_current_pid_tgid();

	PID_CHECK_HOOK

	ev.packet_type = E_KP_EXIT;
	ev.size = sizeof(ev);
	ev.pid_tid = pid_tid;
	ev.finish_ts_nsec = bpf_ktime_get_ns();
	ev.sc_id = SYSCALL_NR; /* SysCall ID */
	ev.ret = PT_REGS_RC(ctx);

	events.perf_submit(ctx, &ev, sizeof(ev));

	return 0;
}
