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
 * template_1_str-full.c -- templates for syscalls with one string argument,
 *                          full string version,
 *                          see README_templates.txt for details
 */

/*
 * kprobe__SYSCALL_NAME_filled_for_replace -- SYSCALL_NAME_filled_for_replace()
 *                                            entry handler
 */
int
kprobe__SYSCALL_NAME_filled_for_replace(struct pt_regs *ctx)
{
	uint64_t pid_tid = bpf_get_current_pid_tgid();

	PID_CHECK_HOOK

	enum { _pad_size = offsetof(struct data_entry_s, aux_str) + BUF_SIZE };
	union {
		struct data_entry_s ev;
		char _pad[_pad_size];
	} u;

	u.ev.packet_type = E_KP_ENTRY;
	u.ev.size = _pad_size;
	u.ev.start_ts_nsec = bpf_ktime_get_ns();

	u.ev.sc_id = SYSCALL_NR; /* SysCall ID */
	u.ev.pid_tid = pid_tid;

	u.ev.args[0] = PT_REGS_PARM1(ctx);
	u.ev.args[1] = PT_REGS_PARM2(ctx);
	u.ev.args[2] = PT_REGS_PARM3(ctx);
	u.ev.args[3] = PT_REGS_PARM4(ctx);
	u.ev.args[4] = PT_REGS_PARM5(ctx);
	u.ev.args[5] = PT_REGS_PARM6(ctx);

	int ret;
	int end_bpf_read = 0;
	char *src = (char *)u.ev.args[STR1];
	char *dest = (char *)&u.ev.aux_str;

	memset(dest, 0, BUF_SIZE);

	int length = BUF_SIZE; /* bpf_probe_read_str is null-terminated */

	if ((ret = bpf_probe_read_str(dest, length, (void *)src)) < length) {
		/* string is completed */
		end_bpf_read = 1;
		/*
		 * From the beginning (0) to the end (7) -
		 * contains 1st string
		 */
		u.ev.packet_type = E_KP_ENTRY |
					(0 << 2) +
					(7 << 5);
		if (ret < 0)
			u.ev.packet_type |= READ_ERROR;
	} else {
		/* string is not completed */
		end_bpf_read = 0;
		/* from the beginning (0) to 1st string - contains 1st string */
		u.ev.packet_type = E_KP_ENTRY |
					(0 << 2) +
					((STR1 + 1) << 5) +
					(1 << 8); /* will be continued */
	}

	events.perf_submit(ctx, &u.ev, _pad_size);

	if (!end_bpf_read) {
		/* only 1st string argument */
		u.ev.packet_type = E_KP_ENTRY |
					((STR1 + 1) << 2) +
					((STR1 + 1) << 5) +
					(1 << 9) + /* it is a continuation */
					(1 << 8);  /* and will be continued */

		/*
		 * It is a macro for sending (Args.n_str_packets-2) packets.
		 * The code from the file: macro_full_string_mode.c
		 * will be placed here (Args.n_str_packets-2) times,
		 * because no loops can be used here in eBPF code.
		 */
		READ_AND_SUBMIT_N_MINUS_2_PACKETS

		/*
		 * From 1st string argument to the end (7) -
		 * contains 1st string
		 */
		u.ev.packet_type = E_KP_ENTRY |
					((STR1 + 1) << 2) +
					(7 << 5) +
					(1 << 9); /* is a continuation */
		if (ret < 0)
			u.ev.packet_type |= READ_ERROR;
		if (!end_bpf_read) {
			/* bpf_probe_read_str is null-terminated */
			src += length - 1;
			ret = bpf_probe_read_str(dest, length, (void *)src);
			if (ret < 0)
				u.ev.packet_type |= READ_ERROR;
		}
		events.perf_submit(ctx, &u.ev, _pad_size);
	}

	return 0;
};

/*
 * kretprobe__SYSCALL_NAME_filled_for_replace --
 *                               SYSCALL_NAME_filled_for_replace() exit handler
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
