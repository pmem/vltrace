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
 * template_3_str-full.c -- templates for syscalls with three string arguments,
 *                          full string version
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

	enum { _pad_size = offsetof(struct data_entry_t, aux_str) + BUF_SIZE };
	union {
		struct data_entry_t ev;
		char _pad[_pad_size];
	} u;

	u.ev.type = E_KP_ENTRY;
	u.ev.start_ts_nsec = bpf_ktime_get_ns();

	u.ev.sc_id = SYSCALL_NR; /* SysCall ID */
	u.ev.pid_tid = pid_tid;

	u.ev.args[0] = PT_REGS_PARM1(ctx);
	u.ev.args[1] = PT_REGS_PARM2(ctx);
	u.ev.args[2] = PT_REGS_PARM3(ctx);
	u.ev.args[3] = PT_REGS_PARM4(ctx);
	u.ev.args[4] = PT_REGS_PARM5(ctx);
	u.ev.args[5] = PT_REGS_PARM6(ctx);

	int end_bpf_read = 0;
	char *src;
	char *dest = (char *)&u.ev.aux_str;

	memset(dest, 0, BUF_SIZE);

	int br; /* number of read bytes */
	int length = BUF_SIZE; /* bpf_probe_read_str is null-terminated */

/* 1st string argument */
	src = (char *)u.ev.args[STR1];

	/* from the beginning (0) to 1st string - contains 1st string */
	u.ev.packet_type = (0) + ((STR1 + 1) << 3) +
				(1 << 7); /* will be continued */
	if ((br = bpf_probe_read_str(dest, length, (void *)src)) > 0) {
		events.perf_submit(ctx, &u.ev, _pad_size);
	}
	if (br < length) {
		end_bpf_read = 1;
	}

	/* only 1st string argument */
	u.ev.packet_type = (STR1 + 1) + ((STR1 + 1) << 3) +
				(1 << 6) + /* it is a continuation */
				(1 << 7);  /* and will be continued */

	/*
	 * It is a macro for:
	 *
	 * for (int i = 0; i < Args.n_str_packets - 2; i++) {
	 *	if (!end_bpf_read) {
	 *		src += length;
	 *		if ((br = bpf_probe_read_str(dest, length,
	 *						(void *)src)) > 0) {
	 *			events.perf_submit(ctx, &u.ev, _pad_size);
	 *		}
	 *		if (br < length) {
	 *			end_bpf_read = 1;
	 *		}
	 *	}
	 * }
	 *
	 * because no loops can be used here in eBPF code.
	 */
	READ_AND_SUBMIT_N_MINUS_2_PACKETS

	/* from 1st to 2nd string argument - contains 1st string */
	u.ev.packet_type = (STR1 + 1) + (STR2 << 3) +
				(1 << 6); /* is a continuation */
	if (!end_bpf_read) {
		src += length;
		bpf_probe_read_str(dest, length, (void *)src);
	}
	events.perf_submit(ctx, &u.ev, _pad_size);

/* 2nd string argument */
	end_bpf_read = 0;
	src = (char *)u.ev.args[STR2];

	/* first packet - only 2nd string argument */
	u.ev.packet_type = (STR2) + ((STR2 + 1) << 3) +
				(1 << 7);  /* and will be continued */
	if ((br = bpf_probe_read_str(dest, length, (void *)src)) > 0) {
		events.perf_submit(ctx, &u.ev, _pad_size);
	}
	if (br < length) {
		end_bpf_read = 1;
	}

	/* only 2nd string argument */
	u.ev.packet_type = (STR2 + 1) + ((STR2 + 1) << 3) +
				(1 << 6) + /* it is a continuation */
				(1 << 7);  /* and will be continued */

	/*
	 * It is a macro for:
	 *
	 * for (int i = 0; i < Args.n_str_packets - 2; i++) {
	 *	if (!end_bpf_read) {
	 *		src += length;
	 *		if ((br = bpf_probe_read_str(dest, length,
	 *						(void *)src)) > 0) {
	 *			events.perf_submit(ctx, &u.ev, _pad_size);
	 *		}
	 *		if (br < length) {
	 *			end_bpf_read = 1;
	 *		}
	 *	}
	 * }
	 *
	 * because no loops can be used here in eBPF code.
	 */
	READ_AND_SUBMIT_N_MINUS_2_PACKETS

	/* from 1st to 2nd string argument - contains 2nd string */
	u.ev.packet_type = (STR2 + 1) + (STR3 << 3) +
				(1 << 6); /* is a continuation */
	if (!end_bpf_read) {
		src += length;
		bpf_probe_read_str(dest, length, (void *)src);
	}
	events.perf_submit(ctx, &u.ev, _pad_size);

/* 3rd string argument */
	end_bpf_read = 0;
	src = (char *)u.ev.args[STR3];

	/* first packet - only 2nd string argument */
	u.ev.packet_type = (STR3) + ((STR3 + 1) << 3) +
				(1 << 7);  /* and will be continued */
	if ((br = bpf_probe_read_str(dest, length, (void *)src)) > 0) {
		events.perf_submit(ctx, &u.ev, _pad_size);
	}
	if (br < length) {
		end_bpf_read = 1;
	}

	/* only 3rd string argument */
	u.ev.packet_type = (STR3 + 1) + ((STR3 + 1) << 3) +
				(1 << 6) + /* it is a continuation */
				(1 << 7);  /* and will be continued */

	/*
	 * It is a macro for:
	 *
	 * for (int i = 0; i < Args.n_str_packets - 2; i++) {
	 *	if (!end_bpf_read) {
	 *		src += length;
	 *		if ((br = bpf_probe_read_str(dest, length,
	 *						(void *)src)) > 0) {
	 *			events.perf_submit(ctx, &u.ev, _pad_size);
	 *		}
	 *		if (br < length) {
	 *			end_bpf_read = 1;
	 *		}
	 *	}
	 * }
	 *
	 * because no loops can be used here in eBPF code.
	 */
	READ_AND_SUBMIT_N_MINUS_2_PACKETS

	/* from 3rd string argument to the end (7) - contains 3rd string */
	u.ev.packet_type = (STR3 + 1) + (7 << 3) +
				(1 << 6); /* is a continuation */
	if (!end_bpf_read) {
		src += length;
		bpf_probe_read_str(dest, length, (void *)src);
	}
	events.perf_submit(ctx, &u.ev, _pad_size);

	return 0;
};

/*
 * kretprobe__SYSCALL_NAME_filled_for_replace --
 *                               SYSCALL_NAME_filled_for_replace() exit handler
 */
int
kretprobe__SYSCALL_NAME_filled_for_replace(struct pt_regs *ctx)
{
	struct data_exit_t ev;

	uint64_t cur_nsec = bpf_ktime_get_ns();
	uint64_t pid_tid = bpf_get_current_pid_tgid();

	PID_CHECK_HOOK

	ev.type = E_KP_EXIT;
	ev.packet_type = 0; /* No additional packets */
	ev.sc_id = SYSCALL_NR; /* SysCall ID */
	ev.pid_tid = pid_tid;
	ev.finish_ts_nsec = cur_nsec;
	ev.ret = PT_REGS_RC(ctx);

	events.perf_submit(ctx, &ev, sizeof(struct data_exit_t));

	return 0;
}
