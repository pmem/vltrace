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
 * trace.h -- data exchange packet between packet filter and reader callback
 */

#ifndef VLTRACE_TRACE_H
#define VLTRACE_TRACE_H

#define MAX_STR_ARG	3 /* max number of supported string arguments */

#define FIRST_PACKET	0 /* this is the first packet for this syscall */
#define LAST_PACKET	7 /* this is the last packet for this syscall */
#define ARG_MASK	(0b1111111100) /* arguments mask */

#define BUF_SIZE	384 /* size of buffer for string arguments */
#define STR_MAX_1	(BUF_SIZE - 2)
#define STR_MAX_2	((BUF_SIZE / 2) - 2)
#define STR_MAX_3	((BUF_SIZE / 3) - 2)

#define E_MASK		0x03 /* enum data_packet_types mask */

/* types of data packets */
enum data_packet_types {
	E_KP_ENTRY = 0,	/* entry of Kprobe */
	E_KP_EXIT  = 1,	/* exit  of Kprobe */
	E_TP_ENTRY = 2,	/* entry of Tracepoint */
	E_TP_EXIT  = 3,	/* exit  of Tracepoint */
};

struct data_entry_s {
	/* size of the packet */
	uint32_t size;

	/* union containing information about the packet */
	union {
		uint32_t info_all;
		struct {
			/*
			 * bits 0-1:
			 *   type of data packet (enum data_packet_types)
			 */
			uint32_t packet_type : 2;

			/*
			 * bits 2-4:
			 *   number of the first saved argument in the packet
			 */
			uint32_t arg_first : 3;

			/*
			 * bits 5-7:
			 *   number of the last saved argument in the packet
			 */
			uint32_t arg_last : 3;

			/*
			 * bit 8:
			 *   flag: syscall is not finished and will be continued
			 *         - next packets will be sent
			 */
			uint32_t will_be_cont : 1;

			/*
			 * bit 9:
			 *   flag: syscall has not finished
			 *         and this is a continuation
			 */
			uint32_t is_cont : 1;

			/*
			 * bit 10:
			 *   flag: bpf_probe_read error occurred
			 */
			uint32_t bpf_read_error : 1;
		} info;
	};

	/* PID and TID */
	uint64_t pid_tid;

	/* syscall's ID (number) */
	uint64_t sc_id;

	/* timestamp */
	uint64_t start_ts_nsec;

	/* arguments of the syscall */
	int64_t args[6];

	/* buffer for string arguments (of BUF_SIZE) */
	char aux_str[1];
};

struct data_exit_s {
	/* size of the rest of data (except this field) */
	uint32_t size;

	/* type of data packet (enum data_packet_types) */
	uint32_t packet_type;

	/* PID and TID */
	uint64_t pid_tid;

	/* syscall's ID (number) */
	uint64_t sc_id;

	/* timestamp */
	uint64_t finish_ts_nsec;

	/* return value */
	int64_t ret;
};

#endif /* VLTRACE_TRACE_H */
