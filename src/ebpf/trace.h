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


#ifndef TRACE_H
#define TRACE_H

/* define it as empty for case when Args.n_str_packets <= 2 */
#define READ_AND_SUBMIT_N_MINUS_2_PACKETS

#define MAX_STR_ARG 	3 /* max supported number of string arguments */

#define BUF_SIZE	384 /* size of buffer for string arguments */
#define STR_MAX_1	(BUF_SIZE - 2)
#define STR_MAX_2	((BUF_SIZE / 2) - 2)
#define STR_MAX_3	((BUF_SIZE / 3) - 2)

/* types of data packets */
enum {
	E_KP_ENTRY,	/* entry of KProbe */
	E_KP_EXIT,	/* exit  of KProbe */
	E_TP_ENTRY,	/* entry of TracePoint */
	E_TP_EXIT,	/* exit  of TracePoint */
};

struct data_entry_s {
	uint32_t size; /* size of the rest of data (except this field) */
	uint32_t type; /* type of data packets */

	/*
	 * This field describes a series of packets for every syscall.
	 *
	 * It is needed because stack size is limited to 512 bytes and used part
	 * of the stack is initialized with zero on every call of syscall handlers.
	 *
	 * the value equal to 0 means that this is "single-packet" syscall
	 *    and there will be no additional packets sent.
	 * the value bigger than 0 means that this is a first packet and there
	 *    will be sent 'packet_type' more additional packets.
	 * the value less than 0 means that this is additional packet with
	 *   serial number 'packet_type'.
	 *
	 * Content of additional packets is defined by syscall number in
	 *    first packet.
	 */
	int64_t packet_type;

	/*
	 * Syscall's signature. All packets with the same signature belong to one
	 *    syscall. We need two time stamps here, because syscalls can nest
	 *    from one pid_tid by calling syscall from signal handler, before
	 *    syscall called from main context has returned.
	 */
	struct {
		uint64_t pid_tid;

		/* timestamp */
		uint64_t start_ts_nsec;

		/* value -1 means "header" */
		int64_t sc_id;
	};

	/* arguments of the syscall */
	struct {
		int64_t args[6];

		/* buffer for string arguments (of BUF_SIZE) */
		char aux_str[1];
	};
};

struct data_exit_s {
	uint32_t size; /* size of the rest of data (except this field) */
	uint32_t type; /* type of data packets */
	uint64_t pid_tid;
	uint64_t finish_ts_nsec;
	int64_t sc_id;
	int64_t ret;
};

#endif /* TRACE_H */
