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
 * trace.h -- Data exchange packet between packet filter and reader callback
 */


#ifndef TRACE_H
#define TRACE_H

#define STR_MAX 401 /* including terminating '\0' */

enum {
	E_SC_ENTRY	= 0,
	E_SC_EXIT	= 1,
	E_SC_TP		= 2
};

struct data_entry_t {
	u64 type; /* E_SC_ENTRY or E_SC_EXIT or E_SC_TP */

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
	s64 packet_type;

	/*
	 * Syscall's signature. All packets with the same signature belong to one
	 *    syscall. We need two time stamps here, because syscalls can nest
	 *    from one pid_tid by calling syscall from signal handler, before
	 *    syscall called from main context has returned.
	 */
	struct {
		u64 pid_tid;

		/* timestamp */
		u64 start_ts_nsec;

		/* value -1 means "header" */
		s64 sc_id;
	};

	union {
		/* Body of first packet */
		struct {
			s64 args[6];

			/*
			 * Body of string argument. The content and
			 *    meaning of argument is defined by
			 *    syscall's number in the sc_id field.
			 */
			char aux_str[1];	/* STR_MAX */
		};

		/*
		 * Body of string argument. The content and meaning of argument
		 *    is defined by syscall's number (in the first packet) in
		 *    the sc_id field.
		 */
		char str[1];	/* STR_MAX */
	};
};

struct data_exit_t {
	u64 type; /* E_SC_ENTRY or E_SC_EXIT or E_SC_TP */

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
	s64 packet_type;

	/*
	 * Syscall's signature. All packets with the same signature belong to one
	 *    syscall. We need two time stamps here, because syscalls can nest
	 *    from one pid_tid by calling syscall from signal handler, before
	 *    syscall called from main context has returned.
	 */
	struct {
		u64 pid_tid;

		/* timestamp */
		u64 finish_ts_nsec;

		/* value -1 means "header" */
		s64 sc_id;
	};

	s64 ret;
};

struct tp_s {
	u64 type;
	u64 pid_tid;
	u64 finish_ts_nsec;
	s64 id;
	s64 ret;
};

#endif /* TRACE_H */
