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

enum {
	E_SC_ENTRY	= 0,
	E_SC_EXIT	= 1,
	E_SC_TP		= 2
};

/*
 * The longest syscall's name is equal to 26 characters:
 *    'SyS_sched_get_priority_max'.
 * Let's add a space for '\0' and few extra bytes.
 */
enum { E_SC_NAME_SIZE = 32 };

struct data_entry_t {
	s64 type; /* E_SC_ENTRY or E_SC_EXIT */

	/*
	 * This field is set for glibc-defined syscalls and describe
	 *    a series of packets for every syscall.
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
	 *    first packet. There are no additional packets for "sc_id == -2"
	 */
	s64 packet_type;

	/*
	 * Syscall's signature. All packets with the same signature belong to one
	 *    syscall. We need two time stamps here, because syscalls can nest
	 *    from one pid_tid by calling syscall from signal handler, before
	 *    syscall called from main context has returned.
	 *
	 * XXX In fact sc_id is not needed here, but its presence simplifies
	 *    a lot of processing, so let's keep it here.
	 */
	struct {
		u64 pid_tid;

		/* Timestamps */
		u64 start_ts_nsec;

		/*
		 * the value equal to -1 means "header"
		 *
		 * the value equal to -2 means that syscall's num is
		 *    unknown for glibc and the field sc_name should be
		 *    used to figuring out syscall.
		 */
		s64 sc_id;
	};

	union {
		/* Body of first packet */
		struct {
			s64 arg_1;
			s64 arg_2;
			s64 arg_3;
			s64 arg_4;
			s64 arg_5;
			s64 arg_6;

			union {
				/* should be last in this structure */
				char sc_name[E_SC_NAME_SIZE];
				/*
				 * Body of string argument. The content and
				 *    meaning of argument is defined by
				 *    syscall's number in the sc_id field.
				 */
				char aux_str[1];	/* NAME_MAX */
			};
		};

		/* Body of header */
		struct {
			s64 argc;
			char argv[];
		} header;

		/*
		 * Body of string argument. The content and meaning of argument
		 *    is defined by syscall's number (in the first packet) in
		 *    the sc_id field.
		 */
		char str[1];	/* NAME_MAX */
	};
};

struct data_exit_t {
	s64 type; /* E_SC_ENTRY or E_SC_EXIT */

	/*
	 * This field is set for glibc-defined syscalls and describe
	 *    a series of packets for every syscall.
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
	 *    first packet. There are no additional packets for "sc_id == -2"
	 */
	s64 packet_type;

	/*
	 * Syscall's signature. All packets with the same signature belong to one
	 *    syscall. We need two time stamps here, because syscalls can nest
	 *    from one pid_tid by calling syscall from signal handler, before
	 *    syscall called from main context has returned.
	 *
	 * XXX In fact sc_id is not needed here, but its presence simplifies
	 *    a lot of processing, so let's keep it here.
	 */
	struct {
		u64 pid_tid;

		/* Timestamps */
		u64 finish_ts_nsec;

		/*
		 * the value equal to -1 means "header"
		 *
		 * the value equal to -2 means that syscall's num is
		 *    unknown for glibc and the field sc_name should be
		 *    used to figuring out syscall.
		 */
		s64 sc_id;
	};

	s64 ret;

	/* should be last in this structure */
	char sc_name[E_SC_NAME_SIZE];
};

struct tp_s {
	s64 type;
	u64 pid_tid;
	u64 finish_ts_nsec;
	s64 id;
	s64 ret;
};

#endif /* TRACE_H */
