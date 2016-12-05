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
 * trace.h -- Data exchange packet between packet filter and reader callback
 */


#ifndef TRACE_H
#define TRACE_H


struct ev_dt_t {
	/*
	 * the value equals to -1 mean "header"
	 * the value equals to -2 mean that syscall's num is unknown for glibc
	 *    and the field sc_name should be used to figuring out syscall.
	 */
	s64 sc_id;

	u64 pid_tid;

	/* Timestamps */
	u64 start_ts_nsec;
	u64 finish_ts_nsec;
	s64 ret;

	union {
		struct {
			s64 arg_1;
			s64 arg_2;
			s64 arg_3;
			s64 arg_4;
			s64 arg_5;
			s64 arg_6;
		};
		struct {
		} open;

		struct {
			s64 fd;
		} close;

		struct {
			s64 fd;
		} read;

		struct {
			s64 fd;
		} write;
	};

	union {
		/*
		 * The longest syscall's name is equal to 26 characters:
		 *    'SyS_sched_get_priority_max'.
		 * Let's to add a space for '\0' and few extra bytes.
		 */
		char sc_name[32];

		struct {
			char fl_nm[NAME_MAX];
			/* Current process name. XXX Reserved for future. */
			char comm[TASK_COMM_LEN];
		};

		struct {
			s32 argc;
			char argv[];
		} header;
	};
};

#endif /* TRACE_H */
