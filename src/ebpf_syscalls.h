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
 * ebpf_syscalls.h -- definitions for table of known syscalls
 */

#ifndef EBPF_SYSCALLS_H
#define EBPF_SYSCALLS_H

#include <stdio.h>
#include <stdint.h>

enum masks_t {
	/* syscall has string as first arg */
	EM_str_1 = 1 << 0,
	/* syscall has string as second arg */
	EM_str_2 = 1 << 1,
	/* syscall has string as third arg */
	EM_str_3 = 1 << 2,
	/* syscall has string as fourth arg */
	EM_str_4 = 1 << 3,
	/* syscall has string as fifth arg */
	EM_str_5 = 1 << 4,
	/* syscall has string as sixth arg */
	EM_str_6 = 1 << 5,
	/* all strings */
	EM_strings = EM_str_1 | EM_str_2 | EM_str_3 |
			EM_str_4 | EM_str_5 | EM_str_6,

	/* syscall has fd as first arg */
	EM_fd_1 = 1 << 6,
	/* syscall has fd as second arg */
	EM_fd_2 = 1 << 7,
	/* syscall has fd as third arg */
	EM_fd_3 = 1 << 8,
	/* syscall has fd as fourth arg */
	EM_fd_4 = 1 << 9,
	/* syscall has fd as fifth arg */
	EM_fd_5 = 1 << 10,
	/* syscall has fd as sixth arg */
	EM_fd_6 = 1 << 11,

	/* syscall has path as first arg */
	EM_path_1 = 1 << 12,
	/* syscall has path as second arg */
	EM_path_2 = 1 << 13,
	/* syscall has path as third arg */
	EM_path_3 = 1 << 14,
	/* syscall has path as fourth arg */
	EM_path_4 = 1 << 15,
	/* syscall has path as fifth arg */
	EM_path_5 = 1 << 16,
	/* syscall has path as sixth arg */
	EM_path_6 = 1 << 17,

	/* '*at' type syscall (dirfd + path) */
	EM_fileat = 1 << 18,
	/* double '*at' type syscall (dirfd + path) */
	EM_fileat2 = EM_fileat | 1 << 19,

	/* syscall does not return */
	EM_no_ret = 1 << 20,
	/* syscall returns a file descriptor */
	EM_rfd = 1 << 21,
	/* syscall returns a PID */
	EM_rpid = 1 << 22,

	/* syscall returns a file handle as third arg: name_to_handle_at() */
	EM_rhandle_3 = 1 << 23,
	/* syscall takes a file handle as second arg: open_by_handle_at() */
	EM_handle_2 = 1 << 24,

	/* AT_EMPTY_PATH can be at the 4th argument (fstatat and newfstatat) */
	EM_aep_arg_4 = 1 << 25,
	/* AT_EMPTY_PATH can be at the 5th argument (linkat and fchownat) */
	EM_aep_arg_5 = 1 << 26,

	/* disabled syscall */
	EM_DISABLED = 1 << 31,

	/* syscall has strings as first and second args. rename() */
	EM_str_1_2 = EM_str_1 | EM_str_2,
	/* syscall has strings as first and third args. linkat() */
	EM_str_1_3 = EM_str_1 | EM_str_3,
	/* syscall has strings as second and forth args. renameat() */
	EM_str_2_4 = EM_str_2 | EM_str_4,
	/* syscall has strings as 1st, 2nd and 3rd args. mount() */
	EM_str_1_2_3 = EM_str_1 | EM_str_2 | EM_str_3,

	/* syscall has paths as first and second args. rename() */
	EM_path_1_2 = EM_path_1 | EM_path_2,
	/* syscall has fs paths as first and third args. linkat() */
	EM_path_1_3 = EM_path_1 | EM_path_3,
	/* syscall has fs paths as second and forth args. renameat() */
	EM_path_2_4 = EM_path_2 | EM_path_4,

	/* syscall has fd as first and third args. renameat() */
	EM_fd_1_3 = EM_fd_1 | EM_fd_3,
};

enum {
	/* size of table of syscalls */
	SC_TBL_SIZE = 1000,

	/* maximum number of syscall's arguments */
	SC_ARGS_MAX = 6,

	/* maximum length of a syscall's number: 3 digits + '\0' */
	SC_NUM_LEN = 3,

	/* maximum length of a syscall's name */
	SC_NAME_LEN = 31
};

/* properties of syscall with number 'num' */
struct syscall_descriptor {

	/* syscall number */
	uint32_t num;

	/* syscall number as string */
	char num_str[SC_NUM_LEN + 1];

	/* name of in-kernel syscall's handler */
	char *handler_name;

	/* syscall name buffer */
	char syscall_name[SC_NAME_LEN + 1];

	/* length of the syscall's name */
	uint32_t name_length;

	/* number of syscall's arguments */
	uint32_t args_qty;

	/* mask of flags */
	uint32_t mask;

	/* syscall is available in current kernel */
	int32_t available;

	/* number of string arguments */
	uint32_t nstrings;

	/* positions of string arguments */
	char positions[SC_ARGS_MAX];
};

extern struct syscall_descriptor Syscall_array[SC_TBL_SIZE];

void init_syscalls_table(void);
int print_syscalls_table(FILE *f);
int dump_syscalls_table(const char *path);

#endif /* EBPF_SYSCALLS_H */
