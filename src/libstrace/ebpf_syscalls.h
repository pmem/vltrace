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
 * ebpf_syscalls.h -- a list of glibc-supported syscalls.
 */

#ifndef EBPF_SYSCALLS_H
#define EBPF_SYSCALLS_H

#include <sys/syscall.h>

enum masks_t {
	/* syscall returns an fd */
	EM_rdesc = 1 << 0,
	/* syscall accepts fd as a first arg */
	EM_desc = 1 << 1,
	/* syscall accepts fs path as a first arg */
	EM_file = 1 << 2,
	/* syscall accepts dir fd as a first arg and path as a second */
	EM_fileat = 1 << 3,
	/* syscall is actual for PMemFile */
	EM_pmemfile = 1 << 4,
	EM_kern_all = 1 << 5,
	EM_libc_all = 1 << 6,

	EM_ALL = -1,
};

struct sc_t {
	unsigned num;
	const char *num_name;
	const char *hlr_name;
	unsigned masks;
};

/* Currently glibc does not have appropriate macro for it */
enum { SC_TBL_SIZE = 1024 };
extern struct sc_t sc_tbl[SC_TBL_SIZE];

#endif /* EBPF_SYSCALLS_H */
