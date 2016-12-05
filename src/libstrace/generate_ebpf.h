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
 * generate_ebpf.h -- generate_ebpf() function
 */

#ifndef GENERATE_EBPF_H
#define GENERATE_EBPF_H

extern const char *ebpf_trace_h_file;

extern const char *ebpf_head_file;
extern const char *ebpf_libc_tmpl_file;
extern const char *ebpf_file_tmpl_file;
extern const char *ebpf_fileat_tmpl_file;
extern const char *ebpf_kern_tmpl_file;
extern const char *ebpf_tp_all_file;

char *generate_ebpf(void);

extern const char _binary_trace_fileat_tmpl_c_size[];
extern const char _binary_trace_fileat_tmpl_c_start[];

extern const char _binary_trace_file_tmpl_c_size[];
extern const char _binary_trace_file_tmpl_c_start[];

extern const char _binary_trace_head_c_size[];
extern const char _binary_trace_head_c_start[];

extern const char _binary_trace_h_size[];
extern const char _binary_trace_h_start[];

extern const char _binary_trace_kern_tmpl_c_size[];
extern const char _binary_trace_kern_tmpl_c_start[];

extern const char _binary_trace_libc_tmpl_c_size[];
extern const char _binary_trace_libc_tmpl_c_start[];

extern const char _binary_trace_tp_all_c_size[];
extern const char _binary_trace_tp_all_c_start[];

#endif
