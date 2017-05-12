/*
 * Copyright 2017, Intel Corporation
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
 * ebpf_file_set.c -- A set of ebpf files
 */

#ifndef EBPF_FILE_SET_H
#define EBPF_FILE_SET_H

#include <stdint.h>

/* names */

extern const char *ebpf_trace_h_file;
extern const char *ebpf_head_file;

extern const char *ebpf_0_str_file;

extern const char *ebpf_1_str_sl_file;
extern const char *ebpf_2_str_sl_file;
extern const char *ebpf_3_str_sl_file;

extern const char *ebpf_2_str_ml_file;
extern const char *ebpf_3_str_ml_file;

extern const char *ebpf_1_str_const_file;
extern const char *ebpf_2_str_const_file;
extern const char *ebpf_3_str_const_file;

extern const char *ebpf_1_str_full_file;
extern const char *ebpf_2_str_full_file;
extern const char *ebpf_3_str_full_file;

extern const char *ebpf_fork_file;
extern const char *ebpf_vfork_file;
extern const char *ebpf_clone_file;
extern const char *ebpf_exit_file;

extern const char *ebpf_tracepoints_file;

extern const char *ebpf_const_string_mode;
extern const char *ebpf_full_string_mode;

extern const char *ebpf_pid_own_file;
extern const char *ebpf_pid_ff_disabled_file;
extern const char *ebpf_pid_ff_full_file;

extern const char *ebpf_file_table[4][4];

/* functions */

char *ebpf_load_file(const char *fn);

/* bodies */

extern const char _binary_template_1_str_sl_c_end[];
extern const char _binary_template_1_str_sl_c_start[];

extern const char _binary_template_2_str_sl_c_end[];
extern const char _binary_template_2_str_sl_c_start[];

extern const char _binary_template_3_str_sl_c_end[];
extern const char _binary_template_3_str_sl_c_start[];

extern const char _binary_template_2_str_ml_c_end[];
extern const char _binary_template_2_str_ml_c_start[];

extern const char _binary_template_3_str_ml_c_end[];
extern const char _binary_template_3_str_ml_c_start[];

extern const char _binary_template_1_str_const_c_end[];
extern const char _binary_template_1_str_const_c_start[];

extern const char _binary_template_2_str_const_c_end[];
extern const char _binary_template_2_str_const_c_start[];

extern const char _binary_template_3_str_const_c_end[];
extern const char _binary_template_3_str_const_c_start[];

extern const char _binary_template_1_str_full_c_end[];
extern const char _binary_template_1_str_full_c_start[];

extern const char _binary_template_2_str_full_c_end[];
extern const char _binary_template_2_str_full_c_start[];

extern const char _binary_template_3_str_full_c_end[];
extern const char _binary_template_3_str_full_c_start[];

extern const char _binary_template_fork_c_end[];
extern const char _binary_template_fork_c_start[];

extern const char _binary_template_vfork_c_end[];
extern const char _binary_template_vfork_c_start[];

extern const char _binary_template_clone_c_end[];
extern const char _binary_template_clone_c_start[];

extern const char _binary_template_exit_c_end[];
extern const char _binary_template_exit_c_start[];

extern const char _binary_trace_head_c_end[];
extern const char _binary_trace_head_c_start[];

extern const char _binary_trace_h_end[];
extern const char _binary_trace_h_start[];

extern const char _binary_template_0_str_c_end[];
extern const char _binary_template_0_str_c_start[];

extern const char _binary_template_tracepoints_c_end[];
extern const char _binary_template_tracepoints_c_start[];

extern const char _binary_macro_const_string_mode_c_end[];
extern const char _binary_macro_const_string_mode_c_start[];

extern const char _binary_macro_full_string_mode_c_end[];
extern const char _binary_macro_full_string_mode_c_start[];

extern const char _binary_macro_pid_own_c_end[];
extern const char _binary_macro_pid_own_c_start[];

extern const char _binary_macro_pid_ff_disabled_c_end[];
extern const char _binary_macro_pid_ff_disabled_c_start[];

extern const char _binary_macro_pid_ff_full_c_end[];
extern const char _binary_macro_pid_ff_full_c_start[];

#define BINARY_FILE_SIZE(name) (size_t)((uintptr_t)_binary_##name##_end -\
		(uintptr_t)_binary_##name##_start)
#define BINARY_FILE_CONTENT(name) strndup(_binary_##name##_start, \
		BINARY_FILE_SIZE(name))

#endif /* EBPF_FILE_SET_H */
