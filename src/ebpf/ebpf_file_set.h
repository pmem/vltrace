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

/* names */

extern const char *ebpf_trace_h_file;

extern const char *ebpf_head_file;

extern const char *ebpf_file_tmpl_ml_file;
extern const char *ebpf_fileat_tmpl_ml_file;
extern const char *ebpf_fs_path_1_2_arg_tmpl_ml_file;
extern const char *ebpf_fs_path_1_3_arg_tmpl_ml_file;
extern const char *ebpf_fs_path_2_4_arg_tmpl_ml_file;

extern const char *ebpf_file_tmpl_sl_file;
extern const char *ebpf_fileat_tmpl_sl_file;
extern const char *ebpf_fs_path_1_2_arg_tmpl_sl_file;
extern const char *ebpf_fs_path_1_3_arg_tmpl_sl_file;
extern const char *ebpf_fs_path_2_4_arg_tmpl_sl_file;

extern const char *ebpf_fork_tmpl_file;
extern const char *ebpf_vfork_tmpl_file;
extern const char *ebpf_clone_tmpl_file;

extern const char *ebpf_libc_tmpl_file;
extern const char *ebpf_kern_tmpl_file;
extern const char *ebpf_tp_all_file;

extern const char *ebpf_pid_check_ff_disabled_hook_file;
extern const char *ebpf_pid_check_ff_fast_hook_file;
extern const char *ebpf_pid_check_ff_full_hook_file;

/* functions */

char *ebpf_load_file(const char *fn);

/* bodies */

extern const char _binary_trace_file_tmpl_sl_c_size[];
extern const char _binary_trace_file_tmpl_sl_c_start[];

extern const char _binary_trace_fileat_tmpl_sl_c_size[];
extern const char _binary_trace_fileat_tmpl_sl_c_start[];

extern const char _binary_trace_fs_path_1_2_arg_tmpl_sl_c_size[];
extern const char _binary_trace_fs_path_1_2_arg_tmpl_sl_c_start[];

extern const char _binary_trace_fs_path_1_3_arg_tmpl_sl_c_size[];
extern const char _binary_trace_fs_path_1_3_arg_tmpl_sl_c_start[];

extern const char _binary_trace_fs_path_2_4_arg_tmpl_sl_c_size[];
extern const char _binary_trace_fs_path_2_4_arg_tmpl_sl_c_start[];

extern const char _binary_trace_file_tmpl_ml_c_size[];
extern const char _binary_trace_file_tmpl_ml_c_start[];

extern const char _binary_trace_fileat_tmpl_ml_c_size[];
extern const char _binary_trace_fileat_tmpl_ml_c_start[];

extern const char _binary_trace_fs_path_1_2_arg_tmpl_ml_c_size[];
extern const char _binary_trace_fs_path_1_2_arg_tmpl_ml_c_start[];

extern const char _binary_trace_fs_path_1_3_arg_tmpl_ml_c_size[];
extern const char _binary_trace_fs_path_1_3_arg_tmpl_ml_c_start[];

extern const char _binary_trace_fs_path_2_4_arg_tmpl_ml_c_size[];
extern const char _binary_trace_fs_path_2_4_arg_tmpl_ml_c_start[];

extern const char _binary_trace_fork_tmpl_c_size[];
extern const char _binary_trace_fork_tmpl_c_start[];

extern const char _binary_trace_vfork_tmpl_c_size[];
extern const char _binary_trace_vfork_tmpl_c_start[];

extern const char _binary_trace_clone_tmpl_c_size[];
extern const char _binary_trace_clone_tmpl_c_start[];

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

extern const char _binary_pid_check_ff_disabled_hook_c_size[];
extern const char _binary_pid_check_ff_disabled_hook_c_start[];

extern const char _binary_pid_check_ff_fast_hook_c_size[];
extern const char _binary_pid_check_ff_fast_hook_c_start[];

extern const char _binary_pid_check_ff_full_hook_c_size[];
extern const char _binary_pid_check_ff_full_hook_c_start[];

#endif /* EBPF_FILE_SET_H */
