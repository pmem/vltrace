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

#include <stdlib.h>
#include <string.h>

#include "ebpf_file_set.h"

const char *ebpf_trace_h_file = "trace.h";

const char *ebpf_head_file = "trace_head.c";

const char *ebpf_file_tmpl_sl_file =
		"trace_file_tmpl-sl.c";
const char *ebpf_fileat_tmpl_sl_file =
		"trace_fileat_tmpl-sl.c";
const char *ebpf_fs_path_1_2_arg_tmpl_sl_file =
		"trace_fs_path_1_2_arg_tmpl-sl.c";
const char *ebpf_fs_path_1_3_arg_tmpl_sl_file =
		"trace_fs_path_1_3_arg_tmpl-sl.c";
const char *ebpf_fs_path_2_4_arg_tmpl_sl_file =
		"trace_fs_path_2_4_arg_tmpl-sl.c";

const char *ebpf_file_tmpl_ml_file =
		"trace_file_tmpl-ml.c";
const char *ebpf_fileat_tmpl_ml_file =
		"trace_fileat_tmpl-ml.c";
const char *ebpf_fs_path_1_2_arg_tmpl_ml_file =
		"trace_fs_path_1_2_arg_tmpl-ml.c";
const char *ebpf_fs_path_1_3_arg_tmpl_ml_file =
		"trace_fs_path_1_3_arg_tmpl-ml.c";
const char *ebpf_fs_path_2_4_arg_tmpl_ml_file =
		"trace_fs_path_2_4_arg_tmpl-ml.c";

const char *ebpf_fork_tmpl_file = "trace_fork_tmpl.c";
const char *ebpf_vfork_tmpl_file = "trace_vfork_tmpl.c";
const char *ebpf_clone_tmpl_file = "trace_clone_tmpl.c";
const char *ebpf_exit_tmpl_file = "trace_exit_tmpl.c";

const char *ebpf_basic_tmpl_file = "trace_basic_tmpl.c";
const char *ebpf_tp_all_file = "trace_tp_all.c";

const char *ebpf_pid_check_own_hook_file =
		"pid_check_own_hook.c";
const char *ebpf_pid_check_ff_disabled_hook_file =
		"pid_check_ff_disabled_hook.c";
const char *ebpf_pid_check_ff_full_hook_file =
		"pid_check_ff_full_hook.c";

/*
 * ebpf_load_file -- This function return strndup() from embedded body of
 *                   'virtual' file.
 */
char *
ebpf_load_file(const char *const fn)
{
	if (NULL == fn)
		return NULL;

	/* fallback to embedded ones */
	if (0 == strcmp(ebpf_head_file, fn)) {
		return BINARY_FILE_CONTENT(trace_head_c);
	} else if (0 == strcmp(ebpf_basic_tmpl_file, fn)) {
		return BINARY_FILE_CONTENT(trace_basic_tmpl_c);
	} else if (0 == strcmp(ebpf_file_tmpl_ml_file, fn)) {
		return BINARY_FILE_CONTENT(trace_file_tmpl_ml_c);
	} else if (0 == strcmp(ebpf_file_tmpl_sl_file, fn)) {
		return BINARY_FILE_CONTENT(trace_file_tmpl_sl_c);
	} else if (0 == strcmp(ebpf_fileat_tmpl_ml_file, fn)) {
		return BINARY_FILE_CONTENT(trace_fileat_tmpl_ml_c);
	} else if (0 == strcmp(ebpf_fileat_tmpl_sl_file, fn)) {
		return BINARY_FILE_CONTENT(trace_fileat_tmpl_sl_c);
	} else if (0 == strcmp(ebpf_tp_all_file, fn)) {
		return BINARY_FILE_CONTENT(trace_tp_all_c);
	} else if (0 == strcmp(ebpf_trace_h_file, fn)) {
		return BINARY_FILE_CONTENT(trace_h);
	} else if (0 == strcmp(ebpf_fs_path_1_2_arg_tmpl_ml_file, fn)) {
		return BINARY_FILE_CONTENT(trace_fs_path_1_2_arg_tmpl_ml_c);
	} else if (0 == strcmp(ebpf_fs_path_1_3_arg_tmpl_ml_file, fn)) {
		return BINARY_FILE_CONTENT(trace_fs_path_1_3_arg_tmpl_ml_c);
	} else if (0 == strcmp(ebpf_fs_path_2_4_arg_tmpl_ml_file, fn)) {
		return BINARY_FILE_CONTENT(trace_fs_path_2_4_arg_tmpl_ml_c);
	} else if (0 == strcmp(ebpf_fs_path_1_2_arg_tmpl_sl_file, fn)) {
		return BINARY_FILE_CONTENT(trace_fs_path_1_2_arg_tmpl_sl_c);
	} else if (0 == strcmp(ebpf_fs_path_1_3_arg_tmpl_sl_file, fn)) {
		return BINARY_FILE_CONTENT(trace_fs_path_1_3_arg_tmpl_sl_c);
	} else if (0 == strcmp(ebpf_fs_path_2_4_arg_tmpl_sl_file, fn)) {
		return BINARY_FILE_CONTENT(trace_fs_path_2_4_arg_tmpl_sl_c);
	} else if (0 == strcmp(ebpf_fork_tmpl_file, fn)) {
		return BINARY_FILE_CONTENT(trace_fork_tmpl_c);
	} else if (0 == strcmp(ebpf_vfork_tmpl_file, fn)) {
		return BINARY_FILE_CONTENT(trace_vfork_tmpl_c);
	} else if (0 == strcmp(ebpf_clone_tmpl_file, fn)) {
		return BINARY_FILE_CONTENT(trace_clone_tmpl_c);
	} else if (0 == strcmp(ebpf_exit_tmpl_file, fn)) {
		return BINARY_FILE_CONTENT(trace_exit_tmpl_c);
	} else if (0 == strcmp(ebpf_pid_check_own_hook_file, fn)) {
		return BINARY_FILE_CONTENT(pid_check_own_hook_c);
	} else if (0 == strcmp(ebpf_pid_check_ff_disabled_hook_file, fn)) {
		return BINARY_FILE_CONTENT(pid_check_ff_disabled_hook_c);
	} else if (0 == strcmp(ebpf_pid_check_ff_full_hook_file, fn)) {
		return BINARY_FILE_CONTENT(pid_check_ff_full_hook_c);
	}

	return NULL;
}
