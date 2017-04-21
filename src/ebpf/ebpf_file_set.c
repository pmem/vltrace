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

const char *ebpf_trace_h_file = 	"trace.h";
const char *ebpf_head_file = 		"trace_head.c";

const char *ebpf_0_str_file =		"template_0_str.c";

const char *ebpf_1_str_sl_file =	"template_1_str-sl.c";
const char *ebpf_2_str_sl_file =	"template_2_str-sl.c";
const char *ebpf_3_str_sl_file =	"template_3_str-sl.c";

const char *ebpf_1_str_ml_file =	"template_1_str-ml.c";
const char *ebpf_2_str_ml_file =	"template_2_str-ml.c";
const char *ebpf_3_str_ml_file =	"template_3_str-ml.c";

const char *ebpf_fork_file =		"template_fork.c";
const char *ebpf_vfork_file =		"template_vfork.c";
const char *ebpf_clone_file =		"template_clone.c";
const char *ebpf_exit_file =		"template_exit.c";

const char *ebpf_tracepoints_file =	"template_tracepoints.c";

const char *ebpf_pid_own_file =		"pid_check_own_hook.c";
const char *ebpf_pid_ff_disabled_file = "pid_check_ff_disabled_hook.c";
const char *ebpf_pid_ff_full_file =	"pid_check_ff_full_hook.c";


const char *ebpf_file_table[4][3] = {
	{
		"template_0_str.c",
		"template_0_str.c",
		"template_0_str.c",
	},
	{
		"template_1_str-sl.c",
		"template_1_str-sl.c",
		"template_1_str-ml.c",
	},
	{
		"template_2_str-sl.c",
		"template_2_str-ml.c",
		"template_2_str-ml.c",
	},
	{
		"template_3_str-sl.c",
		"template_3_str-ml.c",
		"template_3_str-ml.c",
	}
};

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
	if (0 == strcmp(ebpf_trace_h_file, fn)) {
		return BINARY_FILE_CONTENT(trace_h);
	} else if (0 == strcmp(ebpf_head_file, fn)) {
		return BINARY_FILE_CONTENT(trace_head_c);

	} else if (0 == strcmp(ebpf_0_str_file, fn)) {
		return BINARY_FILE_CONTENT(template_0_str_c);

	} else if (0 == strcmp(ebpf_1_str_sl_file, fn)) {
		return BINARY_FILE_CONTENT(template_1_str_sl_c);
	} else if (0 == strcmp(ebpf_1_str_ml_file, fn)) {
		return BINARY_FILE_CONTENT(template_1_str_ml_c);

	} else if (0 == strcmp(ebpf_2_str_sl_file, fn)) {
		return BINARY_FILE_CONTENT(template_2_str_sl_c);
	} else if (0 == strcmp(ebpf_2_str_ml_file, fn)) {
		return BINARY_FILE_CONTENT(template_2_str_ml_c);

	} else if (0 == strcmp(ebpf_3_str_sl_file, fn)) {
		return BINARY_FILE_CONTENT(template_3_str_sl_c);
	} else if (0 == strcmp(ebpf_3_str_ml_file, fn)) {
		return BINARY_FILE_CONTENT(template_3_str_ml_c);

	} else if (0 == strcmp(ebpf_fork_file, fn)) {
		return BINARY_FILE_CONTENT(template_fork_c);
	} else if (0 == strcmp(ebpf_vfork_file, fn)) {
		return BINARY_FILE_CONTENT(template_vfork_c);
	} else if (0 == strcmp(ebpf_clone_file, fn)) {
		return BINARY_FILE_CONTENT(template_clone_c);
	} else if (0 == strcmp(ebpf_exit_file, fn)) {
		return BINARY_FILE_CONTENT(template_exit_c);

	} else if (0 == strcmp(ebpf_tracepoints_file, fn)) {
		return BINARY_FILE_CONTENT(template_tracepoints_c);

	} else if (0 == strcmp(ebpf_pid_own_file, fn)) {
		return BINARY_FILE_CONTENT(pid_check_own_hook_c);
	} else if (0 == strcmp(ebpf_pid_ff_disabled_file, fn)) {
		return BINARY_FILE_CONTENT(pid_check_ff_disabled_hook_c);
	} else if (0 == strcmp(ebpf_pid_ff_full_file, fn)) {
		return BINARY_FILE_CONTENT(pid_check_ff_full_hook_c);
	}

	return NULL;
}
