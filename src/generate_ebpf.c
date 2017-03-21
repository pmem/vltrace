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
 * generate_ebpf.h -- generate_ebpf() function
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "ebpf/ebpf_file_set.h"

#include "strace.ebpf.h"
#include "utils.h"
#include "ebpf_syscalls.h"
#include "generate_ebpf.h"

/*
 * get_sc_num -- This function returns syscall number by name according to
 *     libc knowledge.
 */
static int
get_sc_num(const char *sc_name)
{
	for (int i = 0; i < SC_TBL_SIZE; i++) {
		if (NULL == Syscall_array[i].handler_name)
			continue;

		if (!strcasecmp(sc_name, Syscall_array[i].handler_name))
			return i;
	}

	return -1;
}

static char *
load_ebpf_fileat_tmpl(void)
{
	char *text = NULL;

	switch (Args.fnr_mode) {
	case E_FNR_FAST:
		text = load_file_no_cr(ebpf_fileat_tmpl_sl_file);
		break;
	case E_FNR_NAME_MAX:
		text = load_file_no_cr(ebpf_fileat_tmpl_ml_file);
		break;
	case E_FNR_FULL:
		/* XXX */
	default:
		assert(false);
		break;
	}

	return text;
}

static char *
load_ebpf_file_tmpl(void)
{
	char *text = NULL;

	switch (Args.fnr_mode) {
	case E_FNR_FAST:
		text = load_file_no_cr(ebpf_file_tmpl_sl_file);
		break;
	case E_FNR_NAME_MAX:
		text = load_file_no_cr(ebpf_file_tmpl_ml_file);
		break;
	case E_FNR_FULL:
		/* XXX */
	default:
		assert(false);
		break;
	}

	return text;
}

static char *
get_libc_tmpl(unsigned i)
{
	char *text = NULL;

	if (NULL == Syscall_array[i].handler_name)
		return NULL;

	if (EM_fs_path_1_2_arg ==
			(EM_fs_path_1_2_arg & Syscall_array[i].masks)) {
		switch (Args.fnr_mode) {
		case E_FNR_FAST:
			text = load_file_no_cr(
					ebpf_fs_path_1_2_arg_tmpl_sl_file);
			break;
		case E_FNR_NAME_MAX:
			text = load_file_no_cr(
					ebpf_fs_path_1_2_arg_tmpl_ml_file);
			break;
		case E_FNR_FULL:
			/* XXX */
		default:
			assert(false);
			break;
		}
	} else if (EM_fs_path_1_3_arg ==
			(EM_fs_path_1_3_arg & Syscall_array[i].masks)) {
		switch (Args.fnr_mode) {
		case E_FNR_FAST:
			text = load_file_no_cr(
					ebpf_fs_path_1_3_arg_tmpl_sl_file);
			break;
		case E_FNR_NAME_MAX:
			text = load_file_no_cr(
					ebpf_fs_path_1_3_arg_tmpl_ml_file);
			break;
		case E_FNR_FULL:
			/* XXX */
		default:
			assert(false);
			break;
		}
	} else if (EM_fs_path_2_4_arg ==
			(EM_fs_path_2_4_arg & Syscall_array[i].masks)) {
		switch (Args.fnr_mode) {
		case E_FNR_FAST:
			text = load_file_no_cr(
					ebpf_fs_path_2_4_arg_tmpl_sl_file);
			break;
		case E_FNR_NAME_MAX:
			text = load_file_no_cr(
					ebpf_fs_path_2_4_arg_tmpl_ml_file);
			break;
		case E_FNR_FULL:
			/* XXX */
		default:
			assert(false);
			break;
		}
	} else if (E_FF_FULL == Args.ff_mode &&
			EM_rpid == (EM_rpid & Syscall_array[i].masks)) {
		switch (i) {
		case __NR_clone:
			text = load_file_no_cr(ebpf_clone_tmpl_file);
			break;
		case __NR_vfork:
			text = load_file_no_cr(ebpf_vfork_tmpl_file);
			break;
		case __NR_fork:
			text = load_file_no_cr(ebpf_fork_tmpl_file);
			break;

		default:
			assert(false);
			break;
		};
	} else if (EM_file == (EM_file & Syscall_array[i].masks)) {
		text = load_ebpf_file_tmpl();
	} else if (EM_fileat == (EM_fileat & Syscall_array[i].masks)) {
		text = load_ebpf_fileat_tmpl();
	} else {
		text = load_file_no_cr(ebpf_libc_tmpl_file);
	}

	if (NULL == text)
		return NULL;

	str_replace_all(&text, "SYSCALL_NR",
			Syscall_array[i].num_name);

	return text;
}

/*
 * generate_ebpf_kp_libc_all -- This function generates eBPF handler for
 *     syscalls which are known to glibc.
 */
static void
generate_ebpf_kp_libc_all(FILE *ts)
{
	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		size_t fw_res;
		char *text;

		text = get_libc_tmpl(i);

		if (NULL == text)
			continue;

		str_replace_all(&text, "SYSCALL_NAME",
				Syscall_array[i].handler_name);

		fw_res = fwrite(text, strlen(text), 1, ts);

		assert(fw_res > 0);

		free(text);

		text = NULL;
	}
}

/* XXX HACK: this syscall is exported by kernel twice. */
static unsigned SyS_sigsuspend = 0;

/*
 * generate_ebpf_kp_kern_all -- This function generates universal default eBPF
 *     syscall handler.
 *
 * Primary purpose of generated handler - new and unknown syscalls.
 */
static void
generate_ebpf_kp_kern_all(FILE *ts)
{
	char *text = NULL;


	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	FILE *in = fopen(Debug_tracing_aff, "r");

	if (NULL == in) {
		fprintf(stderr, "%s: ERROR: '%m'\n", __func__);
		return;
	}

	while ((read = getline(&line, &len, in)) != -1) {
		int sc_num;
		size_t fw_res;

		if (!is_a_sc(line, read - 1))
			continue;

		line [read - 1] = '\0';

		/* XXX HACK: this syscall is exported by kernel twice. */
		if (!strcasecmp("SyS_sigsuspend", line)) {
			if (SyS_sigsuspend)
				continue;

			SyS_sigsuspend ++;
		}

		sc_num = get_sc_num(line);

		/* Some optimization for glibc-supported syscalls */
		if (0 <= sc_num) {
			text = get_libc_tmpl((unsigned)sc_num);
		} else {
			text = load_file_no_cr(ebpf_kern_tmpl_file);
		}

		str_replace_all(&text, "SYSCALL_NAME", line);

		fw_res = fwrite(text, strlen(text), 1, ts);

		assert(fw_res > 0);

		free(text);

		text = NULL;
	}

	free(line);
	fclose(in);
}

/*
 * generate_ebpf_kp_file -- This function generates eBPF syscall handlers
 *     specific for syscalls with filename in arguments.
 */
static void
generate_ebpf_kp_file(FILE *ts)
{
	char *text = NULL;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		size_t fw_res;

		if (NULL == Syscall_array[i].handler_name)
			continue;

		if (EM_file != (EM_file & Syscall_array[i].masks))
			continue;

		text = load_ebpf_file_tmpl();

		str_replace_all(&text, "SYSCALL_NR",
				Syscall_array[i].num_name);
		str_replace_all(&text, "SYSCALL_NAME",
				Syscall_array[i].handler_name);

		fw_res = fwrite(text, strlen(text), 1, ts);

		assert(fw_res > 0);

		free(text);

		text = NULL;
	}
}

/*
 * generate_ebpf_kp_fileat -- This function generates eBPF syscall handlers
 *     specific for syscalls with relative filename in arguments.
 */
static void
generate_ebpf_kp_fileat(FILE *ts)
{
	char *text = NULL;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		size_t fw_res;

		if (NULL == Syscall_array[i].handler_name)
			continue;

		if (EM_fileat != (EM_fileat & Syscall_array[i].masks))
			continue;

		text = load_ebpf_fileat_tmpl();

		str_replace_all(&text, "SYSCALL_NR",
				Syscall_array[i].num_name);
		str_replace_all(&text, "SYSCALL_NAME",
				Syscall_array[i].handler_name);

		fw_res = fwrite(text, strlen(text), 1, ts);

		assert(fw_res > 0);

		free(text);

		text = NULL;
	}
}

/*
 * generate_ebpf_kp_desc -- This function generates eBPF syscall handlers
 *     specific for syscalls with file-descriptor in arguments.
 */
static void
generate_ebpf_kp_desc(FILE *ts)
{
	char *text = NULL;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		size_t fw_res;

		if (NULL == Syscall_array[i].handler_name)
			continue;

		if (EM_desc != (EM_desc & Syscall_array[i].masks))
			continue;

		text = load_file_no_cr(ebpf_libc_tmpl_file);

		str_replace_all(&text, "SYSCALL_NR",
				Syscall_array[i].num_name);
		str_replace_all(&text, "SYSCALL_NAME",
				Syscall_array[i].handler_name);

		fw_res = fwrite(text, strlen(text), 1, ts);

		assert(fw_res > 0);

		free(text);

		text = NULL;
	}
}

/*
 * generate_ebpf_kp_fileio -- This function generates eBPF syscall handlers
 *     specific for syscalls which operate on files.
 */
static void
generate_ebpf_kp_fileio(FILE *ts)
{
	generate_ebpf_kp_file(ts);
	generate_ebpf_kp_desc(ts);
	generate_ebpf_kp_fileat(ts);
}

/*
 * generate_ebpf_tp_all -- This function generates eBPF syscall handler
 *     specific for tracepoint feature.
 */
static void
generate_ebpf_tp_all(FILE *ts)
{
	char *text = load_file_no_cr(ebpf_tp_all_file);

	size_t fw_res = fwrite(text, strlen(text), 1, ts);

	assert(fw_res > 0);

	free(text);

	text = NULL;
}

/*
 * generate_ebpf_common -- This function generates eBPF syscall handler
 *     specific for kprobes and tracepoints.
 */
static void
generate_ebpf_common(FILE *ts)
{
	generate_ebpf_kp_kern_all(ts);
	generate_ebpf_tp_all(ts);
}

/*
 * generate_ebpf -- This function parses and process expression.
 */
char *
generate_ebpf()
{
	char *text = NULL;
	size_t text_size = 0;

	FILE *ts = open_memstream(&text, &text_size);

	/* Let's from header */
	char *head = load_file(ebpf_head_file);
	size_t fw_res = fwrite(head, strlen(head), 1, ts);

	assert(fw_res > 0);
	free(head);

	head = NULL;

	if (NULL == Args.expr) {
		fprintf(stderr, "%s: defaulting to 'trace=kp-kern-all'.\n",
				__func__);
		generate_ebpf_kp_kern_all(ts);
	} else if (!strcasecmp(Args.expr, "trace=kp-libc-all")) {
		generate_ebpf_kp_libc_all(ts);
	} else if (!strcasecmp(Args.expr, "trace=kp-kern-all")) {
		generate_ebpf_kp_kern_all(ts);
	} else if (!strcasecmp(Args.expr, "trace=kp-file")) {
		generate_ebpf_kp_file(ts);
	} else if (!strcasecmp(Args.expr, "trace=kp-desc")) {
		generate_ebpf_kp_desc(ts);
	} else if (!strcasecmp(Args.expr, "trace=kp-fileio")) {
		generate_ebpf_kp_fileio(ts);
	} else if (!strcasecmp(Args.expr, "trace=tp-all")) {
		generate_ebpf_tp_all(ts);
	} else if (!strcasecmp(Args.expr, "trace=common")) {
		generate_ebpf_common(ts);
	}

	fclose(ts);
	return text;
}

/*
 * This function apply process-attach code to generated code with handlers
 */
void
apply_process_attach_code(char **const pbpf_str)
{
	if (0 < Args.pid) {
		char str[64];
		int snp_res;
		char *pid_check_hook;

		snp_res = snprintf(str, sizeof(str), "%d", Args.pid);

		assert(snp_res > 0);

		pid_check_hook = load_pid_check_hook(Args.ff_mode);

		assert(NULL != pid_check_hook);

		str_replace_all(&pid_check_hook, "TRACED_PID", str);

		str_replace_all(pbpf_str, "PID_CHECK_HOOK", pid_check_hook);

		free(pid_check_hook);
	} else {
		str_replace_all(pbpf_str, "PID_CHECK_HOOK", "");
	}
}

/*
 * This function apply trace.h because this way is the safest.
 */
void
apply_trace_h_header(char **const pbpf_str)
{
	char *trace_h = load_file_no_cr(ebpf_trace_h_file);

	str_replace_all(pbpf_str, "#include \"trace.h\"\n", trace_h);

	free(trace_h);
}

/*
 * Print ebpf code with marks for debug reason
 */
void
fprint_ebpf_code_with_debug_marks(FILE *f, const char *bpf_str)
{
	fprintf(f, "\t>>>>> Generated eBPF code <<<<<\n");

	if (bpf_str) {
		size_t fw_res;

		fw_res = fwrite(bpf_str, strlen(bpf_str), 1, f);

		assert(fw_res > 0);
	}

	fprintf(f, "\t>>>>> EndOf generated eBPF code <<<<<<\n");
}
