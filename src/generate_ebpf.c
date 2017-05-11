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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ebpf/trace.h"
#include "ebpf/ebpf_file_set.h"

#include "strace.ebpf.h"
#include "utils.h"
#include "ebpf_syscalls.h"
#include "generate_ebpf.h"
#include "syscalls_numbers.h"

/*
 * get_sc_num -- this function returns syscall number by name
 *               according to the table of syscalls
 */
static int
get_sc_num(const char *sc_name)
{
	static int last_free = __NR_LAST_UNKNOWN;
	unsigned i;

	assert(__NR_LAST_UNKNOWN <= SC_TBL_SIZE);

	for (i = 0; i < __NR_LAST_UNKNOWN; i++) {
		if (NULL == Syscall_array[i].handler_name)
			continue;

		if (Syscall_array[i].attached)
			continue;

		if (strcasecmp(sc_name, Syscall_array[i].handler_name) == 0) {
			Syscall_array[i].attached = 1;
			return i;
		}
	}

	/* add unknown syscall to the array */
	i = last_free++;

	Syscall_array[i].num = i;
	sprintf(Syscall_array[i].num_str, "%u", Syscall_array[i].num);

	/* will be freed in free_syscalls_table() */
	Syscall_array[i].handler_name = strdup(sc_name);

	Syscall_array[i].name_length = strlen(Syscall_array[i].handler_name);
	Syscall_array[i].args_qty = 6;
	Syscall_array[i].mask = 0;
	Syscall_array[i].attached = 1;
	Syscall_array[i].nstrings = 0;
	Syscall_array[i].positions[0] = 0;

	NOTICE("added syscall to the table [%i]: %s",
		i, Syscall_array[i].handler_name);

	return i;
}

static char *
load_ebpf_2_str_tmpl(void)
{
	char *text = NULL;

	switch (Args.fnr_mode) {
	case E_FNR_FAST:
	case E_FNR_STR_MAX:
		text = load_file_no_cr(ebpf_2_str_sl_file);
		break;
	case E_FNR_FULL_CONST_N:
		text = load_file_no_cr(ebpf_2_str_ml_file);
		break;
	default:
		assert(false);
		break;
	}

	return text;
}

static char *
load_ebpf_path_1_tmpl(void)
{
	char *text = NULL;

	switch (Args.fnr_mode) {
	case E_FNR_FAST:
	case E_FNR_STR_MAX:
		text = load_file_no_cr(ebpf_1_str_sl_file);
		break;
	case E_FNR_FULL_CONST_N:
		text = load_file_no_cr(ebpf_1_str_full_file);
		break;
	default:
		assert(false);
		break;
	}

	return text;
}

static char *
get_template(unsigned sc_num)
{
	static const char *tmpl_str[MAX_STR_ARG] = {"STR1", "STR2", "STR3"};
	char *text = NULL;

	if (Syscall_array[sc_num].handler_name == NULL)
		return NULL;

	if (Args.ff_mode == E_FF_FULL) {
		switch (sc_num) {
		case __NR_clone:
			text = load_file_no_cr(ebpf_clone_file);
			goto replace;
		case __NR_vfork:
			text = load_file_no_cr(ebpf_vfork_file);
			goto replace;
		case __NR_fork:
			text = load_file_no_cr(ebpf_fork_file);
			goto replace;
		case __NR_exit:
		case __NR_exit_group:
			text = load_file_no_cr(ebpf_exit_file);
			goto replace;
		}
	}

	int nstr = Syscall_array[sc_num].nstrings;

	if (nstr > MAX_STR_ARG) {
		WARNING("syscall '%s' has more than %i string arguments,\n"
			"\tonly first %i of them will be printed\n",
			Syscall_array[sc_num].handler_name,
			MAX_STR_ARG, MAX_STR_ARG);

		nstr = MAX_STR_ARG;
	}

	text = load_file_no_cr(ebpf_file_table[nstr][Args.fnr_mode]);
	if (NULL == text) {
		ERROR("cannot load the file: %s",
			ebpf_file_table[nstr][Args.fnr_mode]);
		return NULL;
	}

	/* replace STRX */
	for (int i = 0; i < nstr; i++) {
		str_replace_with_char(text, tmpl_str[i],
					Syscall_array[sc_num].positions[i]);
	}

replace:
	str_replace_all(&text, "SYSCALL_NR",
			Syscall_array[sc_num].num_str);

	return text;
}

/* XXX HACK: this syscall is exported by kernel twice. */
static unsigned SyS_sigsuspend = 0;

/*
 * generate_ebpf_kp_kern_all -- This function generates universal default eBPF
 *     syscall handler.
 *
 * Primary purpose of generated handler - new and unknown syscalls.
 */
static int
generate_ebpf_kp_kern_all(FILE *ts)
{
	char *text = NULL;


	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	FILE *in = fopen(Debug_tracing_aff, "r");

	if (NULL == in) {
		ERROR("error opening '%s': %m", Debug_tracing_aff);
		return -1;
	}

	while ((read = getline(&line, &len, in)) != -1) {
		unsigned sc_num;
		size_t fw_res;

		if (!is_a_sc(line, read - 1))
			continue;

		line[read - 1] = '\0';

		/* XXX HACK: this syscall is exported by kernel twice. */
		if (!strcasecmp("SyS_sigsuspend", line)) {
			if (SyS_sigsuspend)
				continue;
			SyS_sigsuspend = 1;
		}

		sc_num = get_sc_num(line);
		text = get_template(sc_num);
		if (text == NULL) {
			ERROR("no template found for syscall: '%s'", line);
			free(line);
			return -1;
		}

		str_replace_all(&text, "SYSCALL_NAME_filled_for_replace", line);

		fw_res = fwrite(text, strlen(text), 1, ts);
		if (fw_res < 1) {
			perror("fwrite");
			free(line);
			free(text);
			return -1;
		}

		free(text);
	}

	free(line);
	fclose(in);
	return 0;
}

/*
 * generate_ebpf_kp_file -- generate eBPF syscall handlers specific
 *                          for syscalls with filename in arguments
 */
static int
generate_ebpf_kp_file(FILE *ts)
{
	char *text = NULL;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		size_t fw_res;

		if (NULL == Syscall_array[i].handler_name)
			continue;

		if (EM_file != (EM_file & Syscall_array[i].mask))
			continue;

		text = load_ebpf_path_1_tmpl();

		str_replace_all(&text, "SYSCALL_NR",
				Syscall_array[i].num_str);
		str_replace_all(&text, "SYSCALL_NAME_filled_for_replace",
				Syscall_array[i].handler_name);

		fw_res = fwrite(text, strlen(text), 1, ts);
		if (fw_res < 1) {
			perror("fwrite");
			free(text);
			return -1;
		}

		free(text);
	}
	return 0;
}

/*
 * generate_ebpf_kp_fileat -- generate eBPF syscall handlers specific
 *                            for syscalls with relative filename in arguments
 */
static int
generate_ebpf_kp_fileat(FILE *ts)
{
	char *text = NULL;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		size_t fw_res;

		if (NULL == Syscall_array[i].handler_name)
			continue;

		if (EM_fileat != (EM_fileat & Syscall_array[i].mask))
			continue;

		text = load_ebpf_2_str_tmpl();

		str_replace_all(&text, "SYSCALL_NR",
				Syscall_array[i].num_str);
		str_replace_all(&text, "SYSCALL_NAME_filled_for_replace",
				Syscall_array[i].handler_name);

		fw_res = fwrite(text, strlen(text), 1, ts);
		if (fw_res < 1) {
			perror("fwrite");
			free(text);
			return -1;
		}

		free(text);
	}
	return 0;
}

/*
 * generate_ebpf_kp_desc -- generate eBPF syscall handlers specific
 *                          for syscalls with file-descriptor in arguments
 */
static int
generate_ebpf_kp_desc(FILE *ts)
{
	char *text = NULL;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		size_t fw_res;

		if (NULL == Syscall_array[i].handler_name)
			continue;

		if (EM_desc != (EM_desc & Syscall_array[i].mask))
			continue;

		text = load_file_no_cr(ebpf_0_str_file);

		str_replace_all(&text, "SYSCALL_NR",
				Syscall_array[i].num_str);
		str_replace_all(&text, "SYSCALL_NAME_filled_for_replace",
				Syscall_array[i].handler_name);

		fw_res = fwrite(text, strlen(text), 1, ts);
		if (fw_res < 1) {
			perror("fwrite");
			free(text);
			return -1;
		}

		free(text);
	}
	return 0;
}

/*
 * generate_ebpf_kp_fileio -- generate eBPF syscall handlers specific
 *                            for syscalls which operate on files
 */
static int
generate_ebpf_kp_fileio(FILE *ts)
{
	int ret = generate_ebpf_kp_file(ts);
	if (ret)
		return ret;

	ret = generate_ebpf_kp_desc(ts);
	if (ret)
		return ret;

	return generate_ebpf_kp_fileat(ts);
}

/*
 * generate_ebpf_tp_all -- generate eBPF syscall handler
 *                         specific for tracepoint feature
 */
static int
generate_ebpf_tp_all(FILE *ts)
{
	char *text = load_file_no_cr(ebpf_tracepoints_file);
	int ret = 0;

	size_t fw_res = fwrite(text, strlen(text), 1, ts);
	if (fw_res < 1) {
		perror("fwrite");
		ret = -1;
	}

	free(text);

	return ret;
}

/*
 * generate_ebpf_common -- generate eBPF syscall handler
 *                         specific for kprobes and tracepoints
 */
static int
generate_ebpf_common(FILE *ts)
{
	int ret;

	ret = generate_ebpf_kp_kern_all(ts);
	if (ret)
		return ret;

	return generate_ebpf_tp_all(ts);
}

/*
 * generate_ebpf -- This function parses and process expression.
 */
char *
generate_ebpf()
{
	char *text = NULL;
	size_t text_size = 0;
	int ret;

	FILE *ts = open_memstream(&text, &text_size);
	if (ts == NULL)
		return NULL;

	char *head = load_file(ebpf_head_file);
	size_t fw_res = fwrite(head, strlen(head), 1, ts);
	if (fw_res < 1) {
		perror("fwrite");
		free(head);
		return NULL;
	}

	free(head);

	if (NULL == Args.expr) {
		NOTICE("defaulting to 'trace=common'");
		ret = generate_ebpf_common(ts);
	} else if (!strcasecmp(Args.expr, "trace=common")) {
		ret = generate_ebpf_common(ts);
	} else if (!strcasecmp(Args.expr, "trace=kp-kern-all")) {
		ret = generate_ebpf_kp_kern_all(ts);
	} else if (!strcasecmp(Args.expr, "trace=kp-file")) {
		ret = generate_ebpf_kp_file(ts);
	} else if (!strcasecmp(Args.expr, "trace=kp-desc")) {
		ret = generate_ebpf_kp_desc(ts);
	} else if (!strcasecmp(Args.expr, "trace=kp-fileio")) {
		ret = generate_ebpf_kp_fileio(ts);
	} else if (!strcasecmp(Args.expr, "trace=tp-all")) {
		ret = generate_ebpf_tp_all(ts);
	} else {
		ERROR("unknown option: '%s'", Args.expr);
		ret = -1;
	}

	fclose(ts);
	if (ret) {
		free(text);
		return NULL;
	}

	return text;
}

/*
 * apply_process_attach_code -- apply process-attach code
 *                              to generated code with handlers
 */
void
apply_process_attach_code(char **const pbpf_str)
{
	char strpid[64];
	int snp_res;
	char *loaded_file;
	int pid;

	if (0 < Args.pid) {
		/* traced pid */
		pid = Args.pid;

		snp_res = snprintf(strpid, sizeof(strpid), "%d", pid);
		assert(snp_res > 0);
		(void) snp_res;

		loaded_file = load_pid_check_hook(Args.ff_mode);
		assert(NULL != loaded_file);

		str_replace_all(&loaded_file, "TRACED_PID", strpid);
	} else {
		/* my own pid */
		pid = getpid();
		NOTICE("will not trace my own PID %i (0x%X)", pid, pid);

		snp_res = snprintf(strpid, sizeof(strpid), "%d", pid);
		assert(snp_res > 0);
		(void) snp_res;

		loaded_file = load_file_no_cr(ebpf_pid_own_file);
		assert(NULL != loaded_file);

		str_replace_all(&loaded_file, "MY_OWN_PID", strpid);
	}
	str_replace_all(pbpf_str, "PID_CHECK_HOOK", loaded_file);
	free(loaded_file);

	if (Args.fnr_mode == E_FNR_FULL_CONST_N && Args.n_str_packets > 2) {
		loaded_file = load_file_no_cr(ebpf_const_string_mode);
		assert(NULL != loaded_file);
		str_replace_many(pbpf_str, "READ_AND_SUBMIT_N_MINUS_2_PACKETS",
					loaded_file, Args.n_str_packets - 2);
	}

	if (Args.fnr_mode == E_FNR_FULL && Args.n_str_packets > 2) {
		loaded_file = load_file_no_cr(ebpf_full_string_mode);
		assert(NULL != loaded_file);
		str_replace_many(pbpf_str, "READ_AND_SUBMIT_N_MINUS_2_PACKETS",
					loaded_file, Args.n_str_packets - 2);
	}

}

/*
 * Print ebpf code with marks for debug reason
 */
int
fprint_ebpf_code_with_debug_marks(FILE *f, const char *bpf_str)
{
	fprintf(f, "\t>>>>> Generated eBPF code <<<<<\n");

	if (bpf_str) {
		size_t fw_res;

		fw_res = fwrite(bpf_str, strlen(bpf_str), 1, f);
		if (fw_res < 1) {
			perror("fwrite");
			return -1;
		}
	}

	fprintf(f, "\t>>>>> EndOf generated eBPF code <<<<<<\n");
	return 0;
}
