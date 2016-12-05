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

#include <stdlib.h>
#include <string.h>

#include "main.h"
#include "utils.h"
#include "ebpf_syscalls.h"
#include "generate_ebpf.h"

const char *ebpf_trace_h_file = "trace.h";

const char *ebpf_head_file = "trace_head.c";
const char *ebpf_libc_tmpl_file = "trace_libc_tmpl.c";
const char *ebpf_file_tmpl_file = "trace_file_tmpl.c";
const char *ebpf_fileat_tmpl_file = "trace_fileat_tmpl.c";
const char *ebpf_kern_tmpl_file = "trace_kern_tmpl.c";

const char *ebpf_tp_all_file = "trace_tp_all.c";

/*
 * This function returns syscall number by name according to libc knowledge.
 */
static int
get_sc_num(const char *sc_name)
{
	for (int i = 0; i < SC_TBL_SIZE; i++) {
		if (NULL == sc_tbl[i].hlr_name)
			continue;

		if (!strcasecmp(sc_name, sc_tbl[i].hlr_name))
			return i;
	}

	return -1;
}

/*
 * This function generates eBPF handler for syscalls which are known to glibc.
 */
static void
generate_ebpf_kp_libc_all(FILE *ts)
{
	char *text = NULL;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		if (NULL == sc_tbl[i].hlr_name)
			continue;

		if (EM_file == (EM_file & sc_tbl[i].masks))
			text = load_file(ebpf_file_tmpl_file);
		else if (EM_fileat == (EM_fileat & sc_tbl[i].masks))
			text = load_file(ebpf_fileat_tmpl_file);
		else
			text = load_file(ebpf_libc_tmpl_file);

		str_replace_all(&text, "SYSCALL_NR",
				sc_tbl[i].num_name);
		str_replace_all(&text, "SYSCALL_NAME",
				sc_tbl[i].hlr_name);

		fwrite(text, strlen(text), 1, ts);

		free(text); text = NULL;
	}
}

/* XXX HACK: this syscall is exported by kernel twice. */
static unsigned SyS_sigsuspend = 0;

/*
 * This function generates universal default eBPF syscall handler.
 *
 * Primer purpose of generated handler - new and unknown syscalls.
 */
static void
generate_ebpf_kp_kern_all(FILE *ts)
{
	char *text = NULL;


	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	FILE *in = fopen(debug_tracing_aff, "r");

	if (NULL == in) {
		fprintf(stderr, "%s: ERROR: '%m'\n", __func__);
		return;
	}

	while ((read = getline(&line, &len, in)) != -1) {
		int sc_num;

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
			if (EM_file == (EM_file & sc_tbl[sc_num].masks))
				text = load_file(ebpf_file_tmpl_file);
			else if (EM_fileat ==
					(EM_fileat & sc_tbl[sc_num].masks))
				text = load_file(ebpf_fileat_tmpl_file);
			else
				text = load_file(ebpf_libc_tmpl_file);

			str_replace_all(&text, "SYSCALL_NR",
					sc_tbl[sc_num].num_name);
		} else {
			text = load_file(ebpf_kern_tmpl_file);
		}

		str_replace_all(&text, "SYSCALL_NAME", line);

		fwrite(text, strlen(text), 1, ts);

		free(text); text = NULL;
	}

	free(line);
	fclose(in);
}

/*
 * This function generates eBPF syscall handlers specific for syscalls with
 * filename in arguments.
 */
static void
generate_ebpf_kp_file(FILE *ts)
{
	char *text = NULL;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		if (NULL == sc_tbl[i].hlr_name)
			continue;

		if (EM_file != (EM_file & sc_tbl[i].masks))
			continue;

		text = load_file(ebpf_file_tmpl_file);

		str_replace_all(&text, "SYSCALL_NR",
				sc_tbl[i].num_name);
		str_replace_all(&text, "SYSCALL_NAME",
				sc_tbl[i].hlr_name);

		fwrite(text, strlen(text), 1, ts);

		free(text); text = NULL;
	}
}

/*
 * This function generates eBPF syscall handlers specific for syscalls with
 * relative filename in arguments.
 */
static void
generate_ebpf_kp_fileat(FILE *ts)
{
	char *text = NULL;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		if (NULL == sc_tbl[i].hlr_name)
			continue;

		if (EM_fileat != (EM_fileat & sc_tbl[i].masks))
			continue;

		text = load_file(ebpf_fileat_tmpl_file);

		str_replace_all(&text, "SYSCALL_NR",
				sc_tbl[i].num_name);
		str_replace_all(&text, "SYSCALL_NAME",
				sc_tbl[i].hlr_name);

		fwrite(text, strlen(text), 1, ts);

		free(text); text = NULL;
	}
}

/*
 * This function generates eBPF syscall handlers specific for syscalls with
 * file-descriptor in arguments.
 */
static void
generate_ebpf_kp_desc(FILE *ts)
{
	char *text = NULL;

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		if (NULL == sc_tbl[i].hlr_name)
			continue;

		if (EM_desc != (EM_desc & sc_tbl[i].masks))
			continue;

		text = load_file(ebpf_libc_tmpl_file);

		str_replace_all(&text, "SYSCALL_NR",
				sc_tbl[i].num_name);
		str_replace_all(&text, "SYSCALL_NAME",
				sc_tbl[i].hlr_name);

		fwrite(text, strlen(text), 1, ts);

		free(text); text = NULL;
	}
}

/*
 * This function generates eBPF syscall handlers specific for syscalls which
 * operate on files.
 */
static void
generate_ebpf_kp_pmemfile(FILE *ts)
{
	generate_ebpf_kp_file(ts);
	generate_ebpf_kp_desc(ts);
	generate_ebpf_kp_fileat(ts);
}

/*
 * This function generates eBPF syscall handler specific for tracepoint
 * feature.
 */
static void
generate_ebpf_tp_all(FILE *ts)
{
	char *text = load_file(ebpf_tp_all_file);

	fwrite(text, strlen(text), 1, ts);

	free(text); text = NULL;
}

/*
 * This function parses and process expression.
 */
char *
generate_ebpf()
{
	char *text = NULL;
	size_t text_size = 0;

	FILE *ts = open_memstream(&text, &text_size);

	/* Let's from header */
	char *head = load_file(ebpf_head_file);
	fwrite(head, strlen(head), 1, ts);
	free(head); head = NULL;

	if (NULL == args.expr)
		goto DeFault;

	if (!strcasecmp(args.expr, "trace=kp-libc-all")) {
		generate_ebpf_kp_libc_all(ts);
		goto out;
	} else if (!strcasecmp(args.expr, "trace=kp-kern-all")) {
		generate_ebpf_kp_kern_all(ts);
		goto out;
	} else if (!strcasecmp(args.expr, "trace=kp-file")) {
		generate_ebpf_kp_file(ts);
		goto out;
	} else if (!strcasecmp(args.expr, "trace=kp-desc")) {
		generate_ebpf_kp_desc(ts);
		goto out;
	} else if (!strcasecmp(args.expr, "trace=kp-pmemfile")) {
		generate_ebpf_kp_pmemfile(ts);
		goto out;
	} else if (!strcasecmp(args.expr, "trace=tp-all")) {
		generate_ebpf_tp_all(ts);
		goto out;
	}

DeFault:
	fprintf(stderr,
			"%s: Default expression 'trace=kp-kern-all' was chosen."
			" If you would like some speed improvment think about"
			" 'trace=kp-libc-all'.\n", __func__);
	generate_ebpf_kp_kern_all(ts);

out:
	fclose(ts);
	return text;
}
