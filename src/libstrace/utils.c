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
 * utils.c -- utility functions
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "main.h"
#include "utils.h"
#include "generate_ebpf.h"

/*
 * This function loads text file from disk and return malloc-ed,
 * null-terminated string
 */
char *
load_file_from_disk(const char *const fn)
{
	int fd;
	long res;
	char *buf = NULL;
	struct stat st;

	fd = open(fn, O_RDONLY);

	if (fd == -1)
		return buf;

	res = fstat(fd, &st);

	if (res == -1)
		goto out;

	buf = calloc(1, (size_t)st.st_size + 1);

	res = read(fd, buf, (size_t)st.st_size);

	if (st.st_size != res) {
		free(buf);
		buf = NULL;
	}

out:
	close(fd);

	return buf;
}

/*
 * Export embedded trace.h to file
 */
void save_trace_h(void) {
	int fd;

	long res = access(ebpf_trace_h_file, R_OK);

	if (res == 0)
		return;

	fd = open(ebpf_trace_h_file, O_WRONLY | O_CREAT, 0666);

	if (fd == -1)
		return;

	res = write(fd, _binary_trace_h_start, (size_t)_binary_trace_h_size);

	close(fd);
}

/*
 * This function loads 'virtual' file.
 */
char *
load_file(const char *const fn)
{
	char *f = load_file_from_disk(fn);

	if (NULL != f)
		return f;

	/* fallback to embedded ones */
	if (0 == strcmp(ebpf_head_file, fn)) {
		return strndup(_binary_trace_head_c_start,
				(size_t)_binary_trace_head_c_size);
	} else if (0 == strcmp(ebpf_libc_tmpl_file, fn)) {
		return strndup(_binary_trace_libc_tmpl_c_start,
				(size_t)_binary_trace_libc_tmpl_c_size);
	} else if (0 == strcmp(ebpf_file_tmpl_file, fn)) {
		return strndup(_binary_trace_file_tmpl_c_start,
				(size_t)_binary_trace_file_tmpl_c_size);
	} else if (0 == strcmp(ebpf_fileat_tmpl_file, fn)) {
		return strndup(_binary_trace_fileat_tmpl_c_start,
				(size_t)_binary_trace_fileat_tmpl_c_size);
	} else if (0 == strcmp(ebpf_kern_tmpl_file, fn)) {
		return strndup(_binary_trace_kern_tmpl_c_start,
				(size_t)_binary_trace_kern_tmpl_c_size);
	} else if (0 == strcmp(ebpf_tp_all_file, fn)) {
		return strndup(_binary_trace_tp_all_c_start,
				(size_t)_binary_trace_tp_all_c_size);
	} else if (0 == strcmp(ebpf_trace_h_file, fn)) {
		return strndup(_binary_trace_h_start,
				(size_t)_binary_trace_h_size);
	}

	return NULL;
}

/*
 * This function reads status of eBPF JIT compiler.
 */
static int
load_bpf_jit_status(void)
{
	int fd, err_no;
	long res;
	char buf[16];

	fd = open("/proc/sys/net/core/bpf_jit_enable", O_RDONLY);

	if (fd == -1)
		return -1;

	errno = 0;
	res = read(fd, buf, sizeof(buf));

	err_no = errno;
	close(fd);
	errno = err_no;

	if (res <= 0)
		return -1;

	return atoi(buf);
}

/*
 * This function checks status of eBPF JIT compiler and prints appropriate
 * message.
 */
void
check_bpf_jit_status(FILE *file)
{
	int status = load_bpf_jit_status();

	switch (status) {
	case -1:
		fprintf(file,
			"ERROR:%s: could not read bpf_jit status: '%m'\n",
			__func__);
		return;

	case  0:
		fprintf(file,
			"WARNING:%s: DISABLED.\n"
			"\tPlease reffer to `man strace.ebpf`,"
				" section 'Configuration'.\n"
			"\tIt will allow to improve performance significantly\n"
			"\tand drop appropriate problems.\n",
			__func__);
		return;

	case  1:
		fprintf(file, "INFO:%s: ENABLED.\n", __func__);
		return;

	case  2:
		fprintf(file, "INFO:%s: DEBUG.\n", __func__);
		return;

	default:
		fprintf(file,
			"WARNING:%s: UNKNOWN. Please notify the author.\n",
			__func__);
		return;
	}
}


/*
 * This function recognises syscalls among in-kernel functions.
 */
bool
is_a_sc(const char *const line, const ssize_t size)
{
	static const char template[] = "sys_";

	const size_t template_len = strlen(template);

	if (size <= (ssize_t)template_len)
		return false;

	if (strncasecmp(line, template, template_len))
		return false;

	if (line[size - 1] == ']')
		return false;

	return true;
}

const char debug_tracing[] = DEBUG_TRACING;
const char debug_tracing_aff[] = DEBUG_TRACING DT_AFF;

/*
 * This function fetch syscall's list from running kernel
 */
void
get_sc_list(FILE *f, template_t template)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	FILE *in = fopen(debug_tracing_aff, "r");

	if (NULL == in) {
		fprintf(stderr, "%s: ERROR: '%m'\n", __func__);
		return;
	}

	while ((read = getline(&line, &len, in)) != -1) {
		if (NULL != template) {
			if (!template(line, read - 1))
				continue;
		}

		fwrite(line, (size_t)read, 1, f);
	}

	free(line);
	fclose(in);
	fflush(f);
}

/*
 * Replace all occurrence of 'templt' in 'text' with 'str'
 */
void
str_replace_all(char **const text, const char *templt, const char *str)
{
	char *occ;

	const size_t templt_len = strlen(templt);
	const size_t str_len = strlen(str);

	while (NULL != (occ = strstr(*text, templt))) {
		char *p;
		size_t text_len;

		p = *text;
		text_len = strlen(p);

		*text = calloc(1, text_len - templt_len + str_len + 1);

		strncpy(*text, p, ((uintptr_t)occ) - ((uintptr_t)p));
		strcat(*text, str);
		strcat(*text, occ + templt_len);

		free(p);
	}
}

/*
 * This function runs traced command passed through command line.
 */
pid_t
start_command(int argc, char *argv[])
{
	pid_t pid = -1;

	pid = fork();

	switch (pid) {
	case -1:
		break;

	case 0:
		/* Wait until parent will be ready */
		/*
		 * for unknown reason sigwait(SIGCONT) and pause()
		 *    do not success with any signal.
		 */
		raise(SIGSTOP);

		execvp(argv[0], argv);
		exit(errno);
		break;

	default:
		break;
	}

	(void) argc;
	return pid;
}

/*
 * SIGCHLD handler. Is used if "command" was provided on command line.
 */
void
sig_chld_handler(int sig, siginfo_t *si, void *unused)
{
	if (si->si_code == CLD_EXITED && args.pid == si->si_pid) {
		cont = false;
	}

	(void) sig;
	(void) unused;
}

/*
 * Generic signal hendler. Is used for notification of traced process about
 * parent's death.
 */
void
sig_transmit_handler(int sig, siginfo_t *si, void *unused)
{
	kill(args.pid, SIGSEGV == sig ? SIGHUP : sig);

	cont = false;

	(void) si;
	(void) unused;
}
