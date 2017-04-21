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
 * utils.c -- utility functions
 */

#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "ebpf/ebpf_file_set.h"

#include "strace.ebpf.h"
#include "utils.h"
#include "generate_ebpf.h"

/*
 * load_file_from_disk -- load text file from disk and return
 *                        malloc-ed, null-terminated string
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
		return NULL;

	res = fstat(fd, &st);

	if (res == -1)
		goto out;

	buf = calloc(1, (size_t)st.st_size + 1);

	if (NULL == buf)
		goto out;

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
 * save_trace_h -- export embedded trace.h to file
 */
void
save_trace_h(void)
{
	int res, fd;

	res = access(ebpf_trace_h_file, R_OK);
	if (res == 0) {
		/* file exists, exiting */
		return;
	}

	fd = open(ebpf_trace_h_file, O_WRONLY | O_CREAT, 0666);
	if (fd == -1) {
		perror("open");
		WARNING("cannot create the file: %s", ebpf_trace_h_file);
		return;
	}

	res = write(fd, _binary_trace_h_start, BINARY_FILE_SIZE(trace_h));
	if (res != (int)BINARY_FILE_SIZE(trace_h)) {
		perror("write");
		WARNING("error while saving the file: %s", ebpf_trace_h_file);
		close(fd);
		unlink(ebpf_trace_h_file);
		return;
	}

	close(fd);
}

/*
 * load_file -- load 'virtual' file
 */
char *
load_file(const char *const fn)
{
	if (NULL != Args.ebpf_src_dir) {
		char path[4096];
		char *f;
		int res;

		res = snprintf(path, sizeof(path), "%s/%s",
				Args.ebpf_src_dir, fn);

		assert(res > 0);
		(void) res;

		f = load_file_from_disk(path);

		if (NULL != f)
			return f;
	}

	/* fallback to embedded ones */
	return ebpf_load_file(fn);
}

/*
 * load_file_no_cr -- load 'virtual' file and strip copyright
 */
char *
load_file_no_cr(const char *const fn)
{
	static const char *const eofcr_sep = " */\n";
	char *f = load_file(fn);

	if (NULL == f)
		return NULL;

	if (NULL == strcasestr(f, "Copyright"))
		return f;

	char *new_f = strcasestr(f, eofcr_sep);
	if (NULL == new_f)
		return f;

	new_f = strdup(new_f + strlen(eofcr_sep));
	if (NULL == new_f)
		return f;

	free(f);
	f = NULL;

	return new_f;
}

/*
 * load_pid_check_hook -- load 'pid_check_hook'
 */
char *
load_pid_check_hook(enum ff_mode ff_mode)
{
	switch (ff_mode) {
	case E_FF_DISABLED:
		return load_file_no_cr(ebpf_pid_ff_disabled_file);

	case E_FF_FULL:
		return load_file_no_cr(ebpf_pid_ff_full_file);

	default:
		return NULL;
	}
}

/*
 * load_bpf_jit_status -- read status of eBPF JIT compiler
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
 * check_bpf_jit_status -- check status of eBPF JIT compiler
 *                         and print appropriate message
 */
void
check_bpf_jit_status(FILE *file)
{
	int status = load_bpf_jit_status();

	switch (status) {
	case -1:
		fprintf(file, "ERROR: cannot read status of "
				"eBPF JIT compiler: '%m'\n");
		return;

	case  0:
		fprintf(file, "WARNING: eBPF JIT compiler is DISABLED.\n"
				"\tPlease refer to `man strace.ebpf`,"
				" section 'Configuration'.\n"
				"\tEnabling this will improve performance\n"
				"\tsignificantly and fix some problems.\n");
		return;

	case  1:
		fprintf(file, "Notice: eBPF JIT compiler is enabled.\n");
		return;

	case  2:
		fprintf(file, "Notice: eBPF JIT compiler is in DEBUG mode.\n");
		return;

	default:
		fprintf(file, "WARNING: unknown status of eBPF JIT compiler. "
				"Please notify the author.\n");
		return;
	}
}


/*
 * is_a_sc -- recognise syscalls among in-kernel functions
 */
bool
is_a_sc(const char *const line, const ssize_t size)
{
	static const char prefix[] = "sys_";
	static const size_t prefix_len = 4; /* = strlen(prefix) */

	if (size <= (ssize_t)prefix_len)
		return false;

	if (strncasecmp(line, prefix, prefix_len))
		return false;

	if (line[size - 1] == ']')
		return false;

	return true;
}

const char Debug_tracing[] = DEBUG_TRACING;
const char Debug_tracing_aff[] = DEBUG_TRACING DT_AFF;

/*
 * get_sc_list -- fetch syscall's list from running kernel
 */
void
get_sc_list(FILE *f, template_t template)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	FILE *in = fopen(Debug_tracing_aff, "r");

	if (NULL == in) {
		fprintf(stderr, "%s: ERROR: '%m'\n", __func__);
		return;
	}

	while ((read = getline(&line, &len, in)) != -1) {
		size_t fw_res;

		if (NULL != template) {
			if (!template(line, read - 1))
				continue;
		}

		fw_res = fwrite(line, (size_t)read, 1, f);

		assert(fw_res > 0);
		(void) fw_res;
	}

	free(line);
	fclose(in);
	fflush(f);
}

/*
 * str_replace_all -- replace all occurrences of 'templt' in 'text' with 'str'
 */
int
str_replace_all(char **const text, const char *templt, const char *str)
{
	const size_t templt_len = strlen(templt);
	const size_t str_len = strlen(str);
	char *occ;

	if (str_len <= templt_len) {
		char *new_str = malloc(templt_len);
		if (new_str == NULL)
			return -1;

		memcpy(new_str, str, str_len);

		/* fill the rest with spaces */
		if (templt_len - str_len > 1) {
			memset(new_str + str_len, ' ', templt_len - str_len);
		} else {
			new_str[str_len] = ' ';
		}

		/* replace all */
		while (NULL != (occ = strstr(*text, templt))) {
			memcpy(occ, new_str, templt_len);
		}

		free(new_str);

	} else {
		while (NULL != (occ = strstr(*text, templt))) {
			char *p = *text;
			size_t text_len = strlen(p);

			*text = calloc(1, text_len - templt_len + str_len + 1);
			if (NULL == *text) {
				free(p);
				return -1;
			}

			strncpy(*text, p, ((uintptr_t)occ) - ((uintptr_t)p));
			strcat(*text, str);
			strcat(*text, occ + templt_len);
			free(p);
		}
	}

	return 0;
}

/*
 * str_replace_with_char -- replace all occurrences of 'templt' in 'text'
 *                          with char 'c'
 */
int
str_replace_with_char(char *const text, const char *templt, const char c)
{
	size_t len = strlen(templt);

	char *new_str = malloc(len);
	if (new_str == NULL)
		return -1;

	new_str[0] = c;

	/* fill the rest with spaces */
	memset(new_str + 1, ' ', len - 1);

	/* replace all */
	char *occ;
	while (NULL != (occ = strstr(text, templt))) {
		memcpy(occ, new_str, len);
	}

	free(new_str);

	return 0;
}

/*
 * start_command -- run traced command passed through command line
 */
pid_t
start_command(char *const argv[])
{
	pid_t pid = fork();
	switch (pid) {
	case -1:
		break;

	case 0:
		/*
		 * Wait until the parent will be ready.
		 * For unknown reasons sigwait(SIGCONT) and pause()
		 * do not success with any signal.
		 */
		raise(SIGSTOP);

		execvp(argv[0], argv);

		exit(errno);
		break;

	default:
		break;
	}

	return pid;
}

/*
 * sig_abort_handler -- signal handler, used to abort the tracing and to notify
 *                      the traced process about the parent's death
 */
static void
sig_abort_handler(int sig, siginfo_t *si, void *unused)
{
	if (PidToBeKilled > 0)
		kill(PidToBeKilled, SIGSEGV == sig ? SIGHUP : sig);

	AbortTracing = 1;

	(void) si;
	(void) unused;
}

/*
 * attach_signals_handlers -- attach signal handlers
 */
void
attach_signals_handlers(void)
{
	struct sigaction sa;

	sa.sa_sigaction = sig_abort_handler;
	sigemptyset(&sa.sa_mask);

	sa.sa_flags = SA_RESTART;

	(void) sigaction(SIGINT,  &sa, NULL);
	(void) sigaction(SIGHUP,  &sa, NULL);
	(void) sigaction(SIGQUIT, &sa, NULL);
	(void) sigaction(SIGTERM, &sa, NULL);

	sa.sa_flags = SA_RESTART | SA_RESETHAND;

	(void) sigaction(SIGSEGV, &sa, NULL);
}

/*
 * Setup Out_lf stream
 */
void
setup_out_lf(void)
{
	int err_no;

	if (NULL == Args.out_fn) {
		Out_lf = stdout;

		goto setup_buffer;
	}

	Out_lf = fopen(Args.out_fn, "w");

	if (NULL != Out_lf)
		goto setup_buffer;

	err_no = errno;

	fprintf(stderr, "ERROR: "
		"Failed to open '%s' for appending: '%m'\n",
		Args.out_fn);

	errno = err_no;
	return;

setup_buffer:
	/* XXX We should improve it. May be we should use fd directly */
	/* setbuffer(Out_lf, NULL, Args.out_buf_size); */
	(void) Args.out_buf_size;
}
