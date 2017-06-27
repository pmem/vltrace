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
 * utils.h -- utility functions
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <signal.h>

#include "vltrace.h"

#define INFO(str, ...) \
	fprintf(stderr, str "\n", ##__VA_ARGS__);

#ifdef DEBUG

#define ERROR(str, ...) \
	fprintf(stderr, "ERROR: %s:" str "\n", __func__, ##__VA_ARGS__);
#define WARNING(str, ...) \
	fprintf(stderr, "Warning: %s:" str "\n", __func__, ##__VA_ARGS__);
#define NOTICE(str, ...) \
	fprintf(stderr, "Notice: %s:" str "\n", __func__, ##__VA_ARGS__);
#define DEBUG_NOTICE(str, ...) \
	fprintf(stderr, "DEBUG Notice: %s:" str "\n", __func__, ##__VA_ARGS__);
#define DEBUG_INFO(str, ...) \
	fprintf(stderr, "DEBUG: %s:" str "\n", __func__, ##__VA_ARGS__);

#else /* DEBUG */

#define ERROR(str, ...) \
	fprintf(stderr, "ERROR: " str "\n", ##__VA_ARGS__);
#define WARNING(str, ...) \
	fprintf(stderr, "Warning: " str "\n", ##__VA_ARGS__);
#define NOTICE(str, ...) \
	fprintf(stderr, "Notice: " str "\n", ##__VA_ARGS__);
#define DEBUG_NOTICE(str, ...)
#define DEBUG_INFO(str, ...)

#endif /* DEBUG */

char *load_file(const char *fn);
char *load_file_no_cr(const char *const fn);
char *load_pid_check_hook(enum ff_mode ff_mode);
char *load_file_from_disk(const char *const fn);
void check_bpf_jit_status();

void save_trace_h(void);

typedef bool (*filter_f)(const char *line, ssize_t size);
bool is_a_sc(const char *const line, const ssize_t size);
void print_sc_list(filter_f filter);

int str_replace_with_char(char *const text, const char *templt, const char c);
int str_replace_all(char **text, const char *templt, const char *str);
int str_replace_many(char **text, const char *templt, const char *str, int n);

pid_t start_command(char *const argv[]);
pid_t start_command_with_signals(int argc, char *const argv[]);

void attach_signal_handlers(void);

FILE *setup_output(void);

#define AVAILABLE_FILTERS "/sys/kernel/debug/tracing/available_filter_functions"

#endif /* UTILS_H */
