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
 * txt.c -- text messages
 */

#include <assert.h>

#include "txt.h"

static const char *help_text = "\
USAGE:\n\
    vltrace -h\n\
    vltrace [-t] [-p PID | command [arg ...]]\n\
\n\
Warning: system-wide tracing can fill out your disk really fast.\n\
\n\
Startup:\n\
    -p, --pid    <pid>\n\
        Trace this PID only, <command> option should be missing.\n\
        Press (CTRL-C) to send interrupt signal to exit.\n\
    --ebpf-src-dir <dir>\n\
        Enable checking of updated ebpf templates in directory <dir>.\n\
\n\
Output format:\n\
    -o, --output <file>\n\
        log filename\n\
    -t, --timestamp\n\
        include timestamp in output\n\
    -l, --format <fmt>\n\
        format of output logs. Possible values:\n\
        - 'bin'  - the binary format described in trace.h,\n\
                   allows the fastest operation,\n\
        - 'text' - the text format.\n\
        Default: 'text'\n\
    --hex-separator <sep>\n\
        set field separator for hex logs. Default is a single space ' '.\n\
\n\
Filtering:\n\
    --failed\n\
        only show failed syscalls\n\
    --expr <expr>\n\
        which syscalls should be traced (Default: 'all'):\n\
	1) Intercepting using both Kprobes and Tracepoints (requires\n\
           kernel >= 4.7):\n\
	- 'all' all syscalls provided by the kernel using:\n\
		- Kprobes on syscalls' entry and\n\
		- Tracepoint (raw syscall sys_exit) on syscalls' exit.\n\
		This is the default and recommended option.\n\
	2) Intercepting using Kprobes only:\n\
	- 'kp-all'    - all syscalls provided by kernel\n\
	- 'kp-fileio' - all syscalls related to file IO\n\
	- 'kp-file'   - all syscalls with path arguments\n\
	- 'kp-desc'   - all syscalls with file descriptor arguments\n\
\n\
Tracing:\n\
    -f, --full-follow-fork\n\
        Follow new processes created with fork()/vfork()/clone() syscall as\n\
        regular strace does.\n\
\n\
    -s, --string-args <length>\n\
	Defines the maximum possible length of string arguments read\n\
	by vltrace. eBPF virtual machine is extremely limited in available\n\
        memory. Also currently there is no way to calculate the length\n\
	of a string argument. For this reason there are four modes\n\
        of fetching such arguments chosen depending on value of 'length':\n\
\n\
	 - 'fast'   - for 'length' <= 126:\n\
\n\
              1 packet is generated per each syscall, maximum length\n\
              of a string depends on number of string arguments\n\
              in the syscall:\n\
              - 1 string argument  = 382,\n\
              - 2 string arguments = 190,\n\
              - 3 string arguments = 126,\n\
              This is the fastest mode.\n\
\n\
	 - 'packet' - for 'length' <= 382:\n\
\n\
              1 packet is generated per each string argument,\n\
              maximum length of a string is 382.\n\
\n\
	 - 'const'  - for 'length' > 382 and kernel version < 4.11:\n\
\n\
              Constant number N of packets is generated per each\n\
              string argument, counted depending on value of 'length'.\n\
              Maximum length of a string is the smallest value\n\
              of (N * 383 - 1) that is greater or equal to 'length'.\n\
\n\
	 - 'full'   - for 'length' > 382 and kernel version >= 4.11:\n\
\n\
              Variable number N of packets is generated per each\n\
              string argument, depending on the actual length\n\
              of each string argument. Maximum length of a string\n\
              is the smallest value of (N * 383 - 1) that is greater\n\
              or equal to 'length'.\n\
\n\
        Default: fast\n\
\n\
Miscellaneous:\n\
    -d, --debug\n\
        enable debug output\n\
    -h, --help\n\
        print help\n\
    --list\n\
        Print a list of all traceable syscalls of the running kernel.\n\
    --ll-list\n\
        Print a list of all traceable low-level funcs of the running kernel.\n\
        WARNING: really long. ~45000 functions.\n\
    --builtin-list\n\
        Print a list of all known syscalls.\n\
\n\
Examples:\n\
    ./vltrace           # trace all syscalls in the system\n\
    ./vltrace ls        # trace syscalls of ls command\n\
    ./vltrace -p 342    # only trace PID 342\n\
";

/*
 * fprint_help -- print help message
 */
void
fprint_help(FILE *f)
{
	fprintf(f, "%s", help_text);
	fflush(f);
}
