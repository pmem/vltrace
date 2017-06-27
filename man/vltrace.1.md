---
layout: manual
Content-Style: 'text/css'
title: vltrace(1)
...

[comment]: <> (Copyright 2016, Intel Corporation)

[comment]: <> (Redistribution and use in source and binary forms, with or without)
[comment]: <> (modification, are permitted provided that the following conditions)
[comment]: <> (are met:)
[comment]: <> (    * Redistributions of source code must retain the above copyright)
[comment]: <> (      notice, this list of conditions and the following disclaimer.)
[comment]: <> (    * Redistributions in binary form must reproduce the above copyright)
[comment]: <> (      notice, this list of conditions and the following disclaimer in)
[comment]: <> (      the documentation and/or other materials provided with the)
[comment]: <> (      distribution.)
[comment]: <> (    * Neither the name of the copyright holder nor the names of its)
[comment]: <> (      contributors may be used to endorse or promote products derived)
[comment]: <> (      from this software without specific prior written permission.)

[comment]: <> (THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS)
[comment]: <> ("AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT)
[comment]: <> (LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR)
[comment]: <> (A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT)
[comment]: <> (OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,)
[comment]: <> (SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT)
[comment]: <> (LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,)
[comment]: <> (DATA, OR PROFITS; OR BUSINESS INTERRUPTION HOWEVER CAUSED AND ON ANY)
[comment]: <> (THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT)
[comment]: <> ((INCLUDING NEGLIGENCE OR OTHERWISE ARISING IN ANY WAY OUT OF THE USE)
[comment]: <> (OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.)

[comment]: <> (vltrace.1 -- man page for vltrace)

[NAME](#name)<br />
[SYNOPSIS](#synopsis)<br />
[DESCRIPTION](#description)<br />
[FEATURES](#features)<br />
[LIMITATIONS](#limitations)<br />
[SYSTEM REQUIREMENTS](#system requirements)<br />
[OPTIONS](#options)<br />
[CONFIGURATION](#configuration)<br />
[FILES](#files)<br />
[EXAMPLES](#examples)<br />
[SEE ALSO](#see-also)<br />


# NAME #

**vltrace** -- extremely fast strace-like tool built on top of eBPF, Kprobe
and Tracepoint technologies.


# SYNOPSIS #

```vltrace [options] [command [arg ...]]```


# DESCRIPTION #

vltrace is a strace equivalent tool for Linux with limited functionality
based on eBPF, Kprobe and Tracepoint technologies and libbcc library.

# FEATURES #

 - Used combination of technologies allow tool to be about one order
   of magnitude faster than regular system strace.
 - This tool consumes fewer resources.
 - Output of this tool is designed to be suitable for processing with
   classical tools and technologies, like awk.
 - Could trace syscalls system-wide.
 - Could trace init (process with 'pid == 1') - finally we have a proper
   tool for debugging systemd ;-)

WARNING: System-wide tracing can fill out your disk really fast.

# LIMITATIONS #

 - Limited functionality
 - Slow attaching and detaching
 - Depends on modern kernel features
 - The underlying eBPF technology is still in active development, so we can
   expect hangs and crashes, especially on low-res systems.

# Outdated limitations

Could be useful with old libbcc versions.

 - Limited possibility to run few instances simultaneously.
   Details:
    - https://github.com/iovisor/bcc/pull/918
    - https://github.com/iovisor/bcc/issues/872

# SYSTEM REQUIREMENTS #

 - kernel v4.7 or later (to attach eBPF to tracepoints)
 - kernel headers installed:
    - 'kernel-devel' package on RHEL, Fedora and CentOS or
    - 'linux-headers' package on Debian and Ubuntu
 - libbcc v0.3.0-150-g3263805 or later
 - CAP_SYS_ADMIN capability (required by the bpf() syscall)
 - mounted debugfs and tracefs

# OPTIONS #

#Output format:

`-o, --output <file>`

filename

`-t, --timestamp`

include timestamp in output

`-l, --format <fmt>`

output logs format. Possible values: 'bin' or 'text':

 - 'bin' - the binary format, allows the fastest operation. It is described
   in generated trace.h. If current directory is not writable,
   generating of trace.h is skipped.

 - 'text' - the text log format.

   Default: 'text'

`-K, --hex-separator <sep>`

set field separator for hex logs. Default is a single space ' '.

#Filtering:

`-X, --failed`

only show failed syscalls

`-e, --expr <expr>`

defines which syscalls should be traced:
	1) Intercepting using both Kprobes and Tracepoints (requires kernel >= 4.7):
	- 'all' all syscalls provided by the kernel using:
		- Kprobes on syscalls' entry and
		- Tracepoint (raw syscall sys_exit) on syscalls' exit.
		This is the default and recommended option.
	2) Intercepting using Kprobes only:
	- 'kp-all'    - all syscalls provided by kernel
	- 'kp-fileio' - all syscalls related to file IO
	- 'kp-file'   - all syscalls with path arguments
	- 'kp-desc'   - all syscalls with file descriptor arguments

Default: all

#Tracing:

`-f, --full-follow-fork`

Follow new processes created with fork()/vfork()/clone() syscall
as regular strace does.

`-s, --string-args <length>`

defines the maximum possible length of string arguments read by vltrace.
eBPF virtual machine is extremely limited in available memory. Also currently
there is no way to calculate the length of a string argument. For this reason
there are four modes of fetching such arguments chosen depending on value
of 'length':

 - 'fast'   - for 'length' <= 126:

              1 packet is generated per each syscall, maximum length of a string depends on number of string arguments in the syscall:
              - 1 string argument  = 382,
              - 2 string arguments = 190,
              - 3 string arguments = 126,
              This is the fastest mode.

 - 'packet' - for 'length' <= 382:

              1 packet is generated per each string argument, maximum length of a string is 382.

 - 'const'  - for 'length' > 382 and kernel version < 4.11:

              Constant number N of packets is generated per each string argument, counted depending on value of 'length'.
              Maximum length of a string is the smallest value of (N * 383 - 1) that is greater or equal to 'length'.

 - 'full'   - for 'length' > 382 and kernel version >= 4.11:

              Variable number N of packets is generated per each string argument, depending on the actual length of each string argument.
              Maximum length of a string is the smallest value of (N * 383 - 1) that is greater or equal to 'length'.

Default: fast

#Startup:

`-p, --pid <PID>`

trace the process with this PID only. It excludes the `command` argument:
the process to be traced can be defined by exactly one of the options:
'command' or this one. Press (CTRL-C) to send interrupt signal to exit.
Note:
```
-p "`pidof PROG`"
```
syntax.

`-N, --ebpf-src-dir <dir>`

Enable checking of updated ebpf templates in directory \<dir\>\.

#Miscellaneous:

`-d, --debug`

enable debug output

`-h, --help`

print help

`-L, --list`

Print a list of all traceable syscalls of the running kernel.

`-R, --ll-list`

Print a list of all traceable low-level funcs of the running kernel.

WARNING: really long. ~45000 functions for 4.4 kernel.

`-B, --builtin-list`

Print a list of all known syscalls.

# CONFIGURATION #

** System configuration **

1. You should provide permissions to access tracefs for final user
   according to your distro documentation. Some of possible options:

    - In /etc/fstab add mode=755 option for debugfs AND tracefs.
    - Use sudo

2. It's a good idea to put this command in init scripts such as local.rc:

	echo 1 > /proc/sys/net/core/bpf_jit_enable

	It will significantly improve performance and avoid 'Lost events'

3. You should increase "Open File Limit" according to your distro documentation.
   Few common ways you can find in this instruction:

    https://easyengine.io/tutorials/linux/increase-open-files-limit/

4. Kernel headers for running kernel should be installed.

5. CAP_SYS_ADMIN capability should be provided for user for bpf() syscall.

# EXAMPLES #

#Example output:

 # ./vltrace -l hex

./vltrace     -l                hex

PID               ERR               RES               SYSCALL ARG1              ARG2  ARG3  AUX_DATA

0000000000000AFD  000000000000000B  FFFFFFFFFFFFFFFF  read    0000000000000005

0000000000000427  0000000000000000  0000000000000020  read    000000000000000A

0000000000000B3D  0000000000000000  0000000000000001  write   000000000000001C

0000000000000B11  0000000000000000  0000000000000001  read    000000000000001B

0000000000000427  0000000000000000  0000000000000020  read    000000000000000A

0000000000000B3D  0000000000000000  0000000000000001  write   000000000000001C

0000000000000B11  0000000000000000  0000000000000001  read    000000000000001B

0000000000000B3D  0000000000000000  0000000000000001  write   000000000000001C

0000000000000B11  0000000000000000  0000000000000001  read    000000000000001B

0000000000000B3D  0000000000000000  0000000000000001  write   000000000000001C

0000000000000B11  0000000000000000  0000000000000001  read    000000000000001B

...

^C

 #


#The -p option can be used to filter on a PID, which is filtered in-kernel.
Here -t option is used to print timestamps:

 # ./vltrace -l hex -tp 2833

./vltrace     -l                hex               -tp               2833
PID               TIME(usec)        ERR               RES               SYSCALL ARG1              ARG2  ARG3  AUX_DATA

0000000000000B11  0000000000000000  0000000000000000  0000000000000001  read    000000000000001B

0000000000000B11  0000000000004047  0000000000000000  0000000000000001  read    000000000000001B

0000000000000B11  0000000000008347  0000000000000000  0000000000000001  read    000000000000001B

0000000000000B11  000000000000C120  0000000000000000  0000000000000001  read    000000000000001B

0000000000000B11  000000000000C287  0000000000000000  0000000000000001  read    000000000000001B

0000000000000B11  000000000000C508  0000000000000000  0000000000000001  read    000000000000001B

0000000000000B11  0000000000010548  0000000000000000  0000000000000001  read    000000000000001B

0000000000000B11  00000000000144A4  0000000000000000  0000000000000001  read    000000000000001B

...

^C

 #


#The -X option only prints failed syscalls:

 # ./vltrace -l hex -X mkdir .

./vltrace     -l                      hex                     -X      mkdir                                                      .

PID               ERR                     RES                     SYSCALL ARG1                                                       ARG2  ARG3  AUX_DATA

000000000000441A  0000000000000002        FFFFFFFFFFFFFFFF        open    /usr/share/locale/en_US/LC_MESSAGES/coreutils.mo                       mkdir

000000000000441A  0000000000000002        FFFFFFFFFFFFFFFF        open    /usr/share/locale/en/LC_MESSAGES/coreutils.mo                          mkdir

000000000000441A  0000000000000002        FFFFFFFFFFFFFFFF        open    /usr/share/locale-langpack/en_US/LC_MESSAGES/coreutils.mo              mkdir

000000000000441A  0000000000000002        FFFFFFFFFFFFFFFF        open    /usr/lib/x86_64-linux-gnu/charset.alias                                mkdir

000000000000441A  0000000000000002        FFFFFFFFFFFFFFFF        open    /usr/share/locale/en_US/LC_MESSAGES/libc.mo                            mkdir

000000000000441A  0000000000000002        FFFFFFFFFFFFFFFF        open    /usr/share/locale/en/LC_MESSAGES/libc.mo                               mkdir

000000000000441A  0000000000000002        FFFFFFFFFFFFFFFF        open    /usr/share/locale-langpack/en_US/LC_MESSAGES/libc.mo                   mkdir

000000000000441A  0000000000000002        FFFFFFFFFFFFFFFF        open    /usr/share/locale-langpack/en/LC_MESSAGES/libc.mo                      mkdir

 #

The ERR column is the system error number. Error number 2 is ENOENT: no such
file or directory.

# SEE ALSO #

**strace**(1), **bpf**(2), **<https://github.com/pmem/vltrace>**.

Also Documentation/networking/filter.txt in kernel sources.
