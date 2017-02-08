---
layout: manual
Content-Style: 'text/css'
title: strace.ebpf(1)
header: NVM Library
date: pmem Tools version 1.0.2
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
[comment]: <> (DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY)
[comment]: <> (THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT)
[comment]: <> ((INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE)
[comment]: <> (OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.)

[comment]: <> (strace.ebpf.1 -- man page for strace.ebpf)

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

**strace.ebpf** -- extreamely fast strace-like tool built on top of eBPF
and KProbe technologies.


# SYNOPSIS #

```
$ strace.ebpf [options] [command [arg ...]]
```


# DESCRIPTION #

strace.ebpf is a limited functional strace equivalent for Linux but based on
eBPF and KProbe technologies and libbcc library.

# FEATURES #

 - Used combination of technologies allow tool to be about one order faster
   than regular system strace.
 - This tool consume much less amount of CPU resource
 - Output of this tool is designed to be suitable for processing with
   classical tools and technologies, like awk.
 - Could trace syscalls system-wide.
 - Could trace init (process with 'pid == 1'). Finally we have a proper
   tool for debugging systemd ;-)

WARNING: System-wide tracing can fill out your disk really fast.

# LIMITATIONS #

 - Limited functionality
 - Slow attaching and detaching
 - Asynchronity. If user will not provide enough system resources for
   performance tool will skip some calls. Tool does not assume to try
   any work-around behind the scene.
 - Depend on modern kernel features
 - Underlaing eBPF technology still is in active development. So we should
   expect hangs and crashes more often as for regular strace, especially on
   low-res systems.
 - Truncating of very long filenames (longer then ~NAME_MAX bytes) to ~NAME_MAX.
   Details:
    - https://github.com/iovisor/bcc/issues/900

# Outdated limitations

Could be useful with old libbcc versions.

 - Limited possibility to run few instances simultaneously.
   Details:
    - https://github.com/iovisor/bcc/pull/918
    - https://github.com/iovisor/bcc/issues/872

# SYSTEM REQUIREMENTS #

 - libbcc after commit e1f7462ceea60297b8ceb8e4dd9927069fce46de
 - Linux Kernel 4.4 or later (for Perf Event Circular Buffer)
 - CAP_SYS_ADMIN capability for bpf() syscall
 - mounted tracefs

# OPTIONS #

#Output format:

`-o, --output <file>`

filename

`-t, --timestamp`

include timestamp in output

`-l, --format <fmt>`

output logs format. Possible values:

	'bin', 'binary', 'hex', 'hex_raw', 'hex_sl', 'strace', 'list' & 'help'.

 - 'bin'/'binary' file format is the fastest one and is described in generated
   trace.h. If current directory is not writable generating of trace.h
   is skipped.

 - 'hex'/'hex_raw' the fastest text log format. Records for some calls could be
   splitted in few lines if used with '--filenames name_max' or like.

 - 'hex_sl' one-line text log format. Assembling syscall's record into one line
   by this tool will improove readability and simplify processing but could
   slowdown this tool if used with '--filenames name_max' or '--filenames full'.
   Implementation is not finished and is postponned.

 - 'strace' is going to emulate usual strace output, but is the slowest one.
   Assume assembling syscall's packets into one line.
   Implementation is not finished and is postponned.

Default: 'hex'

`-K, --hex-separator <sep>`

set field separator for hex logs. Default is '\\t'.


#Filtering:
`-X, --failed`

only show failed syscalls

`-e, --expr <expr>`

expression, 'help' or 'list' for supported list.

Default: trace=kp-kern-all.

#Tracing:

`-f, --full-follow-fork`

Follow new processes created with fork()/vfork()/clone()
syscall as regular strace does.

`-ff, --full-follow-fork=f`

Same as above, but put logs for each process in
separate file with name \<file\>\.pid
Implementation is not finished and is postponned.

`-fff, --full-follow-fork=ff`

Same as above, but put logs for each thread in
separate file with name \<file\>\.tid.pid
Implementation is not finished and is postponned.

`-F, --fast-follow-fork`

Follow new processes created with fork()/vfork()/clone()
in fast, but limited, way using kernel 4.8 feature
bpf_get_current_task(). This mode assume "level 1"
tracing only: no grandchildren or other descendants
will be traced.
Implementation is not debugged and is postponned.
Details:
 - https://github.com/iovisor/bcc/issues/799
 - http://lxr.free-electrons.com/source/kernel/sys.c?v=4.8#L847

`-FF, --fast-follow-fork=F`

Same as above, but put logs for each process in
separate file with name \<file\>\.pid
Implementation is not finished and is postponned.

`-FFF, --fast-follow-fork=FF`

Same as above, but put logs for each process in
separate file with name \<file\>\.tid.pid
Implementation is not finished and is postponned.

`-n, --filenames <mode>`

eBPF virtual machine is extremely limited in available memory. Also currently
there are no ways to calculate a len of strings. For this reason we introduced
four modes of fetching file-names:
 - 'fast' - everything what we could not fit into single packet will be
   truncated.
 - 'name_max' - fetch-up NAME_MAX bytes of name. Every name will be sent
   via separate packet. Processing of that packets is controlled by output
   log format.
 - 'number' - fetch-up 'number * NAME_MAX' bytes of name. Every part of name
   will be sent via separate packet. Processing of that packets is controlled
   by output log format. Minimal accepted value: 1.
   Implementation is not finished and is postponned.
 - 'full' - will be implemented as soon as this issue will be fixed:
   https://github.com/iovisor/bcc/issues/900

Default: fast

#Startup:
`-p, --pid <pid>`

trace this PID only. In current version `command` arg should be missing.
Press (CTRL-C) to send interrupt signal to exit.
Note
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

Print a list of all syscalls known by glibc.


# CONFIGURATION #

** System Configuring **

1. You should provide permissions to access tracefs for final user
   according to your distro documentation. Some of possible options:

    - In /etc/fstab add mode=755 option for debugfs AND tracefs.
    - Use sudo

2. It's good to put this command in init scripts such as local.rc:

	echo 1 > /proc/sys/net/core/bpf_jit_enable

	It will significantly improve performance and avoid 'Lost events'

3. You should increase "Open File Limit" according to your distro documentation.
   Few common ways you can find in this instruction:

    https://easyengine.io/tutorials/linux/increase-open-files-limit/

4. Kernel headers for running kernel should be installed.

5. CAP_SYS_ADMIN capability should be provided for user for bpf() syscall.
   In the newest kernel (4.10 ?) there is alternate option, but your should
   found it youself.


# FILES #

Putting into directory, supplied with -N option, modified template files
allow to customize eBPF code for supporting more newer eBPF VM features in
newer kernels.

Also if current directory does not contain trace.h file, strace.ebpf on first
start saves built-in trace.h into current directory. Saved built-in describe
binary log's format.

 - trace.h
 - ...

The rest of files could be figured out by looking into debug output, into eBPF
source code.

# EXAMPLES #

#Example output:

 # ./strace.ebpf -l hex

./strace.ebpf     -l                hex
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

 # ./strace.ebpf -l hex -tp 2833

./strace.ebpf     -l                hex               -tp               2833
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

 # ./strace.ebpf -l hex -X mkdir .

./strace.ebpf     -l                      hex                     -X      mkdir                                                      .

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

**strace**(1), **bpf**(2), **<https://github.com/vitalyvch/strace.ebpf>**.

Also Documentation/networking/filter.txt in kernel sources.
