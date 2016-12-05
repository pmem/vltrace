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
[OPTIONS](#options)<br />
[CONFIGURATION](#configuration)<br />
[FILES](#files)<br />
[EXAMPLES](#examples)<br />
[SEE ALSO](#see-also)<br />


# NAME #

**strace.ebpf** -- extreamely fast strace-like tool builded on top of eBPF
and KProbe technologies.


# SYNOPSIS #

```
$ strace.ebpf [options] [command [arg ...]]
```


# DESCRIPTION #

strace.ebpf is a limited functional strace equivalent for Linux but based on
eBPF and KProbe technologies and libbcc library.

+ Pros:

    - Used combination of technologies allow tool to be about one order faster
      than regular system strace.
    - This tool consume much less amount of CPU resource
    - Output of this tool is designed to be suiteable for processing with
      classical tools and technologies, like awk.
    - Could trace syscalls system-wide.

+ Cons:

    - Limited functionality
    - Slow attaching and detaching
    - Asyncronity. If user will not provide enough system resources for
      performace tool will skip some calls. Tool does not assume to try
      any work-around behind the scene.


WARNING: System-wide tracing can fill out your disk really fast.


# OPTIONS #

`-t, --timestamp`

include timestamp in output

`-X, --failed`

only show failed syscalls

`-d, --debug`

enable debug output

`-p, --pid`

this PID only. Command arg should be missing

`-o, --output`

filename

`-l, --format`

output logs format. Possible values:

	'bin', 'binary', 'hex', 'strace', 'list' & 'help'.

'bin'/'binary' file format is described in generated trace.h. If current
directory is not writable generating is skipped.

Default: 'hex'

`-K, --hex-separator`

set field separator for hex logs. Default is '\t'.

`-e, --expr`

expression, 'help' or 'list' for supported list.

Default: trace=kp-kern-all.

`-L, --list`

Print a list of all traceable syscalls of the running kernel.

`-R, --ll-list`

Print a list of all traceable low-level funcs of the running kernel.

WARNING: really long. ~45000 functions for 4.4 kernel.

`-b, --builtin-list`

Print a list of all syscalls known by glibc.

`-h, --help`

print help


# CONFIGURATION #

** System Configuring **

1. You should provide permissions to access tracefs for final user.

2. It's good to put this command in init scripts such as local.rc:

	echo 1 > /proc/sys/net/core/bpf_jit_enable

	It will significantly improve performance and avoid 'Lost events'

3. You should increase "Open File Limit", for example according to this
    instruction:

    https://easyengine.io/tutorials/linux/increase-open-files-limit/


# FILES #

Putting into current directory following files allow to customize eBPF code for
supporting more newer eBPF VM features in newer kernels. Also if current
directory does not contain trace.h strace.ebpf on first start saves built-in
trace.h into current directory. Saved built-in describe binary log's format.

-	trace.h
-	trace_head.c
-	trace_tp_all.c
-	trace_kern_tmpl.c
-	trace_libc_tmpl.c
-	trace_file_tmpl.c
-	trace_fileat_tmpl.c


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

**strace**(1), **bpf**(2), **<http://pmem.io>**.

Also Documentation/networking/filter.txt in kernel sources.
