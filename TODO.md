# TODO

1. Performance improvement
============================

Currently we require a bit more than 1000 nsec for tracing a single syscall.
It is not bad but there are at least a few places which could allow us to
reduce this value maybe to 600 nsec. Every syscall itself currently requires
a bit more than 100 nsec for entering and close to the same value for
returning. So a bit more than 200 nsec together.

1.1 Extra poll()
-----------------

_Currently libbcc does two poll() syscalls per iter. There is no reason for
it and we should drop it. It will improve our time by about 200 nsec, but it
is a libbcc bug. A backtrace for one of that poll() syscalls:_

```
(gdb) bt
#0  poll () at ../sysdeps/unix/syscall-template.S:84
#1  0x00007f9c40a07566 in perf_reader_poll () from /usr/lib/x86_64-linux-gnu/libbcc.so.0
#2  0x0000000000401a7b in kprobe_poll (b=<optimized out>, timeout=<optimized out>) at BPF.c:82
#3  0x000000000040175d in main (argc=<optimized out>, argv=0x7fffe635c888) at snoop.c:228
```

GitHub issue: https://github.com/iovisor/bcc/issues/779

1.2 Tracepoints support
-----------------------

Currently kernel provides a way for fast intercepting of all syscalls together.
But we temporarily can't use it because of this bug:

    - https://github.com/iovisor/bcc/issues/748

As soon as this bug will be fixed we should try it one more time.

1.3 Output buffering
--------------------

Optimization of this place is critical to achieve maximum possible log
bandwidth. Most likely we should use fd directly.


2. Debugging
=============

2.1 Enable Valgrind
--------------------

_Currently Valgrind fails with a message like:_

```
--12470-- WARNING: unhandled amd64-linux syscall: 321
==12470==    at 0x77F7C19: syscall (syscall.S:38)
==12470==    by 0x5129133: bpf_create_map (in /usr/lib/x86_64-linux-gnu/libbcc.so.0.1.8)
==12470==    by 0x5181809: ??? (in /usr/lib/x86_64-linux-gnu/libbcc.so.0.1.8)
==12470==    by 0x51AE4A7: ??? (in /usr/lib/x86_64-linux-gnu/libbcc.so.0.1.8)
==12470==    by 0x51835E6: ??? (in /usr/lib/x86_64-linux-gnu/libbcc.so.0.1.8)
==12470==    by 0x522FE1C: ??? (in /usr/lib/x86_64-linux-gnu/libbcc.so.0.1.8)
==12470==    by 0x53DCE85: ??? (in /usr/lib/x86_64-linux-gnu/libbcc.so.0.1.8)
==12470==    by 0x520B9BD: ??? (in /usr/lib/x86_64-linux-gnu/libbcc.so.0.1.8)
==12470==    by 0x51E0065: ??? (in /usr/lib/x86_64-linux-gnu/libbcc.so.0.1.8)
==12470==    by 0x51751A4: ??? (in /usr/lib/x86_64-linux-gnu/libbcc.so.0.1.8)
==12470==    by 0x51209B3: ebpf::BPFModule::load_cfile(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, bool, char const**, int) (in /usr/lib/x86_64-linux-gnu/libbcc.so.0.1.8)
==12470==    by 0x51268FD: ebpf::BPFModule::load_string(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, char const**, int) (in /usr/lib/x86_64-linux-gnu/libbcc.so.0.1.8)
--12470-- You may be able to write your own handler.
--12470-- Read the file README_MISSING_SYSCALL_OR_IOCTL.
--12470-- Nevertheless we consider this a bug.  Please report
--12470-- it at http://valgrind.org/support/bug_reports.html.
```


3. Extra features
==================

3.1 Multi-process tracing
--------------------------

It is not difficult to attach to multiple PIDs simultaneously. Maybe we should do
it for parallel applications like apache, nginx and like. Most likelly we
should simulate -p option from `man 1 strace`.

3.2 Attaching by name
----------------------

It is good to have the ability to attach to processes not only by PIDs
but also by names.

3.3 Implement one more way to attach, using hack with seccomp
--------------------------------------------------------------

It will improve the time of attaching and detaching.

 - https://github.com/iovisor/bcc/issues/786


4. Output logs
============================

4.1 Binary log format: packet-counter field
--------------------------------------------

We should think about writting 64-bit packet number before length
of packet, because it will enlarge reliability of logs. But there is
probability that counting packets will be very expensive, because we run
in multi-threading environment.
