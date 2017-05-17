vltrace: tool tracing syscalls using eBPF
=================================

[![Build Status](https://travis-ci.org/pmem/vltrace.svg)](https://travis-ci.org/pmem/vltrace)

This is the top-level README.md of vltrace.

vltrace is a tool tracing syscalls in a fast way using eBPF linux kernel feature.

### LICENSE ###

Please see the file [LICENSE](https://github.com/pmem/vltrace/blob/master/LICENSE)
for information on how this tool is licensed.

### DEPENDENCIES ###

The vltrace depends on [libbcc](https://github.com/iovisor/bcc) library.
The installation guide of libbcc can be found [here](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

Warning: some old libbcc packages require manual copying of libbcc.pc from sources to
appropriate place in a system. In case of Ubuntu 16.04 LTS appropriate place
is /usr/lib/x86_64-linux-gnu/pkgconfig/libbcc.pc.

### SYSTEM REQUIREMENTS ###

 - kernel v4.7 or later [(to attach eBPF to tracepoints)](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
 - kernel headers installed:
    - 'kernel-devel' package on RHEL, Fedora and CentOS or
    - 'linux-headers' package on Debian and Ubuntu
 - libbcc v0.3.0-150-g3263805 or later
 - CAP_SYS_ADMIN capability (required by the bpf() syscall)
 - mounted debugfs and tracefs

### CONTACTS ###

For more information about this tool contact:

 - Lukasz Dorau (lukasz.dorau at intel.com)

or create an issue [here](https://github.com/pmem/vltrace/issues).
