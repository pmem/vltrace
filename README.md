vltrace: syscall tracer using eBPF
==================================

[![Build Status](https://travis-ci.org/pmem/vltrace.svg)](https://travis-ci.org/pmem/vltrace)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/13758/badge.svg)](https://scan.coverity.com/projects/pmem-vltrace)

This is the top-level README.md of vltrace.

vltrace is a syscall tracing tool which utilizes eBPF - an efficient tracing feature of the Linux kernel.

### LICENSE ###

Please see the file [LICENSE](https://github.com/pmem/vltrace/blob/master/LICENSE)
for information on how this tool is licensed.

### DEPENDENCIES ###

The vltrace depends on [libbcc](https://github.com/iovisor/bcc) library.
The installation guide of libbcc can be found [here](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

### SYSTEM REQUIREMENTS ###

 - kernel v4.7 or later [(to attach eBPF to tracepoints)](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
 - kernel headers installed:
    - 'kernel-devel' package on RHEL, Fedora and CentOS or
    - 'linux-headers' package on Debian and Ubuntu
 - libbcc v0.4.0
 - CAP_SYS_ADMIN capability (required by the bpf() syscall)
 - mounted debugfs and tracefs

### CONTACTS ###

For more information about this tool contact:

 - Lukasz Dorau (lukasz.dorau at intel.com)

or create an issue [here](https://github.com/pmem/vltrace/issues).
