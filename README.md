strace.ebpf: tool tracing syscalls using eBPF
=================================

This is the top-level README.md of strace.ebpf.

strace.ebpf is a tool tracing syscalls in a fast way using eBPF linux kernel feature.

### LICENSE ###

Please see the file [LICENSE](https://github.com/ldorau/strace.ebpf/blob/master/LICENSE)
for information on how this tool is licensed.

### DEPENDENCIES ###

The strace.ebpf depends on [libbcc](https://github.com/iovisor/bcc) library.

Warning: some old libbcc packages require manual coping of libbcc.pc from sources to
appropriate place in a system. In case of Ubuntu 16.04 LTS appropriate place
is /usr/lib/x86_64-linux-gnu/pkgconfig/libbcc.pc.

### SYSTEM REQUIREMENTS ###

 - kernel v4.4 or later (for Perf Event Circular Buffer)
 - kernel headers installed:
    - 'kernel-devel' package on RHEL, Fedora and CentOS or
    - 'linux-headers' package on Debian and Ubuntu
 - libbcc v0.2.0-313-g6c99958 or later
 - CAP_SYS_ADMIN capability (required by the bpf() syscall)
 - mounted tracefs

### CONTACTS ###

For more information about this tool contact:

 - Lukasz Dorau (lukasz.dorau at intel.com)

or create an issue [here](https://github.com/ldorau/strace.ebpf/issues).
