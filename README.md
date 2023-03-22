vltrace: syscall tracer using eBPF
==================================

[![Build Status](https://travis-ci.org/pmem/vltrace.svg)](https://travis-ci.org/pmem/vltrace)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/13758/badge.svg)](https://scan.coverity.com/projects/pmem-vltrace)

## ⚠️ Discontinuation of the project
The **vltrace** project will no longer be maintained by Intel.
- Intel has ceased development and contributions including, but not limited to, maintenance, bug fixes, new releases,
or updates, to this project.
- Intel no longer accepts patches to this project.
- If you have an ongoing need to use this project, are interested in independently developing it, or would like to
maintain patches for the open source software community, please create your own fork of this project.
- You will find more information [here](https://pmem.io/blog/2022/11/update-on-pmdk-and-our-long-term-support-strategy/).

## Introduction

This is the top-level README.md of vltrace.

vltrace is a syscall tracing tool which utilizes eBPF - an efficient tracing feature of the Linux kernel.

## LICENSE

Please see the file [LICENSE](https://github.com/pmem/vltrace/blob/master/LICENSE)
for information on how this tool is licensed.

## DEPENDENCIES

The vltrace depends on [libbcc](https://github.com/iovisor/bcc) library.
The installation guide of libbcc can be found [here](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

## SYSTEM REQUIREMENTS

 - kernel v4.7 or later [(to attach eBPF to tracepoints)](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
 - kernel headers installed:
    - 'kernel-devel' package on RHEL, Fedora and CentOS or
    - 'linux-headers' package on Debian and Ubuntu
 - libbcc v0.4.0
 - CAP_SYS_ADMIN capability (required by the bpf() syscall)
 - mounted debugfs and tracefs

## CONTACTS

If you read the [blog post](https://pmem.io/blog/2022/11/update-on-pmdk-and-our-long-term-support-strategy/) and still have some questions (especially about discontinuation of the project), please contact us using the dedicated e-mail: pmdk_support@intel.com.
