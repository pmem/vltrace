/*
 * Copyright 2016, Intel Corporation
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
 * ebpf_syscalls.c -- a table of glibc-supported syscalls
 */

#include <stdlib.h>

#include "ebpf_syscalls.h"


/* EBPF_SYSCALL(__NR_setxattr, sys_setxattr) */
#define EBPF_SYSCALL(nr, sym)    [nr] = {\
	.num = nr, \
	.num_name = #nr, \
	.hlr_name = #sym, \
	.masks = 0 },

#define EBPF_SYSCALL_FILE(nr, sym)    [nr] = {\
	.num = nr, \
	.num_name = #nr, \
	.hlr_name = #sym, \
	.masks = EM_file },

#define EBPF_SYSCALL_FILEAT(nr, sym)    [nr] = {\
	.num = nr, \
	.num_name = #nr, \
	.hlr_name = #sym, \
	.masks = EM_fileat },

#define EBPF_SYSCALL_DESC(nr, sym)    [nr] = {\
	.num = nr, \
	.num_name = #nr, \
	.hlr_name = #sym, \
	.masks = EM_desc },

#define SC_NI { .num = SC_TBL_SIZE, \
	.num_name = "NI", \
	.hlr_name = NULL }

/*
 * Commented syscalls mean that syscall exists in the kernel but glibc
 *    does not provide __NR_* and SYS_* macros.
 */
struct sc_t sc_tbl[SC_TBL_SIZE] = {
	[0 ... SC_TBL_SIZE - 1] = SC_NI,
	/*
	 * [__NR_open]  =
	 *    { .num = __NR_open,  .hlr_name = "SyS_open",  .masks = EM_file },
	 * [__NR_read]  =
	 *    { .num = __NR_read,  .hlr_name = "SyS_read",  .masks = EM_desk },
	 * [__NR_write] =
	 *    { .num = __NR_write, .hlr_name = "SyS_write", .masks = EM_desk },
	 * [__NR_close] =
	 *    { .num = __NR_close, .hlr_name = "SyS_close", .masks = EM_desk },
	 */

EBPF_SYSCALL(__NR_arch_prctl, sys_arch_prctl)
EBPF_SYSCALL(__NR_rt_sigreturn, sys_rt_sigreturn)
EBPF_SYSCALL(__NR_ioperm, sys_ioperm)
EBPF_SYSCALL(__NR_iopl, SyS_iopl)
EBPF_SYSCALL(__NR_modify_ldt, sys_modify_ldt)
EBPF_SYSCALL_DESC(__NR_mmap, SyS_mmap)
EBPF_SYSCALL(__NR_set_thread_area, SyS_set_thread_area)
EBPF_SYSCALL(__NR_get_thread_area, SyS_get_thread_area)
EBPF_SYSCALL(__NR_set_tid_address, SyS_set_tid_address)
EBPF_SYSCALL(__NR_fork, sys_fork)
EBPF_SYSCALL(__NR_vfork, sys_vfork)
EBPF_SYSCALL(__NR_clone, SyS_clone)
EBPF_SYSCALL(__NR_unshare, SyS_unshare)
EBPF_SYSCALL(__NR_personality, SyS_personality)
EBPF_SYSCALL(__NR_exit, SyS_exit)
EBPF_SYSCALL(__NR_exit_group, SyS_exit_group)
EBPF_SYSCALL(__NR_waitid, SyS_waitid)
EBPF_SYSCALL(__NR_wait4, SyS_wait4)
/* EBPF_SYSCALL(__NR_waitpid, SyS_waitpid) */
EBPF_SYSCALL(__NR__sysctl, SyS_sysctl)
EBPF_SYSCALL(__NR_capget, SyS_capget)
EBPF_SYSCALL(__NR_capset, SyS_capset)
EBPF_SYSCALL(__NR_ptrace, SyS_ptrace)
EBPF_SYSCALL(__NR_restart_syscall, sys_restart_syscall)
EBPF_SYSCALL(__NR_rt_sigprocmask, SyS_rt_sigprocmask)
EBPF_SYSCALL(__NR_rt_sigpending, SyS_rt_sigpending)
EBPF_SYSCALL(__NR_rt_sigtimedwait, SyS_rt_sigtimedwait)
EBPF_SYSCALL(__NR_kill, SyS_kill)
EBPF_SYSCALL(__NR_tgkill, SyS_tgkill)
EBPF_SYSCALL(__NR_tkill, SyS_tkill)
EBPF_SYSCALL(__NR_rt_sigqueueinfo, SyS_rt_sigqueueinfo)
EBPF_SYSCALL(__NR_rt_tgsigqueueinfo, SyS_rt_tgsigqueueinfo)
EBPF_SYSCALL(__NR_sigaltstack, SyS_sigaltstack)
/* EBPF_SYSCALL(__NR_sigpending, SyS_sigpending) */
/* EBPF_SYSCALL(__NR_sigprocmask, SyS_sigprocmask) */
EBPF_SYSCALL(__NR_rt_sigaction, SyS_rt_sigaction)
/* EBPF_SYSCALL(__NR_sgetmask, sys_sgetmask) */
/* EBPF_SYSCALL(__NR_ssetmask, SyS_ssetmask) */
/* EBPF_SYSCALL(__NR_signal, SyS_signal) */
EBPF_SYSCALL(__NR_pause, sys_pause)
EBPF_SYSCALL(__NR_rt_sigsuspend, SyS_rt_sigsuspend)
/* EBPF_SYSCALL(__NR_sigsuspend, SyS_sigsuspend) */
/* EBPF_SYSCALL(__NR_sigsuspend, SyS_sigsuspend) */
EBPF_SYSCALL(__NR_setpriority, SyS_setpriority)
EBPF_SYSCALL(__NR_getpriority, SyS_getpriority)
EBPF_SYSCALL(__NR_setregid, SyS_setregid)
EBPF_SYSCALL(__NR_setgid, SyS_setgid)
EBPF_SYSCALL(__NR_setreuid, SyS_setreuid)
EBPF_SYSCALL(__NR_setuid, SyS_setuid)
EBPF_SYSCALL(__NR_setresuid, SyS_setresuid)
EBPF_SYSCALL(__NR_getresuid, SyS_getresuid)
EBPF_SYSCALL(__NR_setresgid, SyS_setresgid)
EBPF_SYSCALL(__NR_getresgid, SyS_getresgid)
EBPF_SYSCALL(__NR_setfsuid, SyS_setfsuid)
EBPF_SYSCALL(__NR_setfsgid, SyS_setfsgid)
EBPF_SYSCALL(__NR_getpid, sys_getpid)
EBPF_SYSCALL(__NR_gettid, sys_gettid)
EBPF_SYSCALL(__NR_getppid, sys_getppid)
EBPF_SYSCALL(__NR_getuid, sys_getuid)
EBPF_SYSCALL(__NR_geteuid, sys_geteuid)
EBPF_SYSCALL(__NR_getgid, sys_getgid)
EBPF_SYSCALL(__NR_getegid, sys_getegid)
EBPF_SYSCALL(__NR_times, SyS_times)
EBPF_SYSCALL(__NR_setpgid, SyS_setpgid)
EBPF_SYSCALL(__NR_getpgid, SyS_getpgid)
EBPF_SYSCALL(__NR_getpgrp, sys_getpgrp)
EBPF_SYSCALL(__NR_getsid, SyS_getsid)
EBPF_SYSCALL(__NR_setsid, sys_setsid)
/* EBPF_SYSCALL(__NR_newuname, SyS_newuname) */
EBPF_SYSCALL(__NR_uname, SyS_uname)
/* EBPF_SYSCALL(__NR_olduname, SyS_olduname) */
EBPF_SYSCALL(__NR_sethostname, SyS_sethostname)
/* EBPF_SYSCALL(__NR_gethostname, SyS_gethostname) */
EBPF_SYSCALL(__NR_setdomainname, SyS_setdomainname)
/* EBPF_SYSCALL(__NR_old_getrlimit, SyS_old_getrlimit) */
EBPF_SYSCALL(__NR_getrlimit, SyS_getrlimit)
EBPF_SYSCALL(__NR_prlimit64, SyS_prlimit64)
EBPF_SYSCALL(__NR_setrlimit, SyS_setrlimit)
EBPF_SYSCALL(__NR_getrusage, SyS_getrusage)
EBPF_SYSCALL(__NR_umask, SyS_umask)
EBPF_SYSCALL(__NR_prctl, SyS_prctl)
EBPF_SYSCALL(__NR_getcpu, SyS_getcpu)
EBPF_SYSCALL(__NR_sysinfo, SyS_sysinfo)
/* EBPF_SYSCALL(__NR_ni_syscall, sys_ni_syscall) */
EBPF_SYSCALL(__NR_setns, SyS_setns)
EBPF_SYSCALL(__NR_reboot, SyS_reboot)
EBPF_SYSCALL(__NR_getgroups, SyS_getgroups)
EBPF_SYSCALL(__NR_setgroups, SyS_setgroups)
/* EBPF_SYSCALL(__NR_nice, SyS_nice) */
EBPF_SYSCALL(__NR_sched_setscheduler, SyS_sched_setscheduler)
EBPF_SYSCALL(__NR_sched_setparam, SyS_sched_setparam)
EBPF_SYSCALL(__NR_sched_setattr, SyS_sched_setattr)
EBPF_SYSCALL(__NR_sched_getscheduler, SyS_sched_getscheduler)
EBPF_SYSCALL(__NR_sched_getparam, SyS_sched_getparam)
EBPF_SYSCALL(__NR_sched_getattr, SyS_sched_getattr)
EBPF_SYSCALL(__NR_sched_setaffinity, SyS_sched_setaffinity)
EBPF_SYSCALL(__NR_sched_getaffinity, SyS_sched_getaffinity)
EBPF_SYSCALL(__NR_sched_yield, sys_sched_yield)
EBPF_SYSCALL(__NR_sched_get_priority_max, SyS_sched_get_priority_max)
EBPF_SYSCALL(__NR_sched_get_priority_min, SyS_sched_get_priority_min)
EBPF_SYSCALL(__NR_sched_rr_get_interval, SyS_sched_rr_get_interval)
EBPF_SYSCALL(__NR_syslog, SyS_syslog)
EBPF_SYSCALL(__NR_kcmp, SyS_kcmp)
EBPF_SYSCALL(__NR_time, SyS_time)
/* EBPF_SYSCALL(__NR_stime, SyS_stime) */
EBPF_SYSCALL(__NR_gettimeofday, SyS_gettimeofday)
EBPF_SYSCALL(__NR_settimeofday, SyS_settimeofday)
EBPF_SYSCALL(__NR_adjtimex, SyS_adjtimex)
EBPF_SYSCALL(__NR_alarm, SyS_alarm)
EBPF_SYSCALL(__NR_nanosleep, SyS_nanosleep)
EBPF_SYSCALL(__NR_getitimer, SyS_getitimer)
EBPF_SYSCALL(__NR_setitimer, SyS_setitimer)
EBPF_SYSCALL(__NR_timer_create, SyS_timer_create)
EBPF_SYSCALL(__NR_timer_gettime, SyS_timer_gettime)
EBPF_SYSCALL(__NR_timer_getoverrun, SyS_timer_getoverrun)
EBPF_SYSCALL(__NR_timer_settime, SyS_timer_settime)
EBPF_SYSCALL(__NR_timer_delete, SyS_timer_delete)
EBPF_SYSCALL(__NR_clock_settime, SyS_clock_settime)
EBPF_SYSCALL(__NR_clock_gettime, SyS_clock_gettime)
EBPF_SYSCALL(__NR_clock_adjtime, SyS_clock_adjtime)
EBPF_SYSCALL(__NR_clock_getres, SyS_clock_getres)
EBPF_SYSCALL(__NR_clock_nanosleep, SyS_clock_nanosleep)
EBPF_SYSCALL(__NR_set_robust_list, SyS_set_robust_list)
EBPF_SYSCALL(__NR_get_robust_list, SyS_get_robust_list)
EBPF_SYSCALL(__NR_futex, SyS_futex)
/* EBPF_SYSCALL(__NR_chown16, SyS_chown16) */
/* EBPF_SYSCALL(__NR_lchown16, SyS_lchown16) */
/* EBPF_SYSCALL(__NR_fchown16, SyS_fchown16) */
/* EBPF_SYSCALL(__NR_setregid16, SyS_setregid16) */
/* EBPF_SYSCALL(__NR_setgid16, SyS_setgid16) */
/* EBPF_SYSCALL(__NR_setreuid16, SyS_setreuid16) */
/* EBPF_SYSCALL(__NR_setuid16, SyS_setuid16) */
/* EBPF_SYSCALL(__NR_setresuid16, SyS_setresuid16) */
/* EBPF_SYSCALL(__NR_getresuid16, SyS_getresuid16) */
/* EBPF_SYSCALL(__NR_setresgid16, SyS_setresgid16) */
/* EBPF_SYSCALL(__NR_getresgid16, SyS_getresgid16) */
/* EBPF_SYSCALL(__NR_setfsuid16, SyS_setfsuid16) */
/* EBPF_SYSCALL(__NR_setfsgid16, SyS_setfsgid16) */
/* EBPF_SYSCALL(__NR_getgroups16, SyS_getgroups16) */
/* EBPF_SYSCALL(__NR_setgroups16, SyS_setgroups16) */
/* EBPF_SYSCALL(__NR_getuid16, sys_getuid16) */
/* EBPF_SYSCALL(__NR_geteuid16, sys_geteuid16) */
/* EBPF_SYSCALL(__NR_getgid16, sys_getgid16) */
/* EBPF_SYSCALL(__NR_getegid16, sys_getegid16) */
EBPF_SYSCALL_FILE(__NR_delete_module, SyS_delete_module)
EBPF_SYSCALL(__NR_init_module, SyS_init_module)
EBPF_SYSCALL_DESC(__NR_finit_module, SyS_finit_module)
EBPF_SYSCALL_FILE(__NR_acct, SyS_acct)
EBPF_SYSCALL(__NR_kexec_load, SyS_kexec_load)
EBPF_SYSCALL_DESC(__NR_kexec_file_load, SyS_kexec_file_load)
EBPF_SYSCALL(__NR_seccomp, SyS_seccomp)
EBPF_SYSCALL(__NR_bpf, SyS_bpf)
EBPF_SYSCALL(__NR_membarrier, SyS_membarrier)
EBPF_SYSCALL_DESC(__NR_readahead, SyS_readahead)
EBPF_SYSCALL_FILE(__NR_memfd_create, SyS_memfd_create)
EBPF_SYSCALL(__NR_mincore, SyS_mincore)
EBPF_SYSCALL(__NR_mlock, SyS_mlock)
EBPF_SYSCALL(__NR_mlock2, SyS_mlock2)
EBPF_SYSCALL(__NR_munlock, SyS_munlock)
EBPF_SYSCALL(__NR_mlockall, SyS_mlockall)
EBPF_SYSCALL(__NR_munlockall, sys_munlockall)
/* EBPF_SYSCALL(__NR_mmap_pgoff, SyS_mmap_pgoff) */
EBPF_SYSCALL(__NR_brk, SyS_brk)
EBPF_SYSCALL(__NR_munmap, SyS_munmap)
EBPF_SYSCALL(__NR_remap_file_pages, SyS_remap_file_pages)
EBPF_SYSCALL(__NR_mprotect, SyS_mprotect)
EBPF_SYSCALL(__NR_mremap, SyS_mremap)
EBPF_SYSCALL(__NR_msync, SyS_msync)
EBPF_SYSCALL(__NR_process_vm_readv, SyS_process_vm_readv)
EBPF_SYSCALL(__NR_process_vm_writev, SyS_process_vm_writev)
/* EBPF_SYSCALL_DESC(__NR_fadvise64_64, SyS_fadvise64_64) */
EBPF_SYSCALL_DESC(__NR_fadvise64, SyS_fadvise64)
EBPF_SYSCALL(__NR_madvise, SyS_madvise)
EBPF_SYSCALL_FILE(__NR_swapoff, SyS_swapoff)
EBPF_SYSCALL_FILE(__NR_swapon, SyS_swapon)
EBPF_SYSCALL(__NR_set_mempolicy, SyS_set_mempolicy)
EBPF_SYSCALL(__NR_migrate_pages, SyS_migrate_pages)
EBPF_SYSCALL(__NR_get_mempolicy, SyS_get_mempolicy)
EBPF_SYSCALL(__NR_mbind, SyS_mbind)
EBPF_SYSCALL(__NR_move_pages, SyS_move_pages)
EBPF_SYSCALL_DESC(__NR_close, SyS_close)
EBPF_SYSCALL_FILE(__NR_truncate, SyS_truncate)
EBPF_SYSCALL_DESC(__NR_ftruncate, SyS_ftruncate)
EBPF_SYSCALL_DESC(__NR_fallocate, SyS_fallocate)
EBPF_SYSCALL_FILEAT(__NR_faccessat, SyS_faccessat)
EBPF_SYSCALL_FILE(__NR_access, SyS_access)
EBPF_SYSCALL_FILE(__NR_chdir, SyS_chdir)
EBPF_SYSCALL_DESC(__NR_fchdir, SyS_fchdir)
EBPF_SYSCALL_FILE(__NR_chroot, SyS_chroot)
EBPF_SYSCALL_DESC(__NR_fchmod, SyS_fchmod)
EBPF_SYSCALL_FILEAT(__NR_fchmodat, SyS_fchmodat)
EBPF_SYSCALL_FILE(__NR_chmod, SyS_chmod)
EBPF_SYSCALL_FILEAT(__NR_fchownat, SyS_fchownat)
EBPF_SYSCALL_FILE(__NR_chown, SyS_chown)
EBPF_SYSCALL_FILE(__NR_lchown, SyS_lchown)
EBPF_SYSCALL_DESC(__NR_fchown, SyS_fchown)
EBPF_SYSCALL_FILE(__NR_open, SyS_open)
EBPF_SYSCALL_FILEAT(__NR_openat, SyS_openat)
EBPF_SYSCALL_FILE(__NR_creat, SyS_creat)
EBPF_SYSCALL(__NR_vhangup, sys_vhangup)
EBPF_SYSCALL_DESC(__NR_lseek, SyS_lseek)
/* EBPF_SYSCALL_DESC(__NR_llseek, SyS_llseek) */
EBPF_SYSCALL_DESC(__NR_read, SyS_read)
EBPF_SYSCALL_DESC(__NR_write, SyS_write)
EBPF_SYSCALL_DESC(__NR_pread64, SyS_pread64)
EBPF_SYSCALL_DESC(__NR_pwrite64, SyS_pwrite64)
EBPF_SYSCALL_DESC(__NR_readv, SyS_readv)
EBPF_SYSCALL_DESC(__NR_writev, SyS_writev)
EBPF_SYSCALL_DESC(__NR_preadv, SyS_preadv)
EBPF_SYSCALL_DESC(__NR_pwritev, SyS_pwritev)
EBPF_SYSCALL_DESC(__NR_sendfile, SyS_sendfile)
/* EBPF_SYSCALL_DESC(__NR_sendfile64, SyS_sendfile64) */
EBPF_SYSCALL_FILE(__NR_stat, SyS_stat)
EBPF_SYSCALL_FILE(__NR_lstat, SyS_lstat)
EBPF_SYSCALL_DESC(__NR_fstat, SyS_fstat)
EBPF_SYSCALL_FILE(__NR_stat, SyS_newstat)
EBPF_SYSCALL_FILE(__NR_lstat, SyS_newlstat)
EBPF_SYSCALL_DESC(__NR_newfstatat, SyS_newfstatat)
EBPF_SYSCALL_DESC(__NR_fstat, SyS_newfstat)
EBPF_SYSCALL_FILEAT(__NR_readlinkat, SyS_readlinkat)
EBPF_SYSCALL_FILE(__NR_readlink, SyS_readlink)
EBPF_SYSCALL_FILE(__NR_uselib, SyS_uselib)
EBPF_SYSCALL_FILE(__NR_execve, SyS_execve)
EBPF_SYSCALL_FILEAT(__NR_execveat, SyS_execveat)
EBPF_SYSCALL(__NR_pipe2, SyS_pipe2)
EBPF_SYSCALL(__NR_pipe, SyS_pipe)
EBPF_SYSCALL_FILEAT(__NR_mknodat, SyS_mknodat)
EBPF_SYSCALL_FILE(__NR_mknod, SyS_mknod)
EBPF_SYSCALL_FILEAT(__NR_mkdirat, SyS_mkdirat)
EBPF_SYSCALL_FILE(__NR_mkdir, SyS_mkdir)
EBPF_SYSCALL_FILE(__NR_rmdir, SyS_rmdir)
EBPF_SYSCALL_FILEAT(__NR_unlinkat, SyS_unlinkat)
EBPF_SYSCALL_FILE(__NR_unlink, SyS_unlink)
/* WARNING non-standard API */
EBPF_SYSCALL_FILE(__NR_symlinkat, SyS_symlinkat)
EBPF_SYSCALL_FILE(__NR_symlink, SyS_symlink)
EBPF_SYSCALL_FILEAT(__NR_linkat, SyS_linkat)
EBPF_SYSCALL_FILE(__NR_link, SyS_link)
EBPF_SYSCALL_FILEAT(__NR_renameat2, SyS_renameat2)
EBPF_SYSCALL_FILEAT(__NR_renameat, SyS_renameat)
EBPF_SYSCALL_FILE(__NR_rename, SyS_rename)
EBPF_SYSCALL_DESC(__NR_fcntl, SyS_fcntl)
EBPF_SYSCALL_DESC(__NR_ioctl, SyS_ioctl)
/* EBPF_SYSCALL_DESC(__NR_old_readdir, SyS_old_readdir) */
EBPF_SYSCALL_DESC(__NR_getdents, SyS_getdents)
EBPF_SYSCALL_DESC(__NR_getdents64, SyS_getdents64)
EBPF_SYSCALL(__NR_select, SyS_select)
EBPF_SYSCALL(__NR_pselect6, SyS_pselect6)
EBPF_SYSCALL(__NR_poll, SyS_poll)
EBPF_SYSCALL(__NR_ppoll, SyS_ppoll)
EBPF_SYSCALL(__NR_getcwd, SyS_getcwd)
EBPF_SYSCALL_DESC(__NR_dup3, SyS_dup3)
EBPF_SYSCALL_DESC(__NR_dup2, SyS_dup2)
EBPF_SYSCALL_DESC(__NR_dup, SyS_dup)
EBPF_SYSCALL(__NR_sysfs, SyS_sysfs)
/* EBPF_SYSCALL_FILE(__NR_umount, SyS_umount) */
/* EBPF_SYSCALL_FILE(__NR_oldumount, SyS_oldumount) */
EBPF_SYSCALL_FILE(__NR_mount, SyS_mount)
EBPF_SYSCALL_FILE(__NR_pivot_root, SyS_pivot_root)
EBPF_SYSCALL_FILE(__NR_setxattr, SyS_setxattr)
EBPF_SYSCALL_FILE(__NR_lsetxattr, SyS_lsetxattr)
EBPF_SYSCALL_DESC(__NR_fsetxattr, SyS_fsetxattr)
EBPF_SYSCALL_FILE(__NR_getxattr, SyS_getxattr)
EBPF_SYSCALL_FILE(__NR_lgetxattr, SyS_lgetxattr)
EBPF_SYSCALL_DESC(__NR_fgetxattr, SyS_fgetxattr)
EBPF_SYSCALL_FILE(__NR_listxattr, SyS_listxattr)
EBPF_SYSCALL_FILE(__NR_llistxattr, SyS_llistxattr)
EBPF_SYSCALL_DESC(__NR_flistxattr, SyS_flistxattr)
EBPF_SYSCALL_FILE(__NR_removexattr, SyS_removexattr)
EBPF_SYSCALL_FILE(__NR_lremovexattr, SyS_lremovexattr)
EBPF_SYSCALL_DESC(__NR_fremovexattr, SyS_fremovexattr)
EBPF_SYSCALL_DESC(__NR_vmsplice, SyS_vmsplice)
EBPF_SYSCALL_DESC(__NR_splice, SyS_splice)
EBPF_SYSCALL_DESC(__NR_tee, SyS_tee)
EBPF_SYSCALL(__NR_sync, sys_sync)
EBPF_SYSCALL_DESC(__NR_syncfs, SyS_syncfs)
EBPF_SYSCALL_DESC(__NR_fsync, SyS_fsync)
EBPF_SYSCALL_DESC(__NR_fdatasync, SyS_fdatasync)
EBPF_SYSCALL_DESC(__NR_sync_file_range, SyS_sync_file_range)
/* EBPF_SYSCALL_DESC(__NR_sync_file_range2, SyS_sync_file_range2) */
EBPF_SYSCALL_FILE(__NR_utime, SyS_utime)
EBPF_SYSCALL_FILEAT(__NR_utimensat, SyS_utimensat)
EBPF_SYSCALL_FILEAT(__NR_futimesat, SyS_futimesat)
EBPF_SYSCALL_FILE(__NR_utimes, SyS_utimes)
EBPF_SYSCALL_FILE(__NR_statfs, SyS_statfs)
/* EBPF_SYSCALL_FILE(__NR_statfs64, SyS_statfs64) */
EBPF_SYSCALL_DESC(__NR_fstatfs, SyS_fstatfs)
/* EBPF_SYSCALL_DESC(__NR_fstatfs64, SyS_fstatfs64) */
EBPF_SYSCALL(__NR_ustat, SyS_ustat)
/* EBPF_SYSCALL(__NR_bdflush, SyS_bdflush) */
EBPF_SYSCALL(__NR_inotify_init1, SyS_inotify_init1)
EBPF_SYSCALL(__NR_inotify_init, sys_inotify_init)
EBPF_SYSCALL_DESC(__NR_inotify_add_watch, SyS_inotify_add_watch)
EBPF_SYSCALL_DESC(__NR_inotify_rm_watch, SyS_inotify_rm_watch)
EBPF_SYSCALL(__NR_fanotify_init, SyS_fanotify_init)
EBPF_SYSCALL_DESC(__NR_fanotify_mark, SyS_fanotify_mark)
EBPF_SYSCALL(__NR_epoll_create1, SyS_epoll_create1)
EBPF_SYSCALL(__NR_epoll_create, SyS_epoll_create)
EBPF_SYSCALL_DESC(__NR_epoll_ctl, SyS_epoll_ctl)
EBPF_SYSCALL_DESC(__NR_epoll_wait, SyS_epoll_wait)
EBPF_SYSCALL_DESC(__NR_epoll_pwait, SyS_epoll_pwait)
EBPF_SYSCALL_DESC(__NR_signalfd4, SyS_signalfd4)
EBPF_SYSCALL_DESC(__NR_signalfd, SyS_signalfd)
EBPF_SYSCALL(__NR_timerfd_create, SyS_timerfd_create)
EBPF_SYSCALL_DESC(__NR_timerfd_settime, SyS_timerfd_settime)
EBPF_SYSCALL_DESC(__NR_timerfd_gettime, SyS_timerfd_gettime)
EBPF_SYSCALL(__NR_eventfd2, SyS_eventfd2)
EBPF_SYSCALL(__NR_eventfd, SyS_eventfd)
EBPF_SYSCALL(__NR_userfaultfd, SyS_userfaultfd)
EBPF_SYSCALL(__NR_io_setup, SyS_io_setup)
EBPF_SYSCALL(__NR_io_destroy, SyS_io_destroy)
EBPF_SYSCALL(__NR_io_submit, SyS_io_submit)
EBPF_SYSCALL(__NR_io_cancel, SyS_io_cancel)
EBPF_SYSCALL(__NR_io_getevents, SyS_io_getevents)
EBPF_SYSCALL_DESC(__NR_flock, SyS_flock)
EBPF_SYSCALL_FILEAT(__NR_name_to_handle_at, SyS_name_to_handle_at)
EBPF_SYSCALL_DESC(__NR_open_by_handle_at, SyS_open_by_handle_at)
EBPF_SYSCALL(__NR_quotactl, SyS_quotactl)
EBPF_SYSCALL(__NR_lookup_dcookie, SyS_lookup_dcookie)
EBPF_SYSCALL(__NR_msgget, SyS_msgget)
EBPF_SYSCALL(__NR_msgctl, SyS_msgctl)
EBPF_SYSCALL(__NR_msgsnd, SyS_msgsnd)
EBPF_SYSCALL(__NR_msgrcv, SyS_msgrcv)
EBPF_SYSCALL(__NR_semget, SyS_semget)
EBPF_SYSCALL(__NR_semctl, SyS_semctl)
EBPF_SYSCALL(__NR_semtimedop, SyS_semtimedop)
EBPF_SYSCALL(__NR_semop, SyS_semop)
EBPF_SYSCALL(__NR_shmget, SyS_shmget)
EBPF_SYSCALL(__NR_shmctl, SyS_shmctl)
EBPF_SYSCALL(__NR_shmat, SyS_shmat)
EBPF_SYSCALL(__NR_shmdt, SyS_shmdt)
EBPF_SYSCALL_FILE(__NR_mq_open, SyS_mq_open)
EBPF_SYSCALL_FILE(__NR_mq_unlink, SyS_mq_unlink)
EBPF_SYSCALL(__NR_mq_timedsend, SyS_mq_timedsend)
EBPF_SYSCALL(__NR_mq_timedreceive, SyS_mq_timedreceive)
EBPF_SYSCALL(__NR_mq_notify, SyS_mq_notify)
EBPF_SYSCALL(__NR_mq_getsetattr, SyS_mq_getsetattr)
EBPF_SYSCALL(__NR_add_key, SyS_add_key)
EBPF_SYSCALL(__NR_request_key, SyS_request_key)
EBPF_SYSCALL(__NR_keyctl, SyS_keyctl)
EBPF_SYSCALL(__NR_ioprio_set, SyS_ioprio_set)
EBPF_SYSCALL(__NR_ioprio_get, SyS_ioprio_get)
/* EBPF_SYSCALL(__NR_size_show, sys_size_show) */
EBPF_SYSCALL(__NR_getrandom, SyS_getrandom)
/* EBPF_SYSCALL(__NR_dmi_field_show, sys_dmi_field_show) */
/* EBPF_SYSCALL(__NR_dmi_modalias_show, sys_dmi_modalias_show) */
EBPF_SYSCALL(__NR_socket, SyS_socket)
EBPF_SYSCALL(__NR_socketpair, SyS_socketpair)
EBPF_SYSCALL_DESC(__NR_bind, SyS_bind)
EBPF_SYSCALL_DESC(__NR_listen, SyS_listen)
EBPF_SYSCALL_DESC(__NR_accept4, SyS_accept4)
EBPF_SYSCALL_DESC(__NR_accept, SyS_accept)
EBPF_SYSCALL_DESC(__NR_connect, SyS_connect)
EBPF_SYSCALL_DESC(__NR_getsockname, SyS_getsockname)
EBPF_SYSCALL_DESC(__NR_getpeername, SyS_getpeername)
EBPF_SYSCALL_DESC(__NR_sendto, SyS_sendto)
/* EBPF_SYSCALL_DESC(__NR_send, SyS_send) */
EBPF_SYSCALL_DESC(__NR_recvfrom, SyS_recvfrom)
/* EBPF_SYSCALL_DESC(__NR_recv, SyS_recv) */
EBPF_SYSCALL_DESC(__NR_setsockopt, SyS_setsockopt)
EBPF_SYSCALL_DESC(__NR_getsockopt, SyS_getsockopt)
EBPF_SYSCALL_DESC(__NR_shutdown, SyS_shutdown)
EBPF_SYSCALL_DESC(__NR_sendmsg, SyS_sendmsg)
EBPF_SYSCALL_DESC(__NR_sendmmsg, SyS_sendmmsg)
EBPF_SYSCALL_DESC(__NR_recvmsg, SyS_recvmsg)
EBPF_SYSCALL_DESC(__NR_recvmmsg, SyS_recvmmsg)
/* EBPF_SYSCALL(__NR_socketcall, SyS_socketcall) */
};
