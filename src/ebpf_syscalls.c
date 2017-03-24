/*
 * Copyright 2016-2017, Intel Corporation
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
#include "syscalls_unknown.h"

/* array of syscall names */
char *syscall_names[SC_TBL_SIZE] = {
	[0 ... SC_TBL_SIZE - 1] = "?",
#define __SYSCALL_64(nr, name, ptregs)	[nr] = #name,
#include "gen_syscalls_64_mod.h"
#undef __SYSCALL_64
};

#define EBPF_SYSCALL(nr, sym, aq)    [nr] = {\
	.num = nr, \
	.handler_name = #sym, \
	.args_qty = aq, \
	.masks = 0 }

#define EBPF_SYSCALL_FLAGS(nr, sym, flags, aq)    [nr] = {\
	.num = nr, \
	.handler_name = #sym, \
	.args_qty = aq, \
	.masks = flags }

#define EBPF_SYSCALL_FILE(nr, sym, aq)    [nr] = {\
	.num = nr, \
	.handler_name = #sym, \
	.args_qty = aq, \
	.masks = EM_file }

#define EBPF_SYSCALL_FILEAT(nr, sym, aq)    [nr] = {\
	.num = nr, \
	.handler_name = #sym, \
	.args_qty = aq, \
	.masks = EM_fileat }

#define EBPF_SYSCALL_DESC(nr, sym, aq)    [nr] = {\
	.num = nr, \
	.handler_name = #sym, \
	.args_qty = aq, \
	.masks = EM_desc }

#define EBPF_SYSCALL_RPID(nr, sym, aq)    [nr] = {\
	.num = nr, \
	.handler_name = #sym, \
	.args_qty = aq, \
	.masks = EM_rpid }

#define SC_EMPTY {\
	.num = SC_TBL_SIZE, \
	.num_str = "NA", \
	.handler_name = NULL }

/* table of syscalls */
struct syscall_descriptor Syscall_array[SC_TBL_SIZE] = {
	[0 ... SC_TBL_SIZE - 1] = SC_EMPTY,

	EBPF_SYSCALL(__NR_arch_prctl, SyS_arch_prctl, 6),
	EBPF_SYSCALL(__NR_rt_sigreturn, SyS_rt_sigreturn, 6),
	EBPF_SYSCALL(__NR_ioperm, SyS_ioperm, 6),
	EBPF_SYSCALL(__NR_iopl, SyS_iopl, 6),
	EBPF_SYSCALL(__NR_modify_ldt, SyS_modify_ldt, 6),
	EBPF_SYSCALL_DESC(__NR_mmap, SyS_mmap, 6),
	EBPF_SYSCALL(__NR_set_thread_area, SyS_set_thread_area, 6),
	EBPF_SYSCALL(__NR_get_thread_area, SyS_get_thread_area, 6),
	EBPF_SYSCALL(__NR_set_tid_address, SyS_set_tid_address, 6),
	EBPF_SYSCALL_RPID(__NR_fork, SyS_fork, 0),
	EBPF_SYSCALL_RPID(__NR_vfork, SyS_vfork, 0),
	EBPF_SYSCALL_RPID(__NR_clone, SyS_clone, 6),
	EBPF_SYSCALL(__NR_unshare, SyS_unshare, 6),
	EBPF_SYSCALL(__NR_personality, SyS_personality, 6),
	EBPF_SYSCALL(__NR_exit, SyS_exit, 6),
	EBPF_SYSCALL(__NR_exit_group, SyS_exit_group, 6),
	EBPF_SYSCALL(__NR_waitid, SyS_waitid, 6),
	EBPF_SYSCALL(__NR_wait4, SyS_wait4, 6),
	EBPF_SYSCALL(__NR_waitpid, SyS_waitpid, 6),
	EBPF_SYSCALL(__NR__sysctl, SyS_sysctl, 6),
	EBPF_SYSCALL(__NR_capget, SyS_capget, 6),
	EBPF_SYSCALL(__NR_capset, SyS_capset, 6),
	EBPF_SYSCALL(__NR_ptrace, SyS_ptrace, 6),
	EBPF_SYSCALL(__NR_restart_syscall, SyS_restart_syscall, 6),
	EBPF_SYSCALL(__NR_rt_sigprocmask, SyS_rt_sigprocmask, 6),
	EBPF_SYSCALL(__NR_rt_sigpending, SyS_rt_sigpending, 6),
	EBPF_SYSCALL(__NR_rt_sigtimedwait, SyS_rt_sigtimedwait, 6),
	EBPF_SYSCALL(__NR_kill, SyS_kill, 6),
	EBPF_SYSCALL(__NR_tgkill, SyS_tgkill, 6),
	EBPF_SYSCALL(__NR_tkill, SyS_tkill, 6),
	EBPF_SYSCALL(__NR_rt_sigqueueinfo, SyS_rt_sigqueueinfo, 6),
	EBPF_SYSCALL(__NR_rt_tgsigqueueinfo, SyS_rt_tgsigqueueinfo, 6),
	EBPF_SYSCALL(__NR_sigaltstack, SyS_sigaltstack, 6),
	EBPF_SYSCALL(__NR_sigpending, SyS_sigpending, 6),
	EBPF_SYSCALL(__NR_sigprocmask, SyS_sigprocmask, 6),
	EBPF_SYSCALL(__NR_rt_sigaction, SyS_rt_sigaction, 6),
	EBPF_SYSCALL(__NR_sgetmask, SyS_sgetmask, 6),
	EBPF_SYSCALL(__NR_ssetmask, SyS_ssetmask, 6),
	EBPF_SYSCALL(__NR_signal, SyS_signal, 6),
	EBPF_SYSCALL(__NR_pause, SyS_pause, 6),
	EBPF_SYSCALL(__NR_rt_sigsuspend, SyS_rt_sigsuspend, 6),
	EBPF_SYSCALL(__NR_sigsuspend, SyS_sigsuspend, 6),
	EBPF_SYSCALL(__NR_setpriority, SyS_setpriority, 6),
	EBPF_SYSCALL(__NR_getpriority, SyS_getpriority, 6),
	EBPF_SYSCALL(__NR_setregid, SyS_setregid, 6),
	EBPF_SYSCALL(__NR_setgid, SyS_setgid, 6),
	EBPF_SYSCALL(__NR_setreuid, SyS_setreuid, 6),
	EBPF_SYSCALL(__NR_setuid, SyS_setuid, 6),
	EBPF_SYSCALL(__NR_setresuid, SyS_setresuid, 6),
	EBPF_SYSCALL(__NR_getresuid, SyS_getresuid, 6),
	EBPF_SYSCALL(__NR_setresgid, SyS_setresgid, 6),
	EBPF_SYSCALL(__NR_getresgid, SyS_getresgid, 6),
	EBPF_SYSCALL(__NR_setfsuid, SyS_setfsuid, 6),
	EBPF_SYSCALL(__NR_setfsgid, SyS_setfsgid, 6),
	EBPF_SYSCALL(__NR_getpid, SyS_getpid, 6),
	EBPF_SYSCALL(__NR_gettid, SyS_gettid, 6),
	EBPF_SYSCALL(__NR_getppid, SyS_getppid, 6),
	EBPF_SYSCALL(__NR_getuid, SyS_getuid, 6),
	EBPF_SYSCALL(__NR_geteuid, SyS_geteuid, 6),
	EBPF_SYSCALL(__NR_getgid, SyS_getgid, 6),
	EBPF_SYSCALL(__NR_getegid, SyS_getegid, 6),
	EBPF_SYSCALL(__NR_times, SyS_times, 6),
	EBPF_SYSCALL(__NR_setpgid, SyS_setpgid, 6),
	EBPF_SYSCALL(__NR_getpgid, SyS_getpgid, 6),
	EBPF_SYSCALL(__NR_getpgrp, SyS_getpgrp, 6),
	EBPF_SYSCALL(__NR_getsid, SyS_getsid, 6),
	EBPF_SYSCALL(__NR_setsid, SyS_setsid, 6),
	EBPF_SYSCALL(__NR_olduname, SyS_olduname, 1),
	EBPF_SYSCALL(__NR_uname, SyS_uname, 1),
	EBPF_SYSCALL(__NR_newuname, SyS_newuname, 1),
	EBPF_SYSCALL(__NR_sethostname, SyS_sethostname, 6),
	EBPF_SYSCALL(__NR_gethostname, SyS_gethostname, 6),
	EBPF_SYSCALL(__NR_setdomainname, SyS_setdomainname, 6),
	EBPF_SYSCALL(__NR_old_getrlimit, SyS_old_getrlimit, 6),
	EBPF_SYSCALL(__NR_getrlimit, SyS_getrlimit, 6),
	EBPF_SYSCALL(__NR_prlimit64, SyS_prlimit64, 6),
	EBPF_SYSCALL(__NR_setrlimit, SyS_setrlimit, 6),
	EBPF_SYSCALL(__NR_getrusage, SyS_getrusage, 6),
	EBPF_SYSCALL(__NR_umask, SyS_umask, 6),
	EBPF_SYSCALL(__NR_prctl, SyS_prctl, 6),
	EBPF_SYSCALL(__NR_getcpu, SyS_getcpu, 6),
	EBPF_SYSCALL(__NR_sysinfo, SyS_sysinfo, 6),
	EBPF_SYSCALL(__NR_ni_syscall, SyS_ni_syscall, 6),
	EBPF_SYSCALL(__NR_setns, SyS_setns, 6),
	EBPF_SYSCALL(__NR_reboot, SyS_reboot, 6),
	EBPF_SYSCALL(__NR_getgroups, SyS_getgroups, 6),
	EBPF_SYSCALL(__NR_setgroups, SyS_setgroups, 6),
	EBPF_SYSCALL(__NR_nice, SyS_nice, 6),
	EBPF_SYSCALL(__NR_sched_setscheduler, SyS_sched_setscheduler, 6),
	EBPF_SYSCALL(__NR_sched_setparam, SyS_sched_setparam, 6),
	EBPF_SYSCALL(__NR_sched_setattr, SyS_sched_setattr, 6),
	EBPF_SYSCALL(__NR_sched_getscheduler, SyS_sched_getscheduler, 6),
	EBPF_SYSCALL(__NR_sched_getparam, SyS_sched_getparam, 6),
	EBPF_SYSCALL(__NR_sched_getattr, SyS_sched_getattr, 6),
	EBPF_SYSCALL(__NR_sched_setaffinity, SyS_sched_setaffinity, 6),
	EBPF_SYSCALL(__NR_sched_getaffinity, SyS_sched_getaffinity, 6),
	EBPF_SYSCALL(__NR_sched_yield, SyS_sched_yield, 6),
	EBPF_SYSCALL(__NR_sched_get_priority_max,
			SyS_sched_get_priority_max, 6),
	EBPF_SYSCALL(__NR_sched_get_priority_min,
			SyS_sched_get_priority_min, 6),
	EBPF_SYSCALL(__NR_sched_rr_get_interval, SyS_sched_rr_get_interval, 6),
	EBPF_SYSCALL(__NR_syslog, SyS_syslog, 6),
	EBPF_SYSCALL(__NR_kcmp, SyS_kcmp, 6),
	EBPF_SYSCALL(__NR_time, SyS_time, 6),
	EBPF_SYSCALL(__NR_stime, SyS_stime, 6),
	EBPF_SYSCALL(__NR_gettimeofday, SyS_gettimeofday, 6),
	EBPF_SYSCALL(__NR_settimeofday, SyS_settimeofday, 6),
	EBPF_SYSCALL(__NR_adjtimex, SyS_adjtimex, 6),
	EBPF_SYSCALL(__NR_alarm, SyS_alarm, 6),
	EBPF_SYSCALL(__NR_nanosleep, SyS_nanosleep, 6),
	EBPF_SYSCALL(__NR_getitimer, SyS_getitimer, 6),
	EBPF_SYSCALL(__NR_setitimer, SyS_setitimer, 6),
	EBPF_SYSCALL(__NR_timer_create, SyS_timer_create, 6),
	EBPF_SYSCALL(__NR_timer_gettime, SyS_timer_gettime, 6),
	EBPF_SYSCALL(__NR_timer_getoverrun, SyS_timer_getoverrun, 6),
	EBPF_SYSCALL(__NR_timer_settime, SyS_timer_settime, 6),
	EBPF_SYSCALL(__NR_timer_delete, SyS_timer_delete, 6),
	EBPF_SYSCALL(__NR_clock_settime, SyS_clock_settime, 6),
	EBPF_SYSCALL(__NR_clock_gettime, SyS_clock_gettime, 6),
	EBPF_SYSCALL(__NR_clock_adjtime, SyS_clock_adjtime, 6),
	EBPF_SYSCALL(__NR_clock_getres, SyS_clock_getres, 6),
	EBPF_SYSCALL(__NR_clock_nanosleep, SyS_clock_nanosleep, 6),
	EBPF_SYSCALL(__NR_set_robust_list, SyS_set_robust_list, 6),
	EBPF_SYSCALL(__NR_get_robust_list, SyS_get_robust_list, 6),
	EBPF_SYSCALL(__NR_futex, SyS_futex, 6),
	EBPF_SYSCALL(__NR_chown16, SyS_chown16, 6),
	EBPF_SYSCALL(__NR_lchown16, SyS_lchown16, 6),
	EBPF_SYSCALL(__NR_fchown16, SyS_fchown16, 6),
	EBPF_SYSCALL(__NR_setregid16, SyS_setregid16, 6),
	EBPF_SYSCALL(__NR_setgid16, SyS_setgid16, 6),
	EBPF_SYSCALL(__NR_setreuid16, SyS_setreuid16, 6),
	EBPF_SYSCALL(__NR_setuid16, SyS_setuid16, 6),
	EBPF_SYSCALL(__NR_setresuid16, SyS_setresuid16, 6),
	EBPF_SYSCALL(__NR_getresuid16, SyS_getresuid16, 6),
	EBPF_SYSCALL(__NR_setresgid16, SyS_setresgid16, 6),
	EBPF_SYSCALL(__NR_getresgid16, SyS_getresgid16, 6),
	EBPF_SYSCALL(__NR_setfsuid16, SyS_setfsuid16, 6),
	EBPF_SYSCALL(__NR_setfsgid16, SyS_setfsgid16, 6),
	EBPF_SYSCALL(__NR_getgroups16, SyS_getgroups16, 6),
	EBPF_SYSCALL(__NR_setgroups16, SyS_setgroups16, 6),
	EBPF_SYSCALL(__NR_getuid16, SyS_getuid16, 6),
	EBPF_SYSCALL(__NR_geteuid16, SyS_geteuid16, 6),
	EBPF_SYSCALL(__NR_getgid16, SyS_getgid16, 6),
	EBPF_SYSCALL(__NR_getegid16, SyS_getegid16, 6),
	EBPF_SYSCALL_FILE(__NR_delete_module, SyS_delete_module, 6),
	EBPF_SYSCALL(__NR_init_module, SyS_init_module, 6),
	EBPF_SYSCALL_DESC(__NR_finit_module, SyS_finit_module, 6),
	EBPF_SYSCALL_FILE(__NR_acct, SyS_acct, 6),
	EBPF_SYSCALL(__NR_kexec_load, SyS_kexec_load, 6),
	EBPF_SYSCALL_DESC(__NR_kexec_file_load, SyS_kexec_file_load, 6),
	EBPF_SYSCALL(__NR_seccomp, SyS_seccomp, 6),
	EBPF_SYSCALL(__NR_bpf, SyS_bpf, 6),
	EBPF_SYSCALL(__NR_membarrier, SyS_membarrier, 6),
	EBPF_SYSCALL_DESC(__NR_readahead, SyS_readahead, 6),
	EBPF_SYSCALL_FILE(__NR_memfd_create, SyS_memfd_create, 6),
	EBPF_SYSCALL(__NR_mincore, SyS_mincore, 6),
	EBPF_SYSCALL(__NR_mlock, SyS_mlock, 6),
	EBPF_SYSCALL(__NR_mlock2, SyS_mlock2, 6),
	EBPF_SYSCALL(__NR_munlock, SyS_munlock, 6),
	EBPF_SYSCALL(__NR_mlockall, SyS_mlockall, 6),
	EBPF_SYSCALL(__NR_munlockall, SyS_munlockall, 6),
	EBPF_SYSCALL(__NR_mmap_pgoff, SyS_mmap_pgoff, 6),
	EBPF_SYSCALL(__NR_brk, SyS_brk, 6),
	EBPF_SYSCALL(__NR_munmap, SyS_munmap, 6),
	EBPF_SYSCALL(__NR_remap_file_pages, SyS_remap_file_pages, 6),
	EBPF_SYSCALL(__NR_mprotect, SyS_mprotect, 6),
	EBPF_SYSCALL(__NR_mremap, SyS_mremap, 6),
	EBPF_SYSCALL(__NR_msync, SyS_msync, 6),
	EBPF_SYSCALL(__NR_process_vm_readv, SyS_process_vm_readv, 6),
	EBPF_SYSCALL(__NR_process_vm_writev, SyS_process_vm_writev, 6),
	EBPF_SYSCALL_DESC(__NR_fadvise64_64, SyS_fadvise64_64, 6),
	EBPF_SYSCALL_DESC(__NR_fadvise64, SyS_fadvise64, 6),
	EBPF_SYSCALL(__NR_madvise, SyS_madvise, 6),
	EBPF_SYSCALL_FILE(__NR_swapoff, SyS_swapoff, 6),
	EBPF_SYSCALL_FILE(__NR_swapon, SyS_swapon, 6),
	EBPF_SYSCALL(__NR_set_mempolicy, SyS_set_mempolicy, 6),
	EBPF_SYSCALL(__NR_migrate_pages, SyS_migrate_pages, 6),
	EBPF_SYSCALL(__NR_get_mempolicy, SyS_get_mempolicy, 6),
	EBPF_SYSCALL(__NR_mbind, SyS_mbind, 6),
	EBPF_SYSCALL(__NR_move_pages, SyS_move_pages, 6),
	EBPF_SYSCALL_DESC(__NR_close, SyS_close, 1),
	EBPF_SYSCALL_FILE(__NR_truncate, SyS_truncate, 6),
	EBPF_SYSCALL_DESC(__NR_ftruncate, SyS_ftruncate, 6),
	EBPF_SYSCALL_DESC(__NR_fallocate, SyS_fallocate, 6),
	EBPF_SYSCALL_FILEAT(__NR_faccessat, SyS_faccessat, 6),
	EBPF_SYSCALL_FILE(__NR_access, SyS_access, 6),
	EBPF_SYSCALL_FILE(__NR_chdir, SyS_chdir, 6),
	EBPF_SYSCALL_DESC(__NR_fchdir, SyS_fchdir, 6),
	EBPF_SYSCALL_FILE(__NR_chroot, SyS_chroot, 6),
	EBPF_SYSCALL_DESC(__NR_fchmod, SyS_fchmod, 6),
	EBPF_SYSCALL_FILEAT(__NR_fchmodat, SyS_fchmodat, 6),
	EBPF_SYSCALL_FILE(__NR_chmod, SyS_chmod, 6),
	EBPF_SYSCALL_FILEAT(__NR_fchownat, SyS_fchownat, 6),
	EBPF_SYSCALL_FILE(__NR_chown, SyS_chown, 6),
	EBPF_SYSCALL_FILE(__NR_lchown, SyS_lchown, 6),
	EBPF_SYSCALL_DESC(__NR_fchown, SyS_fchown, 6),
	EBPF_SYSCALL_FILE(__NR_open, SyS_open, 6),
	EBPF_SYSCALL_FILEAT(__NR_openat, SyS_openat, 6),
	EBPF_SYSCALL_FILE(__NR_creat, SyS_creat, 6),
	EBPF_SYSCALL(__NR_vhangup, SyS_vhangup, 6),
	EBPF_SYSCALL_DESC(__NR_lseek, SyS_lseek, 6),
	EBPF_SYSCALL_DESC(__NR_llseek, SyS_llseek, 6),
	EBPF_SYSCALL_DESC(__NR_read, SyS_read, 6),
	EBPF_SYSCALL_DESC(__NR_write, SyS_write, 6),
	EBPF_SYSCALL_DESC(__NR_pread64, SyS_pread64, 6),
	EBPF_SYSCALL_DESC(__NR_pwrite64, SyS_pwrite64, 6),
	EBPF_SYSCALL_DESC(__NR_readv, SyS_readv, 6),
	EBPF_SYSCALL_DESC(__NR_writev, SyS_writev, 6),
	EBPF_SYSCALL_DESC(__NR_preadv, SyS_preadv, 6),
	EBPF_SYSCALL_DESC(__NR_pwritev, SyS_pwritev, 6),
	EBPF_SYSCALL_DESC(__NR_sendfile, SyS_sendfile, 6),
	EBPF_SYSCALL_DESC(__NR_sendfile64, SyS_sendfile64, 6),
	EBPF_SYSCALL_FILE(__NR_stat, SyS_stat, 6),
	EBPF_SYSCALL_FILE(__NR_lstat, SyS_lstat, 6),
	EBPF_SYSCALL_DESC(__NR_fstat, SyS_fstat, 2),
	EBPF_SYSCALL_FILE(__NR_newstat, SyS_newstat, 6),
	EBPF_SYSCALL_FILE(__NR_newlstat, SyS_newlstat, 6),
	EBPF_SYSCALL_DESC(__NR_newfstatat, SyS_newfstatat, 6),
	EBPF_SYSCALL_DESC(__NR_newfstat, SyS_newfstat, 2),
	EBPF_SYSCALL_FILEAT(__NR_readlinkat, SyS_readlinkat, 6),
	EBPF_SYSCALL_FILE(__NR_readlink, SyS_readlink, 6),
	EBPF_SYSCALL_FILE(__NR_uselib, SyS_uselib, 6),
	EBPF_SYSCALL_FILE(__NR_execve, SyS_execve, 3),
	EBPF_SYSCALL_FILEAT(__NR_execveat, SyS_execveat, 5),
	EBPF_SYSCALL(__NR_pipe2, SyS_pipe2, 6),
	EBPF_SYSCALL(__NR_pipe, SyS_pipe, 6),
	EBPF_SYSCALL_FILEAT(__NR_mknodat, SyS_mknodat, 6),
	EBPF_SYSCALL_FILE(__NR_mknod, SyS_mknod, 6),
	EBPF_SYSCALL_FILEAT(__NR_mkdirat, SyS_mkdirat, 6),
	EBPF_SYSCALL_FILE(__NR_mkdir, SyS_mkdir, 6),
	EBPF_SYSCALL_FILE(__NR_rmdir, SyS_rmdir, 6),
	EBPF_SYSCALL_FILEAT(__NR_unlinkat, SyS_unlinkat, 6),
	EBPF_SYSCALL_FILE(__NR_unlink, SyS_unlink, 6),
	EBPF_SYSCALL_FLAGS(__NR_symlinkat, SyS_symlinkat,
			EM_fs_path_1_3_arg, 6),
	EBPF_SYSCALL_FLAGS(__NR_symlink, SyS_symlink, EM_fs_path_1_2_arg, 6),
	EBPF_SYSCALL_FLAGS(__NR_linkat, SyS_linkat, EM_fs_path_2_4_arg, 6),
	EBPF_SYSCALL_FLAGS(__NR_link, SyS_link, EM_fs_path_1_2_arg, 6),
	EBPF_SYSCALL_FLAGS(__NR_renameat2, SyS_renameat2,
			EM_fs_path_2_4_arg, 6),
	EBPF_SYSCALL_FLAGS(__NR_renameat, SyS_renameat, EM_fs_path_2_4_arg, 6),
	EBPF_SYSCALL_FLAGS(__NR_rename, SyS_rename, EM_fs_path_1_2_arg, 6),
	EBPF_SYSCALL_DESC(__NR_fcntl, SyS_fcntl, 6),
	EBPF_SYSCALL_DESC(__NR_ioctl, SyS_ioctl, 6),
	EBPF_SYSCALL_DESC(__NR_old_readdir, SyS_old_readdir, 6),
	EBPF_SYSCALL_DESC(__NR_getdents, SyS_getdents, 6),
	EBPF_SYSCALL_DESC(__NR_getdents64, SyS_getdents64, 6),
	EBPF_SYSCALL(__NR_select, SyS_select, 6),
	EBPF_SYSCALL(__NR_pselect6, SyS_pselect6, 6),
	EBPF_SYSCALL(__NR_poll, SyS_poll, 6),
	EBPF_SYSCALL(__NR_ppoll, SyS_ppoll, 6),
	EBPF_SYSCALL(__NR_getcwd, SyS_getcwd, 6),
	EBPF_SYSCALL_DESC(__NR_dup3, SyS_dup3, 6),
	EBPF_SYSCALL_DESC(__NR_dup2, SyS_dup2, 6),
	EBPF_SYSCALL_DESC(__NR_dup, SyS_dup, 6),
	EBPF_SYSCALL(__NR_sysfs, SyS_sysfs, 6),
	EBPF_SYSCALL_FILE(__NR_umount, SyS_umount, 6),
	EBPF_SYSCALL_FILE(__NR_oldumount, SyS_oldumount, 6),
	EBPF_SYSCALL_FLAGS(__NR_mount, SyS_mount, EM_fs_path_1_2_arg, 6),
	EBPF_SYSCALL_FLAGS(__NR_pivot_root, SyS_pivot_root,
				EM_fs_path_1_2_arg, 6),
	EBPF_SYSCALL_FLAGS(__NR_setxattr, SyS_setxattr,
				EM_fs_path_1_2_arg, 6),
	EBPF_SYSCALL_FLAGS(__NR_lsetxattr, SyS_lsetxattr,
				EM_fs_path_1_2_arg, 6),
	EBPF_SYSCALL_FILEAT(__NR_fsetxattr, SyS_fsetxattr, 6),
	EBPF_SYSCALL_FLAGS(__NR_getxattr, SyS_getxattr,
				EM_fs_path_1_2_arg, 6),
	EBPF_SYSCALL_FLAGS(__NR_lgetxattr, SyS_lgetxattr,
				EM_fs_path_1_2_arg, 6),
	EBPF_SYSCALL_FILEAT(__NR_fgetxattr, SyS_fgetxattr, 6),
	EBPF_SYSCALL_FLAGS(__NR_listxattr, SyS_listxattr,
				EM_fs_path_1_2_arg, 6),
	EBPF_SYSCALL_FLAGS(__NR_llistxattr, SyS_llistxattr,
				EM_fs_path_1_2_arg, 6),
	EBPF_SYSCALL_FILEAT(__NR_flistxattr, SyS_flistxattr, 6),
	EBPF_SYSCALL_FLAGS(__NR_removexattr, SyS_removexattr,
				EM_fs_path_1_2_arg, 6),
	EBPF_SYSCALL_FLAGS(__NR_lremovexattr, SyS_lremovexattr,
				EM_fs_path_1_2_arg, 6),
	EBPF_SYSCALL_FILEAT(__NR_fremovexattr, SyS_fremovexattr, 6),
	EBPF_SYSCALL_DESC(__NR_vmsplice, SyS_vmsplice, 6),
	EBPF_SYSCALL_DESC(__NR_splice, SyS_splice, 6),
	EBPF_SYSCALL_DESC(__NR_tee, SyS_tee, 6),
	EBPF_SYSCALL(__NR_sync, SyS_sync, 6),
	EBPF_SYSCALL_DESC(__NR_syncfs, SyS_syncfs, 6),
	EBPF_SYSCALL_DESC(__NR_fsync, SyS_fsync, 6),
	EBPF_SYSCALL_DESC(__NR_fdatasync, SyS_fdatasync, 6),
	EBPF_SYSCALL_DESC(__NR_sync_file_range, SyS_sync_file_range, 6),
	EBPF_SYSCALL_DESC(__NR_sync_file_range2, SyS_sync_file_range2, 6),
	EBPF_SYSCALL_FILE(__NR_utime, SyS_utime, 6),
	EBPF_SYSCALL_FILEAT(__NR_utimensat, SyS_utimensat, 6),
	EBPF_SYSCALL_FILEAT(__NR_futimesat, SyS_futimesat, 6),
	EBPF_SYSCALL_FILE(__NR_utimes, SyS_utimes, 6),
	EBPF_SYSCALL_FILE(__NR_statfs, SyS_statfs, 6),
	EBPF_SYSCALL_FILE(__NR_statfs64, SyS_statfs64, 6),
	EBPF_SYSCALL_DESC(__NR_fstatfs, SyS_fstatfs, 6),
	EBPF_SYSCALL_DESC(__NR_fstatfs64, SyS_fstatfs64, 6),
	EBPF_SYSCALL(__NR_ustat, SyS_ustat, 6),
	EBPF_SYSCALL(__NR_bdflush, SyS_bdflush, 6),
	EBPF_SYSCALL(__NR_inotify_init1, SyS_inotify_init1, 6),
	EBPF_SYSCALL(__NR_inotify_init, SyS_inotify_init, 6),
	EBPF_SYSCALL_DESC(__NR_inotify_add_watch, SyS_inotify_add_watch, 6),
	EBPF_SYSCALL_DESC(__NR_inotify_rm_watch, SyS_inotify_rm_watch, 6),
	EBPF_SYSCALL(__NR_fanotify_init, SyS_fanotify_init, 6),
	EBPF_SYSCALL_DESC(__NR_fanotify_mark, SyS_fanotify_mark, 6),
	EBPF_SYSCALL(__NR_epoll_create1, SyS_epoll_create1, 6),
	EBPF_SYSCALL(__NR_epoll_create, SyS_epoll_create, 6),
	EBPF_SYSCALL_DESC(__NR_epoll_ctl, SyS_epoll_ctl, 6),
	EBPF_SYSCALL_DESC(__NR_epoll_wait, SyS_epoll_wait, 6),
	EBPF_SYSCALL_DESC(__NR_epoll_pwait, SyS_epoll_pwait, 6),
	EBPF_SYSCALL_DESC(__NR_signalfd4, SyS_signalfd4, 6),
	EBPF_SYSCALL_DESC(__NR_signalfd, SyS_signalfd, 6),
	EBPF_SYSCALL(__NR_timerfd_create, SyS_timerfd_create, 6),
	EBPF_SYSCALL_DESC(__NR_timerfd_settime, SyS_timerfd_settime, 6),
	EBPF_SYSCALL_DESC(__NR_timerfd_gettime, SyS_timerfd_gettime, 6),
	EBPF_SYSCALL(__NR_eventfd2, SyS_eventfd2, 6),
	EBPF_SYSCALL(__NR_eventfd, SyS_eventfd, 6),
	EBPF_SYSCALL(__NR_userfaultfd, SyS_userfaultfd, 6),
	EBPF_SYSCALL(__NR_io_setup, SyS_io_setup, 6),
	EBPF_SYSCALL(__NR_io_destroy, SyS_io_destroy, 6),
	EBPF_SYSCALL(__NR_io_submit, SyS_io_submit, 6),
	EBPF_SYSCALL(__NR_io_cancel, SyS_io_cancel, 6),
	EBPF_SYSCALL(__NR_io_getevents, SyS_io_getevents, 6),
	EBPF_SYSCALL_DESC(__NR_flock, SyS_flock, 6),
	EBPF_SYSCALL_FILEAT(__NR_name_to_handle_at, SyS_name_to_handle_at, 6),
	EBPF_SYSCALL_DESC(__NR_open_by_handle_at, SyS_open_by_handle_at, 6),
	EBPF_SYSCALL(__NR_quotactl, SyS_quotactl, 6),
	EBPF_SYSCALL(__NR_lookup_dcookie, SyS_lookup_dcookie, 6),
	EBPF_SYSCALL(__NR_msgget, SyS_msgget, 6),
	EBPF_SYSCALL(__NR_msgctl, SyS_msgctl, 6),
	EBPF_SYSCALL(__NR_msgsnd, SyS_msgsnd, 6),
	EBPF_SYSCALL(__NR_msgrcv, SyS_msgrcv, 6),
	EBPF_SYSCALL(__NR_semget, SyS_semget, 6),
	EBPF_SYSCALL(__NR_semctl, SyS_semctl, 6),
	EBPF_SYSCALL(__NR_semtimedop, SyS_semtimedop, 6),
	EBPF_SYSCALL(__NR_semop, SyS_semop, 6),
	EBPF_SYSCALL(__NR_shmget, SyS_shmget, 6),
	EBPF_SYSCALL(__NR_shmctl, SyS_shmctl, 6),
	EBPF_SYSCALL(__NR_shmat, SyS_shmat, 6),
	EBPF_SYSCALL(__NR_shmdt, SyS_shmdt, 6),
	EBPF_SYSCALL_FILE(__NR_mq_open, SyS_mq_open, 6),
	EBPF_SYSCALL_FILE(__NR_mq_unlink, SyS_mq_unlink, 6),
	EBPF_SYSCALL(__NR_mq_timedsend, SyS_mq_timedsend, 6),
	EBPF_SYSCALL(__NR_mq_timedreceive, SyS_mq_timedreceive, 6),
	EBPF_SYSCALL(__NR_mq_notify, SyS_mq_notify, 6),
	EBPF_SYSCALL(__NR_mq_getsetattr, SyS_mq_getsetattr, 6),
	EBPF_SYSCALL(__NR_add_key, SyS_add_key, 6),
	EBPF_SYSCALL(__NR_request_key, SyS_request_key, 6),
	EBPF_SYSCALL(__NR_keyctl, SyS_keyctl, 6),
	EBPF_SYSCALL(__NR_ioprio_set, SyS_ioprio_set, 6),
	EBPF_SYSCALL(__NR_ioprio_get, SyS_ioprio_get, 6),
	EBPF_SYSCALL(__NR_size_show, SyS_size_show, 6),
	EBPF_SYSCALL(__NR_getrandom, SyS_getrandom, 6),
	EBPF_SYSCALL(__NR_dmi_field_show, SyS_dmi_field_show, 6),
	EBPF_SYSCALL(__NR_dmi_modalias_show, SyS_dmi_modalias_show, 6),
	EBPF_SYSCALL(__NR_socket, SyS_socket, 6),
	EBPF_SYSCALL(__NR_socketpair, SyS_socketpair, 6),
	EBPF_SYSCALL_DESC(__NR_bind, SyS_bind, 6),
	EBPF_SYSCALL_DESC(__NR_listen, SyS_listen, 6),
	EBPF_SYSCALL_DESC(__NR_accept4, SyS_accept4, 6),
	EBPF_SYSCALL_DESC(__NR_accept, SyS_accept, 6),
	EBPF_SYSCALL_DESC(__NR_connect, SyS_connect, 6),
	EBPF_SYSCALL_DESC(__NR_getsockname, SyS_getsockname, 6),
	EBPF_SYSCALL_DESC(__NR_getpeername, SyS_getpeername, 6),
	EBPF_SYSCALL_DESC(__NR_sendto, SyS_sendto, 6),
	EBPF_SYSCALL_DESC(__NR_send, SyS_send, 6),
	EBPF_SYSCALL_DESC(__NR_recvfrom, SyS_recvfrom, 6),
	EBPF_SYSCALL_DESC(__NR_recv, SyS_recv, 6),
	EBPF_SYSCALL_DESC(__NR_setsockopt, SyS_setsockopt, 6),
	EBPF_SYSCALL_DESC(__NR_getsockopt, SyS_getsockopt, 6),
	EBPF_SYSCALL_DESC(__NR_shutdown, SyS_shutdown, 6),
	EBPF_SYSCALL_DESC(__NR_sendmsg, SyS_sendmsg, 6),
	EBPF_SYSCALL_DESC(__NR_sendmmsg, SyS_sendmmsg, 6),
	EBPF_SYSCALL_DESC(__NR_recvmsg, SyS_recvmsg, 6),
	EBPF_SYSCALL_DESC(__NR_recvmmsg, SyS_recvmmsg, 6),
	EBPF_SYSCALL(__NR_socketcall, SyS_socketcall, 6),

	EBPF_SYSCALL(__NR_pkey_mprotect, SyS_pkey_mprotect, 6),
	EBPF_SYSCALL(__NR_pkey_alloc, SyS_pkey_alloc, 6),
	EBPF_SYSCALL(__NR_pkey_free, SyS_pkey_free, 6),
	EBPF_SYSCALL(__NR_preadv2, SyS_preadv2, 6),
	EBPF_SYSCALL(__NR_pwritev2, SyS_pwritev2, 6),
	EBPF_SYSCALL(__NR_copy_file_range, SyS_copy_file_range, 6),
	EBPF_SYSCALL(__NR_fillrect, SyS_fillrect, 6),
	EBPF_SYSCALL(__NR_copyarea, SyS_copyarea, 6),
	EBPF_SYSCALL(__NR_imageblit, SyS_imageblit, 6),

	/*
	 * Syscalls with duplicated numbers -
	 * - overwriten by the new version of syscall
	 */
	EBPF_SYSCALL(DUP__NR_uname, SyS_uname, 1),
	EBPF_SYSCALL_FILE(DUP__NR_stat, SyS_stat, 6),
	EBPF_SYSCALL_FILE(DUP__NR_lstat, SyS_lstat, 6),
	EBPF_SYSCALL_DESC(DUP__NR_fstat, SyS_fstat, 2),
	EBPF_SYSCALL_DESC(DUP__NR_sendfile, SyS_sendfile, 6),
};

/*
 * init_sc_tbl -- init the table of syscalls
 */
void
init_sc_tbl(void)
{
	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		if (NULL != Syscall_array[i].handler_name) {
			Syscall_array[i].num = i;
			sprintf(Syscall_array[i].num_str, "%u",
				Syscall_array[i].num);
		}
	}
}

/*
 * fprint_sc_tbl -- print the table of syscalls
 */
int
fprint_sc_tbl(FILE *f)
{
	int res;

	init_sc_tbl();

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		if (i == __NR_FIRST_UNKNOWN)
			fprintf(f, "\nSyscalls with unknown "
					"or duplicated number:\n");

		if (NULL != Syscall_array[i].handler_name) {
			if (i < __NR_FIRST_UNKNOWN) {
				res = fprintf(f, "%03d:\t%s\n",
					Syscall_array[i].num,
					Syscall_array[i].handler_name);
			} else {
				res = fprintf(f, "\t%s\n",
					Syscall_array[i].handler_name);
			}
			if (res <= 0)
				return res;
		}
	}

	fflush(f);

	return 1;
}
