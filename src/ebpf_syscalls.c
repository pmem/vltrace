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
 * ebpf_syscalls.c -- a table of known syscalls
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "syscalls_numbers.h"
#include "ebpf_syscalls.h"
#include "utils.h"
#include "config.h"

#ifdef __SYSCALL_X32
#undef __SYSCALL_X32
#endif /* __SYSCALL_X32 */

#ifdef __SYSCALL_64
#undef __SYSCALL_64
#endif /* __SYSCALL_64 */

#ifdef __SYSCALL_COMMON
#undef __SYSCALL_COMMON
#endif /* __SYSCALL_COMMON */

#define __SYSCALL_X32(nr, sysname, ptregs)	[nr] = NULL,
#define __SYSCALL_64(nr, sysname, ptregs)	[nr] = #sysname,
#define __SYSCALL_COMMON(nr, sysname, ptregs)	[nr] = #sysname,

/* array of syscall names */
char *syscall_names[SC_TBL_SIZE] = {
	[0 ... SC_TBL_SIZE - 1] = NULL,
/* fill the array with names from the generater header */
#include "syscalls_64_mod.h_gen"
};

#undef __SYSCALL_X32
#undef __SYSCALL_64
#undef __SYSCALL_COMMON

#define EBPF_SYSCALL(nr, sym, aq)    [nr] = {\
	.num = nr, \
	.handler_name = #sym, \
	.args_qty = aq, \
	.mask = 0 }

#define EBPF_SYSCALL_FLAGS(nr, sym, flags, aq)    [nr] = {\
	.num = nr, \
	.handler_name = #sym, \
	.args_qty = aq, \
	.mask = flags }

#define EBPF_SYSCALL_FILE(nr, sym, aq)    [nr] = {\
	.num = nr, \
	.handler_name = #sym, \
	.args_qty = aq, \
	.mask = EM_str_1 | EM_path_1 }

#define EBPF_SYSCALL_FILEAT(nr, sym, flags, aq)    [nr] = {\
	.num = nr, \
	.handler_name = #sym, \
	.args_qty = aq, \
	.mask = EM_fd_1 | EM_str_2 | EM_path_2 | EM_fileat | flags }

#define EBPF_SYSCALL_FILEAT2(nr, sym, flags, aq)    [nr] = {\
	.num = nr, \
	.handler_name = #sym, \
	.args_qty = aq, \
	.mask = EM_fd_1_3 | EM_str_2_4 | EM_path_2_4 | EM_fileat2 | flags }

#define EBPF_SYSCALL_DESC(nr, sym, aq)    [nr] = {\
	.num = nr, \
	.handler_name = #sym, \
	.args_qty = aq, \
	.mask = EM_fd_1 }

#define EBPF_SYSCALL_RPID(nr, sym, aq)    [nr] = {\
	.num = nr, \
	.handler_name = #sym, \
	.args_qty = aq, \
	.mask = EM_rpid }

#define SC_EMPTY {\
	.num = SC_TBL_SIZE, \
	.num_str = "NA", \
	.handler_name = NULL }

/* table of syscalls */
struct syscall_descriptor Syscall_array[SC_TBL_SIZE] = {
	[0 ... SC_TBL_SIZE - 1] = SC_EMPTY,

	EBPF_SYSCALL_DESC(__NR_read, SyS_read, 3),
	EBPF_SYSCALL_DESC(__NR_write, SyS_write, 3),
	EBPF_SYSCALL_FLAGS(__NR_open, SyS_open,
					EM_str_1 | EM_path_1 | EM_rfd, 3),
	EBPF_SYSCALL_DESC(__NR_close, SyS_close, 1),
	EBPF_SYSCALL_FILE(__NR_stat, SyS_stat, 2),
	EBPF_SYSCALL_FILE(__NR_newstat, SyS_newstat, 2),
	EBPF_SYSCALL_DESC(__NR_fstat, SyS_fstat, 2),
	EBPF_SYSCALL_DESC(__NR_newfstat, SyS_newfstat, 2),
	EBPF_SYSCALL_FILE(__NR_lstat, SyS_lstat, 2),
	EBPF_SYSCALL_FILE(__NR_newlstat, SyS_newlstat, 2),
	EBPF_SYSCALL(__NR_poll, SyS_poll, 3),
	EBPF_SYSCALL_DESC(__NR_lseek, SyS_lseek, 3),
	EBPF_SYSCALL_FLAGS(__NR_mmap, SyS_mmap, EM_fd_5, 6),
	EBPF_SYSCALL(__NR_mprotect, SyS_mprotect, 3),
	EBPF_SYSCALL(__NR_munmap, SyS_munmap, 2),
	EBPF_SYSCALL(__NR_brk, SyS_brk, 1),
	EBPF_SYSCALL(__NR_rt_sigaction, SyS_rt_sigaction, 4),
	EBPF_SYSCALL(__NR_rt_sigprocmask, SyS_rt_sigprocmask, 4),
	EBPF_SYSCALL_FLAGS(__NR_rt_sigreturn, SyS_rt_sigreturn, EM_no_ret, 6),
	EBPF_SYSCALL_DESC(__NR_ioctl, SyS_ioctl, 3),
	EBPF_SYSCALL_DESC(__NR_pread64, SyS_pread64, 4),
	EBPF_SYSCALL_DESC(__NR_pwrite64, SyS_pwrite64, 4),
	EBPF_SYSCALL_DESC(__NR_readv, SyS_readv, 3),
	EBPF_SYSCALL_DESC(__NR_writev, SyS_writev, 3),
	EBPF_SYSCALL_FILE(__NR_access, SyS_access, 2),
	EBPF_SYSCALL(__NR_pipe, SyS_pipe, 1),
	EBPF_SYSCALL(__NR_select, SyS_select, 5),
	EBPF_SYSCALL(__NR_sched_yield, SyS_sched_yield, 1),
	EBPF_SYSCALL(__NR_mremap, SyS_mremap, 5),
	EBPF_SYSCALL(__NR_msync, SyS_msync, 3),
	EBPF_SYSCALL(__NR_mincore, SyS_mincore, 3),
	EBPF_SYSCALL(__NR_madvise, SyS_madvise, 3),
	EBPF_SYSCALL(__NR_shmget, SyS_shmget, 3),
	EBPF_SYSCALL(__NR_shmat, SyS_shmat, 3),
	EBPF_SYSCALL(__NR_shmctl, SyS_shmctl, 3),
	EBPF_SYSCALL_FLAGS(__NR_dup,  SyS_dup,  EM_fd_1 | EM_rfd, 1),
	EBPF_SYSCALL_FLAGS(__NR_dup2, SyS_dup2, EM_fd_1 | EM_rfd, 2),
	EBPF_SYSCALL_FLAGS(__NR_dup3, SyS_dup3, EM_fd_1 | EM_rfd, 3),
	EBPF_SYSCALL(__NR_pause, SyS_pause, 1),
	EBPF_SYSCALL(__NR_nanosleep, SyS_nanosleep, 2),
	EBPF_SYSCALL(__NR_getitimer, SyS_getitimer, 2),
	EBPF_SYSCALL(__NR_alarm, SyS_alarm, 1),
	EBPF_SYSCALL(__NR_setitimer, SyS_setitimer, 3),
	EBPF_SYSCALL(__NR_getpid, SyS_getpid, 0),
	EBPF_SYSCALL_FLAGS(__NR_sendfile, SyS_sendfile, EM_fd_1 | EM_fd_2, 4),
	EBPF_SYSCALL_FLAGS(__NR_sendfile64, SyS_sendfile64,
				EM_fd_1 | EM_fd_2, 4),
	EBPF_SYSCALL(__NR_socket, SyS_socket, 3),
	EBPF_SYSCALL_DESC(__NR_connect, SyS_connect, 3),
	EBPF_SYSCALL_DESC(__NR_accept, SyS_accept, 3),
	EBPF_SYSCALL_DESC(__NR_sendto, SyS_sendto, 6),
	EBPF_SYSCALL_DESC(__NR_recvfrom, SyS_recvfrom, 6),
	EBPF_SYSCALL_DESC(__NR_sendmsg, SyS_sendmsg, 3),
	EBPF_SYSCALL_DESC(__NR_recvmsg, SyS_recvmsg, 3),
	EBPF_SYSCALL_DESC(__NR_shutdown, SyS_shutdown, 2),
	EBPF_SYSCALL_DESC(__NR_bind, SyS_bind, 3),
	EBPF_SYSCALL_DESC(__NR_listen, SyS_listen, 2),
	EBPF_SYSCALL_DESC(__NR_getsockname, SyS_getsockname, 3),
	EBPF_SYSCALL_DESC(__NR_getpeername, SyS_getpeername, 3),
	EBPF_SYSCALL(__NR_socketpair, SyS_socketpair, 4),
	EBPF_SYSCALL_DESC(__NR_setsockopt, SyS_setsockopt, 5),
	EBPF_SYSCALL_DESC(__NR_getsockopt, SyS_getsockopt, 5),
	EBPF_SYSCALL_RPID(__NR_clone, SyS_clone, 6),
	EBPF_SYSCALL_RPID(__NR_fork, SyS_fork, 0),
	EBPF_SYSCALL_RPID(__NR_vfork, SyS_vfork, 0),
	EBPF_SYSCALL_FILE(__NR_execve, SyS_execve, 3),
	EBPF_SYSCALL_FLAGS(__NR_exit, SyS_exit, EM_no_ret, 1),
	EBPF_SYSCALL(__NR_wait4, SyS_wait4, 4),
	EBPF_SYSCALL(__NR_kill, SyS_kill, 2),
	EBPF_SYSCALL(__NR_olduname, SyS_olduname, 1),
	EBPF_SYSCALL(__NR_uname, SyS_uname, 1),
	EBPF_SYSCALL(__NR_newuname, SyS_newuname, 1),
	EBPF_SYSCALL(__NR_semget, SyS_semget, 3),
	EBPF_SYSCALL(__NR_semop, SyS_semop, 3),
	EBPF_SYSCALL(__NR_semctl, SyS_semctl, 4),
	EBPF_SYSCALL(__NR_shmdt, SyS_shmdt, 1),
	EBPF_SYSCALL(__NR_msgget, SyS_msgget, 2),
	EBPF_SYSCALL(__NR_msgsnd, SyS_msgsnd, 4),
	EBPF_SYSCALL(__NR_msgrcv, SyS_msgrcv, 5),
	EBPF_SYSCALL(__NR_msgctl, SyS_msgctl, 3),
	EBPF_SYSCALL_DESC(__NR_fcntl, SyS_fcntl, 3),
	EBPF_SYSCALL_DESC(__NR_flock, SyS_flock, 2),
	EBPF_SYSCALL_DESC(__NR_fsync, SyS_fsync, 1),
	EBPF_SYSCALL_DESC(__NR_fdatasync, SyS_fdatasync, 1),
	EBPF_SYSCALL_FILE(__NR_truncate, SyS_truncate, 2),
	EBPF_SYSCALL_DESC(__NR_ftruncate, SyS_ftruncate, 2),
	EBPF_SYSCALL_DESC(__NR_getdents, SyS_getdents, 3),
	EBPF_SYSCALL(__NR_getcwd, SyS_getcwd, 2),
	EBPF_SYSCALL_FILE(__NR_chdir, SyS_chdir, 1),
	EBPF_SYSCALL_DESC(__NR_fchdir, SyS_fchdir, 1),
	EBPF_SYSCALL_FLAGS(__NR_rename, SyS_rename,
					EM_str_1_2 | EM_path_1_2, 2),
	EBPF_SYSCALL_FILE(__NR_mkdir, SyS_mkdir, 2),
	EBPF_SYSCALL_FILE(__NR_rmdir, SyS_rmdir, 1),
	EBPF_SYSCALL_FLAGS(__NR_creat, SyS_creat,
					EM_str_1 | EM_path_1 | EM_rfd, 2),
	EBPF_SYSCALL_FLAGS(__NR_link, SyS_link, EM_str_1_2 | EM_path_1_2, 2),
	EBPF_SYSCALL_FILE(__NR_unlink, SyS_unlink, 1),
	EBPF_SYSCALL_FLAGS(__NR_symlink, SyS_symlink,
					EM_str_1_2 | EM_path_1_2, 2),
	EBPF_SYSCALL_FILE(__NR_readlink, SyS_readlink, 3),
	EBPF_SYSCALL_FILE(__NR_chmod, SyS_chmod, 2),
	EBPF_SYSCALL_DESC(__NR_fchmod, SyS_fchmod, 2),
	EBPF_SYSCALL_FILE(__NR_chown, SyS_chown, 3),
	EBPF_SYSCALL_DESC(__NR_fchown, SyS_fchown, 3),
	EBPF_SYSCALL_FILE(__NR_lchown, SyS_lchown, 3),
	EBPF_SYSCALL(__NR_umask, SyS_umask, 1),
	EBPF_SYSCALL(__NR_gettimeofday, SyS_gettimeofday, 2),
	EBPF_SYSCALL(__NR_getrlimit, SyS_getrlimit, 2),
	EBPF_SYSCALL(__NR_getrusage, SyS_getrusage, 2),
	EBPF_SYSCALL(__NR_sysinfo, SyS_sysinfo, 1),
	EBPF_SYSCALL(__NR_times, SyS_times, 1),
	EBPF_SYSCALL(__NR_ptrace, SyS_ptrace, 4),
	EBPF_SYSCALL(__NR_getuid, SyS_getuid, 1),
	EBPF_SYSCALL(__NR_syslog, SyS_syslog, 3),
	EBPF_SYSCALL(__NR_getgid, SyS_getgid, 1),
	EBPF_SYSCALL(__NR_setuid, SyS_setuid, 1),
	EBPF_SYSCALL(__NR_setgid, SyS_setgid, 1),
	EBPF_SYSCALL(__NR_geteuid, SyS_geteuid, 1),
	EBPF_SYSCALL(__NR_getegid, SyS_getegid, 1),
	EBPF_SYSCALL(__NR_setpgid, SyS_setpgid, 2),
	EBPF_SYSCALL(__NR_getppid, SyS_getppid, 0),
	EBPF_SYSCALL(__NR_getpgrp, SyS_getpgrp, 1),
	EBPF_SYSCALL(__NR_setsid, SyS_setsid, 1),
	EBPF_SYSCALL(__NR_setreuid, SyS_setreuid, 2),
	EBPF_SYSCALL(__NR_setregid, SyS_setregid, 2),
	EBPF_SYSCALL(__NR_getgroups, SyS_getgroups, 2),
	EBPF_SYSCALL(__NR_setgroups, SyS_setgroups, 2),
	EBPF_SYSCALL(__NR_setresuid, SyS_setresuid, 3),
	EBPF_SYSCALL(__NR_getresuid, SyS_getresuid, 3),
	EBPF_SYSCALL(__NR_setresgid, SyS_setresgid, 3),
	EBPF_SYSCALL(__NR_getresgid, SyS_getresgid, 3),
	EBPF_SYSCALL(__NR_getpgid, SyS_getpgid, 1),
	EBPF_SYSCALL(__NR_setfsuid, SyS_setfsuid, 1),
	EBPF_SYSCALL(__NR_setfsgid, SyS_setfsgid, 1),
	EBPF_SYSCALL(__NR_getsid, SyS_getsid, 1),
	EBPF_SYSCALL(__NR_capget, SyS_capget, 2),
	EBPF_SYSCALL(__NR_capset, SyS_capset, 2),
	EBPF_SYSCALL(__NR_rt_sigpending, SyS_rt_sigpending, 2),
	EBPF_SYSCALL(__NR_rt_sigtimedwait, SyS_rt_sigtimedwait, 4),
	EBPF_SYSCALL(__NR_rt_sigqueueinfo, SyS_rt_sigqueueinfo, 3),
	EBPF_SYSCALL(__NR_rt_sigsuspend, SyS_rt_sigsuspend, 2),
	EBPF_SYSCALL(__NR_sigaltstack, SyS_sigaltstack, 2),
	EBPF_SYSCALL_FILE(__NR_utime, SyS_utime, 2),
	EBPF_SYSCALL_FILE(__NR_mknod, SyS_mknod, 3),
	EBPF_SYSCALL_FILE(__NR_uselib, SyS_uselib, 1),
	EBPF_SYSCALL(__NR_personality, SyS_personality, 1),
	EBPF_SYSCALL(__NR_ustat, SyS_ustat, 2),
	EBPF_SYSCALL_FILE(__NR_statfs, SyS_statfs, 2),
	EBPF_SYSCALL_DESC(__NR_fstatfs, SyS_fstatfs, 2),
	EBPF_SYSCALL(__NR_sysfs, SyS_sysfs, 3),
	EBPF_SYSCALL(__NR_getpriority, SyS_getpriority, 2),
	EBPF_SYSCALL(__NR_setpriority, SyS_setpriority, 3),
	EBPF_SYSCALL(__NR_sched_setparam, SyS_sched_setparam, 2),
	EBPF_SYSCALL(__NR_sched_getparam, SyS_sched_getparam, 2),
	EBPF_SYSCALL(__NR_sched_setscheduler, SyS_sched_setscheduler, 3),
	EBPF_SYSCALL(__NR_sched_getscheduler, SyS_sched_getscheduler, 1),
	EBPF_SYSCALL(__NR_sched_get_priority_max,
			SyS_sched_get_priority_max, 1),
	EBPF_SYSCALL(__NR_sched_get_priority_min,
			SyS_sched_get_priority_min, 1),
	EBPF_SYSCALL(__NR_sched_rr_get_interval, SyS_sched_rr_get_interval, 2),
	EBPF_SYSCALL(__NR_mlock, SyS_mlock, 2),
	EBPF_SYSCALL(__NR_munlock, SyS_munlock, 2),
	EBPF_SYSCALL(__NR_mlockall, SyS_mlockall, 1),
	EBPF_SYSCALL(__NR_munlockall, SyS_munlockall, 1),
	EBPF_SYSCALL(__NR_vhangup, SyS_vhangup, 1),
	EBPF_SYSCALL(__NR_modify_ldt, SyS_modify_ldt, 3),
	EBPF_SYSCALL_FLAGS(__NR_pivot_root, SyS_pivot_root,
					EM_str_1_2 | EM_path_1_2, 2),
	EBPF_SYSCALL(__NR_sysctl, SyS_sysctl, 1),
	EBPF_SYSCALL(__NR_prctl, SyS_prctl, 5),
	EBPF_SYSCALL(__NR_arch_prctl, SyS_arch_prctl, 2),
	EBPF_SYSCALL(__NR_adjtimex, SyS_adjtimex, 1),
	EBPF_SYSCALL(__NR_setrlimit, SyS_setrlimit, 2),
	EBPF_SYSCALL_FILE(__NR_chroot, SyS_chroot, 1),
	EBPF_SYSCALL(__NR_sync, SyS_sync, 1),
	EBPF_SYSCALL_FILE(__NR_acct, SyS_acct, 1),
	EBPF_SYSCALL(__NR_settimeofday, SyS_settimeofday, 2),
	EBPF_SYSCALL_FLAGS(__NR_mount, SyS_mount,
						EM_str_1_2_3 | EM_path_1_2, 5),
	EBPF_SYSCALL_FILE(__NR_umount, SyS_umount, 2),
	EBPF_SYSCALL_FILE(__NR_umount2, SyS_umount2, 2),
	EBPF_SYSCALL_FILE(__NR_swapon, SyS_swapon, 2),
	EBPF_SYSCALL_FILE(__NR_swapoff, SyS_swapoff, 1),
	EBPF_SYSCALL(__NR_reboot, SyS_reboot, 4),
	EBPF_SYSCALL_FILE(__NR_sethostname, SyS_sethostname, 2),
	EBPF_SYSCALL_FILE(__NR_setdomainname, SyS_setdomainname, 2),
	EBPF_SYSCALL(__NR_iopl, SyS_iopl, 1),
	EBPF_SYSCALL(__NR_ioperm, SyS_ioperm, 3),
	EBPF_SYSCALL_FLAGS(__NR_init_module, SyS_init_module, EM_str_3, 3),
	EBPF_SYSCALL_FILE(__NR_delete_module, SyS_delete_module, 2),
	EBPF_SYSCALL_FLAGS(__NR_quotactl, SyS_quotactl, EM_str_2, 4),
	EBPF_SYSCALL(__NR_gettid, SyS_gettid, 0),
	EBPF_SYSCALL_DESC(__NR_readahead, SyS_readahead, 3),
	EBPF_SYSCALL_FLAGS(__NR_setxattr, SyS_setxattr,
						EM_str_1_2 | EM_path_1, 5),
	EBPF_SYSCALL_FLAGS(__NR_lsetxattr, SyS_lsetxattr,
						EM_str_1_2 | EM_path_1, 5),
	EBPF_SYSCALL_FLAGS(__NR_fsetxattr, SyS_fsetxattr,
						EM_fd_1 | EM_str_2, 5),
	EBPF_SYSCALL_FLAGS(__NR_getxattr, SyS_getxattr,
						EM_str_1_2 | EM_path_1, 4),
	EBPF_SYSCALL_FLAGS(__NR_lgetxattr, SyS_lgetxattr,
						EM_str_1_2 | EM_path_1, 4),
	EBPF_SYSCALL_FLAGS(__NR_fgetxattr, SyS_fgetxattr,
						EM_fd_1 | EM_str_2, 4),
	EBPF_SYSCALL_FLAGS(__NR_listxattr, SyS_listxattr,
						EM_str_1 | EM_path_1, 3),
	EBPF_SYSCALL_FLAGS(__NR_llistxattr, SyS_llistxattr,
						EM_str_1 | EM_path_1, 3),
	EBPF_SYSCALL_FLAGS(__NR_flistxattr, SyS_flistxattr, EM_fd_1, 3),
	EBPF_SYSCALL_FLAGS(__NR_removexattr, SyS_removexattr,
						EM_str_1_2 | EM_path_1, 2),
	EBPF_SYSCALL_FLAGS(__NR_lremovexattr, SyS_lremovexattr,
						EM_str_1_2 | EM_path_1, 2),
	EBPF_SYSCALL_FLAGS(__NR_fremovexattr, SyS_fremovexattr,
						EM_fd_1 | EM_str_2, 2),
	EBPF_SYSCALL(__NR_tkill, SyS_tkill, 2),
	EBPF_SYSCALL(__NR_time, SyS_time, 1),
	EBPF_SYSCALL(__NR_futex, SyS_futex, 6),
	EBPF_SYSCALL(__NR_sched_setaffinity, SyS_sched_setaffinity, 3),
	EBPF_SYSCALL(__NR_sched_getaffinity, SyS_sched_getaffinity, 3),
	EBPF_SYSCALL(__NR_set_thread_area, SyS_set_thread_area, 1),
	EBPF_SYSCALL(__NR_io_setup, SyS_io_setup, 2),
	EBPF_SYSCALL(__NR_io_destroy, SyS_io_destroy, 1),
	EBPF_SYSCALL(__NR_io_getevents, SyS_io_getevents, 5),
	EBPF_SYSCALL(__NR_io_submit, SyS_io_submit, 3),
	EBPF_SYSCALL(__NR_io_cancel, SyS_io_cancel, 3),
	EBPF_SYSCALL(__NR_get_thread_area, SyS_get_thread_area, 1),
	EBPF_SYSCALL_FLAGS(__NR_lookup_dcookie, SyS_lookup_dcookie,
				EM_str_2, 3),
	EBPF_SYSCALL(__NR_epoll_create, SyS_epoll_create, 1),
	EBPF_SYSCALL(__NR_remap_file_pages, SyS_remap_file_pages, 5),
	EBPF_SYSCALL_DESC(__NR_getdents64, SyS_getdents64, 3),
	EBPF_SYSCALL(__NR_set_tid_address, SyS_set_tid_address, 1),
	EBPF_SYSCALL(__NR_restart_syscall, SyS_restart_syscall, 1),
	EBPF_SYSCALL(__NR_semtimedop, SyS_semtimedop, 4),
	EBPF_SYSCALL_DESC(__NR_fadvise64, SyS_fadvise64, 4),
	EBPF_SYSCALL(__NR_timer_create, SyS_timer_create, 3),
	EBPF_SYSCALL(__NR_timer_settime, SyS_timer_settime, 4),
	EBPF_SYSCALL(__NR_timer_gettime, SyS_timer_gettime, 2),
	EBPF_SYSCALL(__NR_timer_getoverrun, SyS_timer_getoverrun, 1),
	EBPF_SYSCALL(__NR_timer_delete, SyS_timer_delete, 1),
	EBPF_SYSCALL(__NR_clock_settime, SyS_clock_settime, 2),
	EBPF_SYSCALL(__NR_clock_gettime, SyS_clock_gettime, 2),
	EBPF_SYSCALL(__NR_clock_getres, SyS_clock_getres, 2),
	EBPF_SYSCALL(__NR_clock_nanosleep, SyS_clock_nanosleep, 4),
	EBPF_SYSCALL_FLAGS(__NR_exit_group, SyS_exit_group, EM_no_ret, 1),
	EBPF_SYSCALL_DESC(__NR_epoll_wait, SyS_epoll_wait, 4),
	EBPF_SYSCALL_DESC(__NR_epoll_ctl, SyS_epoll_ctl, 4),
	EBPF_SYSCALL(__NR_tgkill, SyS_tgkill, 3),
	EBPF_SYSCALL_FILE(__NR_utimes, SyS_utimes, 2),
	EBPF_SYSCALL(__NR_mbind, SyS_mbind, 6),
	EBPF_SYSCALL(__NR_set_mempolicy, SyS_set_mempolicy, 3),
	EBPF_SYSCALL(__NR_get_mempolicy, SyS_get_mempolicy, 5),
	EBPF_SYSCALL_FILE(__NR_mq_open, SyS_mq_open, 4),
	EBPF_SYSCALL_FILE(__NR_mq_unlink, SyS_mq_unlink, 1),
	EBPF_SYSCALL(__NR_mq_timedsend, SyS_mq_timedsend, 5),
	EBPF_SYSCALL(__NR_mq_timedreceive, SyS_mq_timedreceive, 5),
	EBPF_SYSCALL(__NR_mq_notify, SyS_mq_notify, 2),
	EBPF_SYSCALL(__NR_mq_getsetattr, SyS_mq_getsetattr, 3),
	EBPF_SYSCALL(__NR_kexec_load, SyS_kexec_load, 4),
	EBPF_SYSCALL(__NR_waitid, SyS_waitid, 5),
	EBPF_SYSCALL_FLAGS(__NR_add_key, SyS_add_key, EM_str_1_2, 5),
	EBPF_SYSCALL_FLAGS(__NR_request_key, SyS_request_key, EM_str_1_2_3, 4),
	EBPF_SYSCALL(__NR_keyctl, SyS_keyctl, 5),
	EBPF_SYSCALL(__NR_ioprio_set, SyS_ioprio_set, 3),
	EBPF_SYSCALL(__NR_ioprio_get, SyS_ioprio_get, 2),
	EBPF_SYSCALL(__NR_inotify_init, SyS_inotify_init, 1),
	EBPF_SYSCALL_FLAGS(__NR_inotify_add_watch, SyS_inotify_add_watch,
				EM_fd_1 | EM_str_2, 3),
	EBPF_SYSCALL_DESC(__NR_inotify_rm_watch, SyS_inotify_rm_watch, 2),
	EBPF_SYSCALL(__NR_migrate_pages, SyS_migrate_pages, 4),
	EBPF_SYSCALL_FILEAT(__NR_openat, SyS_openat, EM_rfd, 4),
	EBPF_SYSCALL_FILEAT(__NR_mkdirat, SyS_mkdirat, 0, 3),
	EBPF_SYSCALL_FILEAT(__NR_mknodat, SyS_mknodat, 0, 4),
	EBPF_SYSCALL_FILEAT(__NR_fchownat, SyS_fchownat, EM_aep_arg_5, 5),
	EBPF_SYSCALL_FILEAT(__NR_futimesat, SyS_futimesat, 0, 3),
	EBPF_SYSCALL_FILEAT(__NR_fstatat, SyS_fstatat, EM_aep_arg_4, 4),
	EBPF_SYSCALL_FILEAT(__NR_newfstatat, SyS_newfstatat, EM_aep_arg_4, 4),
	EBPF_SYSCALL_FILEAT(__NR_unlinkat, SyS_unlinkat, 0, 3),
	EBPF_SYSCALL_FILEAT2(__NR_renameat, SyS_renameat, 0, 4),
	EBPF_SYSCALL_FILEAT2(__NR_linkat, SyS_linkat, EM_aep_arg_5, 5),
	EBPF_SYSCALL_FLAGS(__NR_symlinkat, SyS_symlinkat,
				EM_str_1_3 | EM_path_1_3 | EM_fd_2, 3),
	EBPF_SYSCALL_FILEAT(__NR_readlinkat, SyS_readlinkat, 0, 4),
	EBPF_SYSCALL_FILEAT(__NR_fchmodat, SyS_fchmodat, 0, 3),
	EBPF_SYSCALL_FILEAT(__NR_faccessat, SyS_faccessat, 0, 3),
	EBPF_SYSCALL(__NR_pselect6, SyS_pselect6, 6),
	EBPF_SYSCALL(__NR_ppoll, SyS_ppoll, 5),
	EBPF_SYSCALL(__NR_unshare, SyS_unshare, 1),
	EBPF_SYSCALL(__NR_set_robust_list, SyS_set_robust_list, 2),
	EBPF_SYSCALL(__NR_get_robust_list, SyS_get_robust_list, 3),
	EBPF_SYSCALL_FLAGS(__NR_splice, SyS_splice, EM_fd_1_3, 6),
	EBPF_SYSCALL_DESC(__NR_tee, SyS_tee, 4),
	EBPF_SYSCALL_DESC(__NR_sync_file_range, SyS_sync_file_range, 4),
	EBPF_SYSCALL_DESC(__NR_vmsplice, SyS_vmsplice, 4),
	EBPF_SYSCALL(__NR_move_pages, SyS_move_pages, 6),
	EBPF_SYSCALL_FILEAT(__NR_utimensat, SyS_utimensat, 0, 4),
	EBPF_SYSCALL_DESC(__NR_epoll_pwait, SyS_epoll_pwait, 5),
	EBPF_SYSCALL_DESC(__NR_signalfd, SyS_signalfd, 3),
	EBPF_SYSCALL(__NR_timerfd_create, SyS_timerfd_create, 2),
	EBPF_SYSCALL(__NR_eventfd, SyS_eventfd, 1),
	EBPF_SYSCALL_DESC(__NR_fallocate, SyS_fallocate, 4),
	EBPF_SYSCALL_DESC(__NR_timerfd_settime, SyS_timerfd_settime, 4),
	EBPF_SYSCALL_DESC(__NR_timerfd_gettime, SyS_timerfd_gettime, 2),
	EBPF_SYSCALL_DESC(__NR_accept4, SyS_accept4, 4),
	EBPF_SYSCALL_DESC(__NR_signalfd4, SyS_signalfd4, 4),
	EBPF_SYSCALL(__NR_eventfd2, SyS_eventfd2, 2),
	EBPF_SYSCALL(__NR_epoll_create1, SyS_epoll_create1, 1),
	EBPF_SYSCALL(__NR_pipe2, SyS_pipe2, 2),
	EBPF_SYSCALL(__NR_inotify_init1, SyS_inotify_init1, 1),
	EBPF_SYSCALL_DESC(__NR_preadv, SyS_preadv, 5),
	EBPF_SYSCALL_DESC(__NR_pwritev, SyS_pwritev, 5),
	EBPF_SYSCALL(__NR_rt_tgsigqueueinfo, SyS_rt_tgsigqueueinfo, 4),
	EBPF_SYSCALL(__NR_perf_event_open, SyS_perf_event_open, 5),
	EBPF_SYSCALL_DESC(__NR_recvmmsg, SyS_recvmmsg, 5),
	EBPF_SYSCALL(__NR_fanotify_init, SyS_fanotify_init, 2),
	EBPF_SYSCALL_FLAGS(__NR_fanotify_mark, SyS_fanotify_mark,
				EM_fd_4 | EM_str_5, 5),
	EBPF_SYSCALL(__NR_prlimit64, SyS_prlimit64, 4),
	EBPF_SYSCALL_FILEAT(__NR_name_to_handle_at, SyS_name_to_handle_at,
				EM_rhandle_3, 5),
	EBPF_SYSCALL_FLAGS(__NR_open_by_handle_at, SyS_open_by_handle_at,
				EM_fd_1 | EM_handle_2 | EM_rfd, 3),
	EBPF_SYSCALL(__NR_clock_adjtime, SyS_clock_adjtime, 2),
	EBPF_SYSCALL_DESC(__NR_syncfs, SyS_syncfs, 1),
	EBPF_SYSCALL_DESC(__NR_sendmmsg, SyS_sendmmsg, 4),
	EBPF_SYSCALL(__NR_setns, SyS_setns, 2),
	EBPF_SYSCALL(__NR_getcpu, SyS_getcpu, 3),
	EBPF_SYSCALL(__NR_process_vm_readv, SyS_process_vm_readv, 6),
	EBPF_SYSCALL(__NR_process_vm_writev, SyS_process_vm_writev, 6),
	EBPF_SYSCALL(__NR_kcmp, SyS_kcmp, 5),
	EBPF_SYSCALL_DESC(__NR_finit_module, SyS_finit_module, 3),
	EBPF_SYSCALL(__NR_sched_setattr, SyS_sched_setattr, 3),
	EBPF_SYSCALL(__NR_sched_getattr, SyS_sched_getattr, 4),
	EBPF_SYSCALL_FILEAT2(__NR_renameat2, SyS_renameat2, 0, 5),
	EBPF_SYSCALL(__NR_seccomp, SyS_seccomp, 3),
	EBPF_SYSCALL(__NR_getrandom, SyS_getrandom, 3),
	EBPF_SYSCALL_FILE(__NR_memfd_create, SyS_memfd_create, 2),
	EBPF_SYSCALL_FLAGS(__NR_kexec_file_load, SyS_kexec_file_load,
				EM_str_4, 5),
	EBPF_SYSCALL(__NR_bpf, SyS_bpf, 3),
	EBPF_SYSCALL_FILEAT(__NR_execveat, SyS_execveat, 0, 5),
	EBPF_SYSCALL(__NR_userfaultfd, SyS_userfaultfd, 1),
	EBPF_SYSCALL(__NR_membarrier, SyS_membarrier, 2),
	EBPF_SYSCALL(__NR_mlock2, SyS_mlock2, 3),
	EBPF_SYSCALL_FLAGS(__NR_copy_file_range, SyS_copy_file_range,
				EM_fd_1_3, 6),
	EBPF_SYSCALL(__NR_preadv2, SyS_preadv2, 6),
	EBPF_SYSCALL(__NR_pwritev2, SyS_pwritev2, 6),
	EBPF_SYSCALL(__NR_pkey_mprotect, SyS_pkey_mprotect, 4),
	EBPF_SYSCALL(__NR_pkey_alloc, SyS_pkey_alloc, 2),
	EBPF_SYSCALL(__NR_pkey_free, SyS_pkey_free, 1),
	EBPF_SYSCALL(__NR_waitpid, SyS_waitpid, 3),
	EBPF_SYSCALL(__NR_sigpending, SyS_sigpending, 1),
	EBPF_SYSCALL(__NR_sigprocmask, SyS_sigprocmask, 3),
	EBPF_SYSCALL(__NR_sgetmask, SyS_sgetmask, 1),
	EBPF_SYSCALL(__NR_ssetmask, SyS_ssetmask, 1),
	EBPF_SYSCALL(__NR_signal, SyS_signal, 2),
	EBPF_SYSCALL(__NR_sigsuspend, SyS_sigsuspend, 1),
	EBPF_SYSCALL(__NR_gethostname, SyS_gethostname, 2),
	EBPF_SYSCALL(__NR_old_getrlimit, SyS_old_getrlimit, 2),
	EBPF_SYSCALL(__NR_ni_syscall, SyS_ni_syscall, 6),
	EBPF_SYSCALL(__NR_nice, SyS_nice, 1),
	EBPF_SYSCALL(__NR_stime, SyS_stime, 1),
	EBPF_SYSCALL(__NR_chown16, SyS_chown16, 3),
	EBPF_SYSCALL_FILE(__NR_lchown16, SyS_lchown16, 3),
	EBPF_SYSCALL(__NR_fchown16, SyS_fchown16, 3),
	EBPF_SYSCALL(__NR_setregid16, SyS_setregid16, 2),
	EBPF_SYSCALL(__NR_setgid16, SyS_setgid16, 1),
	EBPF_SYSCALL(__NR_setreuid16, SyS_setreuid16, 2),
	EBPF_SYSCALL(__NR_setuid16, SyS_setuid16, 1),
	EBPF_SYSCALL(__NR_setresuid16, SyS_setresuid16, 3),
	EBPF_SYSCALL(__NR_getresuid16, SyS_getresuid16, 3),
	EBPF_SYSCALL(__NR_setresgid16, SyS_setresgid16, 3),
	EBPF_SYSCALL(__NR_getresgid16, SyS_getresgid16, 3),
	EBPF_SYSCALL(__NR_setfsuid16, SyS_setfsuid16, 1),
	EBPF_SYSCALL(__NR_setfsgid16, SyS_setfsgid16, 1),
	EBPF_SYSCALL(__NR_getgroups16, SyS_getgroups16, 2),
	EBPF_SYSCALL(__NR_setgroups16, SyS_setgroups16, 2),
	EBPF_SYSCALL(__NR_getuid16, SyS_getuid16, 1),
	EBPF_SYSCALL(__NR_geteuid16, SyS_geteuid16, 1),
	EBPF_SYSCALL(__NR_getgid16, SyS_getgid16, 1),
	EBPF_SYSCALL(__NR_getegid16, SyS_getegid16, 1),
	EBPF_SYSCALL_DESC(__NR_fadvise64_64, SyS_fadvise64_64, 4),
	EBPF_SYSCALL_DESC(__NR_llseek, SyS_llseek, 5),
	EBPF_SYSCALL_DESC(__NR_old_readdir, SyS_old_readdir, 3),
	EBPF_SYSCALL_FILE(__NR_oldumount, SyS_oldumount, 2),
	EBPF_SYSCALL_DESC(__NR_sync_file_range2, SyS_sync_file_range2, 4),
	EBPF_SYSCALL_FILE(__NR_statfs64, SyS_statfs64, 2),
	EBPF_SYSCALL_DESC(__NR_fstatfs64, SyS_fstatfs64, 2),
	EBPF_SYSCALL(__NR_bdflush, SyS_bdflush, 2),
	EBPF_SYSCALL(__NR_size_show, SyS_size_show, 6),
	EBPF_SYSCALL(__NR_dmi_field_show, SyS_dmi_field_show, 6),
	EBPF_SYSCALL(__NR_dmi_modalias_show, SyS_dmi_modalias_show, 6),
	EBPF_SYSCALL_DESC(__NR_send, SyS_send, 4),
	EBPF_SYSCALL_DESC(__NR_recv, SyS_recv, 4),
	EBPF_SYSCALL(__NR_socketcall, SyS_socketcall, 2),
	EBPF_SYSCALL(__NR_fillrect, SyS_fillrect, 6),
	EBPF_SYSCALL(__NR_copyarea, SyS_copyarea, 6),
	EBPF_SYSCALL(__NR_imageblit, SyS_imageblit, 6),
	EBPF_SYSCALL_FILEAT(__NR_statx, SyS_statx, 0, 5),

	/* mmap_pgoff is a 32-bit-only syscall */
	EBPF_SYSCALL_FLAGS(__NR_mmap_pgoff, SyS_mmap_pgoff, EM_DISABLED, 6),
};

/*
 * init_string_args_data -- init string arguments data in syscalls table
 */
static void
init_string_args_data(unsigned sc_num)
{
	unsigned mask = Syscall_array[sc_num].mask & EM_strings;
	char position = '0';
	unsigned nstr = 0;

	while (mask) {
		if (mask & 0x1) {
			Syscall_array[sc_num].positions[nstr] = position;
			nstr++;
		}
		mask >>= 1;
		position++;
	}

	Syscall_array[sc_num].nstrings = nstr;
}

/*
 * mark_available -- mark syscall as available in syscall table
 */
static void
mark_available(const char *sc_name)
{
	static int last_free = __NR_LAST_UNKNOWN;
	int n = -1;

	assert(__NR_LAST_UNKNOWN < SC_TBL_SIZE);

	for (int i = 0; i < last_free; i++) {
		if (Syscall_array[i].available)
			continue;

		if (Syscall_array[i].handler_name == NULL)
			continue;

		if (strcasecmp(sc_name, Syscall_array[i].handler_name) == 0) {
			/* found number */
			if (EM_DISABLED & Syscall_array[i].mask)
				return;
			n = i;
			break;
		}
	}

	if (n == -1) {
		/* add unknown syscall to the array */
		n = last_free++;
		assert(n < SC_TBL_SIZE);

		NOTICE("added syscall to the table [%i]: %s", n, sc_name);

		Syscall_array[n].args_qty = 6;
		Syscall_array[n].mask = 0;
		Syscall_array[n].nstrings = 0;
		Syscall_array[n].positions[0] = 0;
	}

	Syscall_array[n].available = 1;

	Syscall_array[n].name_length = strlen(sc_name);
	assert(Syscall_array[n].name_length <= SC_NAME_LEN);

	strncpy(Syscall_array[n].syscall_name, sc_name, SC_NAME_LEN);
	Syscall_array[n].syscall_name[SC_NAME_LEN] = '\0';

	Syscall_array[n].num = n;
	sprintf(Syscall_array[n].num_str, "%u", Syscall_array[n].num);

	init_string_args_data(n);
}

/*
 * mark_available_syscalls -- mark available syscalls
 */
static void
mark_available_syscalls()
{
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	int SyS_sigsuspend = 0;

	FILE *file = fopen(AVAILABLE_FILTERS, "r");
	if (file == NULL) {
		ERROR("error opening '%s': %m", AVAILABLE_FILTERS);
		exit(-1);
	}

	while ((read = getline(&line, &len, file)) != -1) {
		line[read - 1] = '\0';
		if (!is_a_sc(line, read - 1))
			continue;

		/* SyS_sigsuspend is exported by kernel twice */
		if (strcasecmp("SyS_sigsuspend", line) == 0) {
			if (SyS_sigsuspend)
				continue;
			SyS_sigsuspend = 1;
		}

		mark_available(line);
	}

	free(line);
	fclose(file);
}

/*
 * init_syscalls_table -- init the table of syscalls
 */
void
init_syscalls_table(void)
{
	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {

		Syscall_array[i].available = 0;
		Syscall_array[i].syscall_name[0] = 0;

		if (Syscall_array[i].handler_name == NULL &&
		    syscall_names[i] != NULL) {
			Syscall_array[i].handler_name = syscall_names[i];
			Syscall_array[i].args_qty = 6;
			Syscall_array[i].mask = 0;

			NOTICE("assigned syscalls table [%i] to '%s'",
				i, syscall_names[i]);
		}
	}

	mark_available_syscalls();
}

/*
 * print_syscalls_table -- print the table of syscalls
 */
int
print_syscalls_table(FILE *f)
{
	int res;

	init_syscalls_table();

	for (unsigned i = 0; i < SC_TBL_SIZE; i++) {
		if (i == __NR_FIRST_UNKNOWN)
			fprintf(f,
				"\nSyscalls with unknown or duplicated number:\n");

		if (Syscall_array[i].available) {
			res = fprintf(f, "%03d:\t%s\n",
					Syscall_array[i].num,
					Syscall_array[i].syscall_name);
			if (res <= 0)
				return res;
		}
	}

	fflush(f);

	return 1;
}

/*
 * dump_syscalls_table -- dump the table of syscalls
 */
int
dump_syscalls_table(const char *path)
{
	int size = sizeof(struct syscall_descriptor);
	int ret = 0;

	char signature[] = VLTRACE_TAB_SIGNATURE;
	unsigned major = VLTRACE_VERSION_MAJOR;
	unsigned minor = VLTRACE_VERSION_MINOR;
	unsigned patch = VLTRACE_VERSION_PATCH;

	FILE *file = fopen(path, "w");
	if (!file) {
		perror("fopen");
		return -1;
	}

	if (fwrite(signature, sizeof(signature), 1, file) != 1 ||
	    fwrite(&major, sizeof(major), 1, file) != 1 ||
	    fwrite(&minor, sizeof(minor), 1, file) != 1 ||
	    fwrite(&patch, sizeof(patch), 1, file) != 1 ||
	    fwrite(&size, sizeof(int), 1, file) != 1 ||
	    fwrite(Syscall_array, sizeof(Syscall_array), 1, file) != 1) {
		perror("fwrite");
		ret = -1;
	}

	fclose(file);
	return ret;
}
