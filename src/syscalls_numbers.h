/*
 * Copyright 2017, Intel Corporation
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
 * syscalls_numbers.h -- define syscalls numbers '__NR_syscall_name'
 *                       that are not defined in the running kernel.
 *
 * The syscalls numbers '__NR_syscall_name' are indices in the syscalls table:
 *
 *     struct sc_desc Syscall_array[SC_TBL_SIZE]
 *
 * defined in the file 'src/ebpf_syscalls.c', so all syscalls numbers contained
 * in this table have to be defined.
 */

#ifndef SYSCALLS_UNKNOWN_H
#define SYSCALLS_UNKNOWN_H

/* include syscalls numbers defined in the running kernel */
#include <syscalls_64_num.h_gen>

/*
 * Define syscalls numbers '__NR_syscall_name'
 * which are not defined in the running kernel.
 */
enum {
	/*
	 * __NR_FIRST_UNKNOWN has to be a valid index in the Syscall_array table
	 * and a number that never will be a valid syscall number. The biggest
	 * number in the 'syscalls_64_num.h_gen' file is 547, so let's take
	 * something bigger, for example 700, for safety reasons.
	 */
	__NR_FIRST_UNKNOWN = 700,

#ifndef __NR_arch_prctl
	__NR_arch_prctl,
#endif
#ifndef __NR_rt_sigreturn
	__NR_rt_sigreturn,
#endif
#ifndef __NR_ioperm
	__NR_ioperm,
#endif
#ifndef __NR_iopl
	__NR_iopl,
#endif
#ifndef __NR_modify_ldt
	__NR_modify_ldt,
#endif
#ifndef __NR_mmap
	__NR_mmap,
#endif
#ifndef __NR_set_thread_area
	__NR_set_thread_area,
#endif
#ifndef __NR_get_thread_area
	__NR_get_thread_area,
#endif
#ifndef __NR_set_tid_address
	__NR_set_tid_address,
#endif
#ifndef __NR_fork
	__NR_fork,
#endif
#ifndef __NR_vfork
	__NR_vfork,
#endif
#ifndef __NR_clone
	__NR_clone,
#endif
#ifndef __NR_unshare
	__NR_unshare,
#endif
#ifndef __NR_personality
	__NR_personality,
#endif
#ifndef __NR_exit
	__NR_exit,
#endif
#ifndef __NR_exit_group
	__NR_exit_group,
#endif
#ifndef __NR_waitid
	__NR_waitid,
#endif
#ifndef __NR_wait4
	__NR_wait4,
#endif
#ifndef __NR_waitpid
	__NR_waitpid,
#endif
#ifndef __NR_sysctl
	__NR_sysctl,
#endif
#ifndef __NR_capget
	__NR_capget,
#endif
#ifndef __NR_capset
	__NR_capset,
#endif
#ifndef __NR_ptrace
	__NR_ptrace,
#endif
#ifndef __NR_restart_syscall
	__NR_restart_syscall,
#endif
#ifndef __NR_rt_sigprocmask
	__NR_rt_sigprocmask,
#endif
#ifndef __NR_rt_sigpending
	__NR_rt_sigpending,
#endif
#ifndef __NR_rt_sigtimedwait
	__NR_rt_sigtimedwait,
#endif
#ifndef __NR_kill
	__NR_kill,
#endif
#ifndef __NR_tgkill
	__NR_tgkill,
#endif
#ifndef __NR_tkill
	__NR_tkill,
#endif
#ifndef __NR_rt_sigqueueinfo
	__NR_rt_sigqueueinfo,
#endif
#ifndef __NR_rt_tgsigqueueinfo
	__NR_rt_tgsigqueueinfo,
#endif
#ifndef __NR_sigaltstack
	__NR_sigaltstack,
#endif
#ifndef __NR_sigpending
	__NR_sigpending,
#endif
#ifndef __NR_sigprocmask
	__NR_sigprocmask,
#endif
#ifndef __NR_rt_sigaction
	__NR_rt_sigaction,
#endif
#ifndef __NR_sgetmask
	__NR_sgetmask,
#endif
#ifndef __NR_ssetmask
	__NR_ssetmask,
#endif
#ifndef __NR_signal
	__NR_signal,
#endif
#ifndef __NR_pause
	__NR_pause,
#endif
#ifndef __NR_rt_sigsuspend
	__NR_rt_sigsuspend,
#endif
#ifndef __NR_sigsuspend
	__NR_sigsuspend,
#endif
#ifndef __NR_setpriority
	__NR_setpriority,
#endif
#ifndef __NR_getpriority
	__NR_getpriority,
#endif
#ifndef __NR_setregid
	__NR_setregid,
#endif
#ifndef __NR_setgid
	__NR_setgid,
#endif
#ifndef __NR_setreuid
	__NR_setreuid,
#endif
#ifndef __NR_setuid
	__NR_setuid,
#endif
#ifndef __NR_setresuid
	__NR_setresuid,
#endif
#ifndef __NR_getresuid
	__NR_getresuid,
#endif
#ifndef __NR_setresgid
	__NR_setresgid,
#endif
#ifndef __NR_getresgid
	__NR_getresgid,
#endif
#ifndef __NR_setfsuid
	__NR_setfsuid,
#endif
#ifndef __NR_setfsgid
	__NR_setfsgid,
#endif
#ifndef __NR_getpid
	__NR_getpid,
#endif
#ifndef __NR_gettid
	__NR_gettid,
#endif
#ifndef __NR_getppid
	__NR_getppid,
#endif
#ifndef __NR_getuid
	__NR_getuid,
#endif
#ifndef __NR_geteuid
	__NR_geteuid,
#endif
#ifndef __NR_getgid
	__NR_getgid,
#endif
#ifndef __NR_getegid
	__NR_getegid,
#endif
#ifndef __NR_times
	__NR_times,
#endif
#ifndef __NR_setpgid
	__NR_setpgid,
#endif
#ifndef __NR_getpgid
	__NR_getpgid,
#endif
#ifndef __NR_getpgrp
	__NR_getpgrp,
#endif
#ifndef __NR_getsid
	__NR_getsid,
#endif
#ifndef __NR_setsid
	__NR_setsid,
#endif
#ifndef __NR_olduname
	__NR_olduname,
#endif
#ifndef __NR_uname
	__NR_uname,
#endif
#ifndef __NR_newuname
	__NR_newuname,
#endif
#ifndef __NR_sethostname
	__NR_sethostname,
#endif
#ifndef __NR_gethostname
	__NR_gethostname,
#endif
#ifndef __NR_setdomainname
	__NR_setdomainname,
#endif
#ifndef __NR_old_getrlimit
	__NR_old_getrlimit,
#endif
#ifndef __NR_getrlimit
	__NR_getrlimit,
#endif
#ifndef __NR_prlimit64
	__NR_prlimit64,
#endif
#ifndef __NR_setrlimit
	__NR_setrlimit,
#endif
#ifndef __NR_getrusage
	__NR_getrusage,
#endif
#ifndef __NR_umask
	__NR_umask,
#endif
#ifndef __NR_prctl
	__NR_prctl,
#endif
#ifndef __NR_getcpu
	__NR_getcpu,
#endif
#ifndef __NR_sysinfo
	__NR_sysinfo,
#endif
#ifndef __NR_ni_syscall
	__NR_ni_syscall,
#endif
#ifndef __NR_setns
	__NR_setns,
#endif
#ifndef __NR_reboot
	__NR_reboot,
#endif
#ifndef __NR_getgroups
	__NR_getgroups,
#endif
#ifndef __NR_setgroups
	__NR_setgroups,
#endif
#ifndef __NR_nice
	__NR_nice,
#endif
#ifndef __NR_sched_setscheduler
	__NR_sched_setscheduler,
#endif
#ifndef __NR_sched_setparam
	__NR_sched_setparam,
#endif
#ifndef __NR_sched_setattr
	__NR_sched_setattr,
#endif
#ifndef __NR_sched_getscheduler
	__NR_sched_getscheduler,
#endif
#ifndef __NR_sched_getparam
	__NR_sched_getparam,
#endif
#ifndef __NR_sched_getattr
	__NR_sched_getattr,
#endif
#ifndef __NR_sched_setaffinity
	__NR_sched_setaffinity,
#endif
#ifndef __NR_sched_getaffinity
	__NR_sched_getaffinity,
#endif
#ifndef __NR_sched_yield
	__NR_sched_yield,
#endif
#ifndef __NR_sched_get_priority_max
	__NR_sched_get_priority_max,
#endif
#ifndef __NR_sched_get_priority_min
	__NR_sched_get_priority_min,
#endif
#ifndef __NR_sched_rr_get_interval
	__NR_sched_rr_get_interval,
#endif
#ifndef __NR_syslog
	__NR_syslog,
#endif
#ifndef __NR_kcmp
	__NR_kcmp,
#endif
#ifndef __NR_time
	__NR_time,
#endif
#ifndef __NR_stime
	__NR_stime,
#endif
#ifndef __NR_gettimeofday
	__NR_gettimeofday,
#endif
#ifndef __NR_settimeofday
	__NR_settimeofday,
#endif
#ifndef __NR_adjtimex
	__NR_adjtimex,
#endif
#ifndef __NR_alarm
	__NR_alarm,
#endif
#ifndef __NR_nanosleep
	__NR_nanosleep,
#endif
#ifndef __NR_getitimer
	__NR_getitimer,
#endif
#ifndef __NR_setitimer
	__NR_setitimer,
#endif
#ifndef __NR_timer_create
	__NR_timer_create,
#endif
#ifndef __NR_timer_gettime
	__NR_timer_gettime,
#endif
#ifndef __NR_timer_getoverrun
	__NR_timer_getoverrun,
#endif
#ifndef __NR_timer_settime
	__NR_timer_settime,
#endif
#ifndef __NR_timer_delete
	__NR_timer_delete,
#endif
#ifndef __NR_clock_settime
	__NR_clock_settime,
#endif
#ifndef __NR_clock_gettime
	__NR_clock_gettime,
#endif
#ifndef __NR_clock_adjtime
	__NR_clock_adjtime,
#endif
#ifndef __NR_clock_getres
	__NR_clock_getres,
#endif
#ifndef __NR_clock_nanosleep
	__NR_clock_nanosleep,
#endif
#ifndef __NR_set_robust_list
	__NR_set_robust_list,
#endif
#ifndef __NR_get_robust_list
	__NR_get_robust_list,
#endif
#ifndef __NR_futex
	__NR_futex,
#endif
#ifndef __NR_chown16
	__NR_chown16,
#endif
#ifndef __NR_lchown16
	__NR_lchown16,
#endif
#ifndef __NR_fchown16
	__NR_fchown16,
#endif
#ifndef __NR_setregid16
	__NR_setregid16,
#endif
#ifndef __NR_setgid16
	__NR_setgid16,
#endif
#ifndef __NR_setreuid16
	__NR_setreuid16,
#endif
#ifndef __NR_setuid16
	__NR_setuid16,
#endif
#ifndef __NR_setresuid16
	__NR_setresuid16,
#endif
#ifndef __NR_getresuid16
	__NR_getresuid16,
#endif
#ifndef __NR_setresgid16
	__NR_setresgid16,
#endif
#ifndef __NR_getresgid16
	__NR_getresgid16,
#endif
#ifndef __NR_setfsuid16
	__NR_setfsuid16,
#endif
#ifndef __NR_setfsgid16
	__NR_setfsgid16,
#endif
#ifndef __NR_getgroups16
	__NR_getgroups16,
#endif
#ifndef __NR_setgroups16
	__NR_setgroups16,
#endif
#ifndef __NR_getuid16
	__NR_getuid16,
#endif
#ifndef __NR_geteuid16
	__NR_geteuid16,
#endif
#ifndef __NR_getgid16
	__NR_getgid16,
#endif
#ifndef __NR_getegid16
	__NR_getegid16,
#endif
#ifndef __NR_delete_module
	__NR_delete_module,
#endif
#ifndef __NR_init_module
	__NR_init_module,
#endif
#ifndef __NR_finit_module
	__NR_finit_module,
#endif
#ifndef __NR_acct
	__NR_acct,
#endif
#ifndef __NR_kexec_load
	__NR_kexec_load,
#endif
#ifndef __NR_kexec_file_load
	__NR_kexec_file_load,
#endif
#ifndef __NR_seccomp
	__NR_seccomp,
#endif
#ifndef __NR_bpf
	__NR_bpf,
#endif
#ifndef __NR_membarrier
	__NR_membarrier,
#endif
#ifndef __NR_readahead
	__NR_readahead,
#endif
#ifndef __NR_memfd_create
	__NR_memfd_create,
#endif
#ifndef __NR_mincore
	__NR_mincore,
#endif
#ifndef __NR_mlock
	__NR_mlock,
#endif
#ifndef __NR_mlock2
	__NR_mlock2,
#endif
#ifndef __NR_munlock
	__NR_munlock,
#endif
#ifndef __NR_mlockall
	__NR_mlockall,
#endif
#ifndef __NR_munlockall
	__NR_munlockall,
#endif
#ifndef __NR_mmap_pgoff
	__NR_mmap_pgoff,
#endif
#ifndef __NR_brk
	__NR_brk,
#endif
#ifndef __NR_munmap
	__NR_munmap,
#endif
#ifndef __NR_remap_file_pages
	__NR_remap_file_pages,
#endif
#ifndef __NR_mprotect
	__NR_mprotect,
#endif
#ifndef __NR_mremap
	__NR_mremap,
#endif
#ifndef __NR_msync
	__NR_msync,
#endif
#ifndef __NR_process_vm_readv
	__NR_process_vm_readv,
#endif
#ifndef __NR_process_vm_writev
	__NR_process_vm_writev,
#endif
#ifndef __NR_fadvise64_64
	__NR_fadvise64_64,
#endif
#ifndef __NR_fadvise64
	__NR_fadvise64,
#endif
#ifndef __NR_madvise
	__NR_madvise,
#endif
#ifndef __NR_swapoff
	__NR_swapoff,
#endif
#ifndef __NR_swapon
	__NR_swapon,
#endif
#ifndef __NR_set_mempolicy
	__NR_set_mempolicy,
#endif
#ifndef __NR_migrate_pages
	__NR_migrate_pages,
#endif
#ifndef __NR_get_mempolicy
	__NR_get_mempolicy,
#endif
#ifndef __NR_mbind
	__NR_mbind,
#endif
#ifndef __NR_move_pages
	__NR_move_pages,
#endif
#ifndef __NR_close
	__NR_close,
#endif
#ifndef __NR_truncate
	__NR_truncate,
#endif
#ifndef __NR_ftruncate
	__NR_ftruncate,
#endif
#ifndef __NR_fallocate
	__NR_fallocate,
#endif
#ifndef __NR_faccessat
	__NR_faccessat,
#endif
#ifndef __NR_access
	__NR_access,
#endif
#ifndef __NR_chdir
	__NR_chdir,
#endif
#ifndef __NR_fchdir
	__NR_fchdir,
#endif
#ifndef __NR_chroot
	__NR_chroot,
#endif
#ifndef __NR_fchmod
	__NR_fchmod,
#endif
#ifndef __NR_fchmodat
	__NR_fchmodat,
#endif
#ifndef __NR_chmod
	__NR_chmod,
#endif
#ifndef __NR_fchownat
	__NR_fchownat,
#endif
#ifndef __NR_chown
	__NR_chown,
#endif
#ifndef __NR_lchown
	__NR_lchown,
#endif
#ifndef __NR_fchown
	__NR_fchown,
#endif
#ifndef __NR_open
	__NR_open,
#endif
#ifndef __NR_openat
	__NR_openat,
#endif
#ifndef __NR_creat
	__NR_creat,
#endif
#ifndef __NR_vhangup
	__NR_vhangup,
#endif
#ifndef __NR_lseek
	__NR_lseek,
#endif
#ifndef __NR_llseek
	__NR_llseek,
#endif
#ifndef __NR_read
	__NR_read,
#endif
#ifndef __NR_write
	__NR_write,
#endif
#ifndef __NR_pread64
	__NR_pread64,
#endif
#ifndef __NR_pwrite64
	__NR_pwrite64,
#endif
#ifndef __NR_readv
	__NR_readv,
#endif
#ifndef __NR_writev
	__NR_writev,
#endif
#ifndef __NR_preadv
	__NR_preadv,
#endif
#ifndef __NR_pwritev
	__NR_pwritev,
#endif
#ifndef __NR_sendfile
	__NR_sendfile,
#endif
#ifndef __NR_sendfile64
	__NR_sendfile64,
#endif
#ifndef __NR_stat
	__NR_stat,
#endif
#ifndef __NR_lstat
	__NR_lstat,
#endif
#ifndef __NR_fstat
	__NR_fstat,
#endif
#ifndef __NR_fstatat
	__NR_fstatat,
#endif
#ifndef __NR_newstat
	__NR_newstat,
#endif
#ifndef __NR_newlstat
	__NR_newlstat,
#endif
#ifndef __NR_newfstatat
	__NR_newfstatat,
#endif
#ifndef __NR_newfstat
	__NR_newfstat,
#endif
#ifndef __NR_readlinkat
	__NR_readlinkat,
#endif
#ifndef __NR_readlink
	__NR_readlink,
#endif
#ifndef __NR_uselib
	__NR_uselib,
#endif
#ifndef __NR_execve
	__NR_execve,
#endif
#ifndef __NR_execveat
	__NR_execveat,
#endif
#ifndef __NR_pipe2
	__NR_pipe2,
#endif
#ifndef __NR_pipe
	__NR_pipe,
#endif
#ifndef __NR_mknodat
	__NR_mknodat,
#endif
#ifndef __NR_mknod
	__NR_mknod,
#endif
#ifndef __NR_mkdirat
	__NR_mkdirat,
#endif
#ifndef __NR_mkdir
	__NR_mkdir,
#endif
#ifndef __NR_rmdir
	__NR_rmdir,
#endif
#ifndef __NR_unlinkat
	__NR_unlinkat,
#endif
#ifndef __NR_unlink
	__NR_unlink,
#endif
#ifndef __NR_symlinkat
	__NR_symlinkat,
#endif
#ifndef __NR_symlink
	__NR_symlink,
#endif
#ifndef __NR_linkat
	__NR_linkat,
#endif
#ifndef __NR_link
	__NR_link,
#endif
#ifndef __NR_renameat2
	__NR_renameat2,
#endif
#ifndef __NR_renameat
	__NR_renameat,
#endif
#ifndef __NR_rename
	__NR_rename,
#endif
#ifndef __NR_fcntl
	__NR_fcntl,
#endif
#ifndef __NR_ioctl
	__NR_ioctl,
#endif
#ifndef __NR_old_readdir
	__NR_old_readdir,
#endif
#ifndef __NR_getdents
	__NR_getdents,
#endif
#ifndef __NR_getdents64
	__NR_getdents64,
#endif
#ifndef __NR_select
	__NR_select,
#endif
#ifndef __NR_pselect6
	__NR_pselect6,
#endif
#ifndef __NR_poll
	__NR_poll,
#endif
#ifndef __NR_ppoll
	__NR_ppoll,
#endif
#ifndef __NR_getcwd
	__NR_getcwd,
#endif
#ifndef __NR_dup3
	__NR_dup3,
#endif
#ifndef __NR_dup2
	__NR_dup2,
#endif
#ifndef __NR_dup
	__NR_dup,
#endif
#ifndef __NR_sysfs
	__NR_sysfs,
#endif
#ifndef __NR_umount
	__NR_umount,
#endif
#ifndef __NR_umount2
	__NR_umount2,
#endif
#ifndef __NR_oldumount
	__NR_oldumount,
#endif
#ifndef __NR_mount
	__NR_mount,
#endif
#ifndef __NR_pivot_root
	__NR_pivot_root,
#endif
#ifndef __NR_setxattr
	__NR_setxattr,
#endif
#ifndef __NR_lsetxattr
	__NR_lsetxattr,
#endif
#ifndef __NR_fsetxattr
	__NR_fsetxattr,
#endif
#ifndef __NR_getxattr
	__NR_getxattr,
#endif
#ifndef __NR_lgetxattr
	__NR_lgetxattr,
#endif
#ifndef __NR_fgetxattr
	__NR_fgetxattr,
#endif
#ifndef __NR_listxattr
	__NR_listxattr,
#endif
#ifndef __NR_llistxattr
	__NR_llistxattr,
#endif
#ifndef __NR_flistxattr
	__NR_flistxattr,
#endif
#ifndef __NR_removexattr
	__NR_removexattr,
#endif
#ifndef __NR_lremovexattr
	__NR_lremovexattr,
#endif
#ifndef __NR_fremovexattr
	__NR_fremovexattr,
#endif
#ifndef __NR_vmsplice
	__NR_vmsplice,
#endif
#ifndef __NR_splice
	__NR_splice,
#endif
#ifndef __NR_tee
	__NR_tee,
#endif
#ifndef __NR_sync
	__NR_sync,
#endif
#ifndef __NR_syncfs
	__NR_syncfs,
#endif
#ifndef __NR_fsync
	__NR_fsync,
#endif
#ifndef __NR_fdatasync
	__NR_fdatasync,
#endif
#ifndef __NR_sync_file_range
	__NR_sync_file_range,
#endif
#ifndef __NR_sync_file_range2
	__NR_sync_file_range2,
#endif
#ifndef __NR_utime
	__NR_utime,
#endif
#ifndef __NR_utimensat
	__NR_utimensat,
#endif
#ifndef __NR_futimesat
	__NR_futimesat,
#endif
#ifndef __NR_utimes
	__NR_utimes,
#endif
#ifndef __NR_statfs
	__NR_statfs,
#endif
#ifndef __NR_statfs64
	__NR_statfs64,
#endif
#ifndef __NR_fstatfs
	__NR_fstatfs,
#endif
#ifndef __NR_fstatfs64
	__NR_fstatfs64,
#endif
#ifndef __NR_ustat
	__NR_ustat,
#endif
#ifndef __NR_bdflush
	__NR_bdflush,
#endif
#ifndef __NR_inotify_init1
	__NR_inotify_init1,
#endif
#ifndef __NR_inotify_init
	__NR_inotify_init,
#endif
#ifndef __NR_inotify_add_watch
	__NR_inotify_add_watch,
#endif
#ifndef __NR_inotify_rm_watch
	__NR_inotify_rm_watch,
#endif
#ifndef __NR_fanotify_init
	__NR_fanotify_init,
#endif
#ifndef __NR_fanotify_mark
	__NR_fanotify_mark,
#endif
#ifndef __NR_epoll_create1
	__NR_epoll_create1,
#endif
#ifndef __NR_epoll_create
	__NR_epoll_create,
#endif
#ifndef __NR_epoll_ctl
	__NR_epoll_ctl,
#endif
#ifndef __NR_epoll_wait
	__NR_epoll_wait,
#endif
#ifndef __NR_epoll_pwait
	__NR_epoll_pwait,
#endif
#ifndef __NR_signalfd4
	__NR_signalfd4,
#endif
#ifndef __NR_signalfd
	__NR_signalfd,
#endif
#ifndef __NR_timerfd_create
	__NR_timerfd_create,
#endif
#ifndef __NR_timerfd_settime
	__NR_timerfd_settime,
#endif
#ifndef __NR_timerfd_gettime
	__NR_timerfd_gettime,
#endif
#ifndef __NR_eventfd2
	__NR_eventfd2,
#endif
#ifndef __NR_eventfd
	__NR_eventfd,
#endif
#ifndef __NR_userfaultfd
	__NR_userfaultfd,
#endif
#ifndef __NR_io_setup
	__NR_io_setup,
#endif
#ifndef __NR_io_destroy
	__NR_io_destroy,
#endif
#ifndef __NR_io_submit
	__NR_io_submit,
#endif
#ifndef __NR_io_cancel
	__NR_io_cancel,
#endif
#ifndef __NR_io_getevents
	__NR_io_getevents,
#endif
#ifndef __NR_flock
	__NR_flock,
#endif
#ifndef __NR_name_to_handle_at
	__NR_name_to_handle_at,
#endif
#ifndef __NR_open_by_handle_at
	__NR_open_by_handle_at,
#endif
#ifndef __NR_quotactl
	__NR_quotactl,
#endif
#ifndef __NR_lookup_dcookie
	__NR_lookup_dcookie,
#endif
#ifndef __NR_msgget
	__NR_msgget,
#endif
#ifndef __NR_msgctl
	__NR_msgctl,
#endif
#ifndef __NR_msgsnd
	__NR_msgsnd,
#endif
#ifndef __NR_msgrcv
	__NR_msgrcv,
#endif
#ifndef __NR_semget
	__NR_semget,
#endif
#ifndef __NR_semctl
	__NR_semctl,
#endif
#ifndef __NR_semtimedop
	__NR_semtimedop,
#endif
#ifndef __NR_semop
	__NR_semop,
#endif
#ifndef __NR_shmget
	__NR_shmget,
#endif
#ifndef __NR_shmctl
	__NR_shmctl,
#endif
#ifndef __NR_shmat
	__NR_shmat,
#endif
#ifndef __NR_shmdt
	__NR_shmdt,
#endif
#ifndef __NR_mq_open
	__NR_mq_open,
#endif
#ifndef __NR_mq_unlink
	__NR_mq_unlink,
#endif
#ifndef __NR_mq_timedsend
	__NR_mq_timedsend,
#endif
#ifndef __NR_mq_timedreceive
	__NR_mq_timedreceive,
#endif
#ifndef __NR_mq_notify
	__NR_mq_notify,
#endif
#ifndef __NR_mq_getsetattr
	__NR_mq_getsetattr,
#endif
#ifndef __NR_add_key
	__NR_add_key,
#endif
#ifndef __NR_request_key
	__NR_request_key,
#endif
#ifndef __NR_keyctl
	__NR_keyctl,
#endif
#ifndef __NR_ioprio_set
	__NR_ioprio_set,
#endif
#ifndef __NR_ioprio_get
	__NR_ioprio_get,
#endif
#ifndef __NR_size_show
	__NR_size_show,
#endif
#ifndef __NR_getrandom
	__NR_getrandom,
#endif
#ifndef __NR_dmi_field_show
	__NR_dmi_field_show,
#endif
#ifndef __NR_dmi_modalias_show
	__NR_dmi_modalias_show,
#endif
#ifndef __NR_socket
	__NR_socket,
#endif
#ifndef __NR_socketpair
	__NR_socketpair,
#endif
#ifndef __NR_bind
	__NR_bind,
#endif
#ifndef __NR_listen
	__NR_listen,
#endif
#ifndef __NR_accept4
	__NR_accept4,
#endif
#ifndef __NR_accept
	__NR_accept,
#endif
#ifndef __NR_connect
	__NR_connect,
#endif
#ifndef __NR_getsockname
	__NR_getsockname,
#endif
#ifndef __NR_getpeername
	__NR_getpeername,
#endif
#ifndef __NR_sendto
	__NR_sendto,
#endif
#ifndef __NR_send
	__NR_send,
#endif
#ifndef __NR_recvfrom
	__NR_recvfrom,
#endif
#ifndef __NR_recv
	__NR_recv,
#endif
#ifndef __NR_setsockopt
	__NR_setsockopt,
#endif
#ifndef __NR_getsockopt
	__NR_getsockopt,
#endif
#ifndef __NR_shutdown
	__NR_shutdown,
#endif
#ifndef __NR_sendmsg
	__NR_sendmsg,
#endif
#ifndef __NR_sendmmsg
	__NR_sendmmsg,
#endif
#ifndef __NR_recvmsg
	__NR_recvmsg,
#endif
#ifndef __NR_recvmmsg
	__NR_recvmmsg,
#endif
#ifndef __NR_socketcall
	__NR_socketcall,
#endif
#ifndef __NR_pkey_mprotect
	__NR_pkey_mprotect,
#endif
#ifndef __NR_pkey_alloc
	__NR_pkey_alloc,
#endif
#ifndef __NR_pkey_free
	__NR_pkey_free,
#endif
#ifndef __NR_preadv2
	__NR_preadv2,
#endif
#ifndef __NR_pwritev2
	__NR_pwritev2,
#endif
#ifndef __NR_copy_file_range
	__NR_copy_file_range,
#endif
#ifndef __NR_fillrect
	__NR_fillrect,
#endif
#ifndef __NR_copyarea
	__NR_copyarea,
#endif
#ifndef __NR_imageblit
	__NR_imageblit,
#endif
#ifndef __NR_perf_event_open
	__NR_perf_event_open,
#endif
#ifndef __NR_statx
	__NR_statx,
#endif

	/* it MUST be the last one in this enum */
	__NR_LAST_UNKNOWN,
};

#endif /* SYSCALLS_UNKNOWN_H */
