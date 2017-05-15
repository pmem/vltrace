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
 * test_syscalls.c -- functional tests for vltrace
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <linux/futex.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <poll.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/swap.h>

#define PATTERN_START	0x12345678
#define PATTERN_END	0x87654321
#define BUF_LEN		0x100

#define MARK_START()	close(PATTERN_START)
#define MARK_END()	close(PATTERN_END)

#define FILE_EXIST	"/etc/fstab"
#define FILE_CREATE	"/tmp/tmp-vltrace"

#define NON_EXIST_PATH_1	"111_non_exist"
#define NON_EXIST_PATH_2	"222_non_exist"

/* used to test unsupported flags (almost all bits are set) */
#define FLAGS_SET		0x0FFFFFFFFFFFFFFF

/*
 * test_basic_syscalls -- test basic syscalls
 */
static void
test_basic_syscalls(void)
{
	char buffer[BUF_LEN];
	struct utsname name;
	struct stat buf;
	int fd;

	/* PART #1 - real arguments */

	fd = open(FILE_EXIST, O_RDONLY);
	close(fd);

	fd = open(FILE_CREATE, O_RDWR | O_CREAT, 0666);
	write(fd, buffer, BUF_LEN);
	lseek(fd, 0, SEEK_SET);
	read(fd, buffer, BUF_LEN);
	fstat(fd, &buf);
	close(fd);
	unlink(FILE_CREATE);

	execve(FILE_CREATE, (char * const*)0x123456, (char * const*)0x654321);

	stat(FILE_EXIST, &buf);
	lstat(FILE_EXIST, &buf);

	uname(&name);

	syscall(SYS_getpid); /* getpid */
	syscall(SYS_gettid); /* gettid */

	/* PART #2 - test arguments */

	write(0x101, buffer, 1);
	read (0x102, buffer, 2);
	lseek(0x103, 3, SEEK_END);
	fstat(0x104, &buf);
	syscall(SYS_futex, 1, FUTEX_WAKE_OP, 3, 4, 5, FLAGS_SET); /* futex */
}

/*
 * test_unsupported_syscalls -- test unsupported syscalls
 */
static void
test_unsupported_syscalls(void)
{
	chroot(NON_EXIST_PATH_1);

	/* fcntl - unsupported flags */
	syscall(SYS_fcntl, 0x104, FLAGS_SET, FLAGS_SET, 0x105, 0x106, 0x107);

	flock(0x108, 0x109);

	setsockopt(0x101, 0x102, 0x103, (void *)0x104, (socklen_t)0x105);
	getsockopt(0x106, 0x107, 0x108, (void *)0x109, (socklen_t *)0x110);

	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	getsockname(0x101, &addr, &addrlen);

	inotify_add_watch(0x104, NON_EXIST_PATH_1, 0x105);
	inotify_rm_watch(0x106, 0x107);

	syscall(SYS_io_cancel, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106);
	syscall(SYS_io_destroy, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107);
	syscall(SYS_io_getevents, 0x103, 0x104, 0x105, 0x106, 0x107, 0x108);
	syscall(SYS_io_setup, 0x104, 0x105, 0x106, 0x107, 0x108, 0x109);
	syscall(SYS_io_submit, 0x105, 0x106, 0x107, 0x108, 0x109, 0x110);

	syscall(SYS_ioctl, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106);

	mknod(FILE_EXIST, 0x101, 0x102);
	mknodat(0x103, FILE_EXIST, 0x104, 0x105);

	mmap((void *)0x101, 0x102, 0x103, 0xFFFF, 0x105, 0x106);
	munmap((void *)0x102, 0x103);

	struct timeval time1;
	struct timespec time2;
	memset(&time1, 0, sizeof(time1));
	memset(&time2, 0, sizeof(time2));

	select(0, (fd_set *)0x104, (fd_set *)0x105, (fd_set *)0x106, &time1);
	pselect(0, (fd_set *)0x105, (fd_set *)0x106, (fd_set *)0x107, &time2,
		(const sigset_t *)0x108);

	swapon(NON_EXIST_PATH_1, 0x101);
	swapoff(NON_EXIST_PATH_2);

	syscall(SYS_poll, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107);

	mount(NON_EXIST_PATH_1, NON_EXIST_PATH_2, "ext3", 0x101, (void *)0x102);
	umount(NON_EXIST_PATH_1);
	umount2(NON_EXIST_PATH_2, 0x123);

	setxattr(NON_EXIST_PATH_1, NON_EXIST_PATH_2,
		 (const void *)0x101, 0x102, 0x103);
	lsetxattr(NON_EXIST_PATH_2, NON_EXIST_PATH_1,
		  (const void *)0x104, 0x105, 0x106);
	fsetxattr(0x107, NON_EXIST_PATH_2,
		  (const void *)0x108, 0x109, 0x110);

	getxattr(NON_EXIST_PATH_1, NON_EXIST_PATH_2, (void *)0x101, 0x102);
	lgetxattr(NON_EXIST_PATH_2, NON_EXIST_PATH_1, (void *)0x103, 0x104);
	fgetxattr(0x105, NON_EXIST_PATH_2, (void *)0x106, 0x107);

	listxattr(NON_EXIST_PATH_1, NON_EXIST_PATH_2, 0x101);
	llistxattr(NON_EXIST_PATH_2, NON_EXIST_PATH_1, 0x102);
	flistxattr(0x103, NON_EXIST_PATH_2, 0x104);

	removexattr(NON_EXIST_PATH_1, NON_EXIST_PATH_2);
	lremovexattr(NON_EXIST_PATH_2, NON_EXIST_PATH_1);
	fremovexattr(0x101, NON_EXIST_PATH_2);

	syscall(SYS_ppoll, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106);

	epoll_ctl(0x101, 0x102, 0x103, (struct epoll_event *)0x104);
	epoll_wait(0x102, (struct epoll_event *)0x103, 0x104, 0x105);
	epoll_pwait(0x103, (struct epoll_event *)0x104, 0x105, 0x106,
			(const sigset_t *)0x107);

	/* open - unsupported flags */
	syscall(SYS_open, NON_EXIST_PATH_2, FLAGS_SET, FLAGS_SET, FLAGS_SET,
		FLAGS_SET, FLAGS_SET);

	/* clone - unsupported flags */
	syscall(SYS_clone, FLAGS_SET, FLAGS_SET, FLAGS_SET, FLAGS_SET,
		FLAGS_SET, FLAGS_SET);

	/* vfork - moved to test_4 */
}

/*
 * test_strings -- test syscalls with string arguments
 */
static void
test_strings(void)
{
	/* string args: 1 (open) */
	syscall(SYS_open, NON_EXIST_PATH_1, 0x102, 0x103, 0x104, 0x105, 0x106);

	/* string args: 2 (openat) */
	syscall(SYS_openat, 0x101, NON_EXIST_PATH_2, 0x103,
		0x104, 0x105, 0x106);

	/* string args: 1 2 (rename) */
	rename(NON_EXIST_PATH_1, NON_EXIST_PATH_2);

	/* string args: 1 2 (llistxattr) */
	llistxattr(NON_EXIST_PATH_2, NON_EXIST_PATH_1, 0x103);

	/* string args: 1 3 (symlinkat) */
	syscall(SYS_symlinkat, NON_EXIST_PATH_1, 0x102, NON_EXIST_PATH_2);

	/* string args: 2 4 (renameat) */
	syscall(SYS_renameat, 0x101, NON_EXIST_PATH_1, 0x103, NON_EXIST_PATH_2);

	/* string args: 1 2 3 (mount) */
	mount(NON_EXIST_PATH_1, NON_EXIST_PATH_2, "ext3", 0x101, (void *)0x102);

	/* string args: 1 2 3 (request_key) */
	syscall(SYS_request_key, "string1_type", "string2_description",
		"string3_callout_info", 0x104);

	/* string args: 3 (init_module) */
	syscall(SYS_init_module, 0x101, 0x102, NON_EXIST_PATH_1);

	/* string args: 4 (kexec_file_load) */
	syscall(SYS_kexec_file_load, 0x101, 0x102, 0x103, NON_EXIST_PATH_2,
		0x105);

	/* string args: 5 (fanotify_mark) */
	syscall(SYS_fanotify_mark, 0x101, 0x102, 0x103, 0x104,
		NON_EXIST_PATH_1);
}

/* testing signals */
static int Signalled;

/*
 * sig_user_handler -- SIGALARM signal handler.
 */
static void
sig_user_handler(int sig, siginfo_t *si, void *unused)
{
	(void) sig;
	(void) si;
	(void) unused;

	Signalled = 1;
}

/*
 * test_signal -- test the syscall 'sigaction'
 */
static void
test_signal(void)
{
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = sig_user_handler;
	sa.sa_flags = SA_RESTART | SA_RESETHAND;
	(void) sigaction(SIGUSR1, &sa, NULL);

	Signalled = 0;

	raise(SIGUSR1);

	while (Signalled == 0)
		sleep(1);
}

/*
 * test_0 -- test basic syscalls
 */
static void test_0(void)
{
	MARK_START();
	test_basic_syscalls();
	MARK_END();
}

/*
 * test_1 -- test basic syscalls with fork()
 */
static void test_1(void)
{
	syscall(SYS_fork);
	test_0();
}

/*
 * test_2 -- test unsupported syscalls
 */
static void test_2(void)
{
	MARK_START();
	test_unsupported_syscalls();
	MARK_END();
}

/*
 * test_3 -- test unsupported syscalls with fork()
 */
static void test_3(void)
{
	syscall(SYS_fork);
	test_2();
}

/*
 * test_4 -- test vfork()
 */
static void test_4(void)
{
	MARK_START();

	/*
	 * test if other syscalls are correctly detected,
	 * when vfork is present
	 */
	syscall(SYS_open, NON_EXIST_PATH_1, 0x101, 0x102, 0x103, 0x104, 0x105);
	syscall(SYS_close, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106);

	if (vfork() == 0) { /* vfork - handle child */
		execve(NON_EXIST_PATH_1, (char * const*)0x123456,
		       (char * const*)0x654321);
		_exit(1);
	}

	/*
	 * test if other syscalls are correctly detected,
	 * when vfork is present
	 */
	syscall(SYS_open, NON_EXIST_PATH_2, 0x102, 0x103, 0x104, 0x105, 0x106);
	syscall(SYS_close, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107);

	MARK_END();
}


/*
 * test_5 -- test basic syscalls after double fork()
 */
static void test_5(void)
{
	syscall(SYS_fork);
	test_1();
}

/*
 * test_6 -- test unsupported syscalls after double fork()
 */
static void test_6(void)
{
	syscall(SYS_fork);
	test_3();
}

/*
 * test_7 -- test the syscall 'signal'
 */
static void test_7(void)
{
	MARK_START();
	test_signal();
	MARK_END();
}

/*
 * test_8 -- test syscalls with string arguments
 */
static void test_8(void)
{
	MARK_START();
	test_strings();
	MARK_END();
}

/*
 * run_test -- array of tests
 */
static void (*run_test[])(void) = {
	test_0,
	test_1,
	test_2,
	test_3,
	test_4,
	test_5,
	test_6,
	test_7,
	test_8
};

int
main(int argc, char *argv[])
{
	int max = sizeof(run_test) / sizeof(run_test[0]) - 1;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <test-number: 0..%i>\n",
				argv[0], max);
		return -1;
	}

	int n = atoi(argv[1]);
	if (n > max) {
		fprintf(stderr, "Error: test number can take only following"
				" values: 0..%i (%i is not allowed)\n",
				max, n);
		return -1;
	}

	printf("Starting: test_%i ...\n", n);

	run_test[n]();

	printf("Done (test_%i)\n", n);
}
