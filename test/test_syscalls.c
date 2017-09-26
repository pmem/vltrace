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

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <utime.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/xattr.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/select.h>
#include <sys/swap.h>
#include <sys/sendfile.h>

#include <linux/futex.h>
#include <linux/fs.h>
#include <linux/falloc.h>

#include "../src/syscalls_numbers.h"

#define F_ADD_SEALS		1033
#define F_GET_SEALS		1034
#define ANY_STR			"any string"

#define PATTERN_START		((int)0x12345678)
#define PATTERN_END		((int)0x87654321)
#define BUF_SIZE		0x100

#define MARK_START()		close(PATTERN_START)
#define MARK_END()		close(PATTERN_END)

#define FILE_EXIST		"/etc/fstab"
#define FILE_CREATE		"/tmp/tmp vltrace"

#define NON_EXIST_PATH_1	"111 non exist"
#define NON_EXIST_PATH_2	"222 non exist"

/* used to test all flags set */
#define FLAGS_SET		0x0FFFFFFFFFFFFFFF

#define STRING_10		"1234567890"
#define STRING_30 		STRING_10 STRING_10 STRING_10
#define STRING_60 		STRING_30 STRING_30
#define STRING_120		STRING_60 STRING_60
#define STRING_420		STRING_120 STRING_120 STRING_120 STRING_60
#define STRING_840		STRING_420 STRING_420
#define STRING_1260		STRING_420 STRING_420 STRING_420

#define STRING_126_1		"START 111 "STRING_10" 111 END"
#define STRING_126_2		"START 222 "STRING_10" 222 END"
#define STRING_126_3		"START 333 "STRING_10" 333 END"

#define STRING_382_1		"START 111 "STRING_120" 111 END"
#define STRING_382_2		"START 222 "STRING_120" 222 END"
#define STRING_382_3		"START 333 "STRING_120" 333 END"

#define STRING_765_1		"START 111 "STRING_420" 111 END"
#define STRING_765_2		"START 222 "STRING_420" 222 END"
#define STRING_765_3		"START 333 "STRING_420" 333 END"

#define STRING_1148_1		"START 111 "STRING_840" 111 END"
#define STRING_1148_2		"START 222 "STRING_840" 222 END"
#define STRING_1148_3		"START 333 "STRING_840" 333 END"

#define STRING_1531_1		"START 111 "STRING_1260" 111 END"
#define STRING_1531_2		"START 222 "STRING_1260" 222 END"
#define STRING_1531_3		"START 333 "STRING_1260" 333 END"

static char *strings[5][3] = {
	{
		STRING_126_1,
		STRING_126_2,
		STRING_126_3,
	},
	{
		STRING_382_1,
		STRING_382_2,
		STRING_382_3,
	},
	{
		STRING_765_1,
		STRING_765_2,
		STRING_765_3,
	},
	{
		STRING_1148_1,
		STRING_1148_2,
		STRING_1148_3,
	},
	{
		STRING_1531_1,
		STRING_1531_2,
		STRING_1531_3,
	},
};

#define N_ITERATIONS		1000000
static int counter;

/*
 * s -- busy wait for a while
 */
static void
s()
{
	for (int i = 0; i < N_ITERATIONS; i++)
		counter += rand();
}

/*
 * test_basic_syscalls -- test basic syscalls
 */
static void
test_basic_syscalls(void)
{
	char buffer[BUF_SIZE];
	struct utsname name;
	struct stat buf;
	int fd;

	/* PART #1 - real arguments */

s();
	fd = open(FILE_EXIST, O_RDONLY);
s();
	close(fd);

s();
	fd = open(FILE_CREATE, O_RDWR | O_CREAT, 0666);
s();
	(void) write(fd, buffer, BUF_SIZE);
s();
	(void) lseek(fd, 0, SEEK_SET);
s();
	(void) read(fd, buffer, BUF_SIZE);
s();
	(void) fstat(fd, &buf);
s();
	close(fd);
s();
	(void) unlink(FILE_CREATE);

s();
	(void) execve(FILE_CREATE, (char * const *)0x123456,
			(char * const *)0x654321);

s();
	(void) stat(FILE_EXIST, &buf);
s();
	(void) lstat(FILE_EXIST, &buf);

s();
	(void) uname(&name);

s();
	(void) syscall(SYS_getpid); /* getpid */
s();
	(void) syscall(SYS_gettid); /* gettid */

	/* PART #2 - test arguments */

s();
	(void) write(0x101, buffer, 1);
s();
	(void) read(0x102, buffer, 2);
s();
	(void) lseek(0x103, 3, SEEK_END);
s();
	(void) fstat(0x104, &buf);
s();
	(void) syscall(SYS_futex, 1, FUTEX_WAKE_OP, 3, 4, 5, FLAGS_SET);
s();
}

/*
 * test_unsupported_syscalls -- test unsupported syscalls
 */
static void
test_unsupported_syscalls(void)
{
	char buf[BUF_SIZE];

s();
	(void) chroot(NON_EXIST_PATH_1);

	/* fcntl - unsupported flags */
s();
	(void) syscall(SYS_fcntl, 0x104, FLAGS_SET, FLAGS_SET, 0x105, 0x106,
			0x107);

s();
	(void) flock(0x108, 0x109);

s();
	(void) setsockopt(0x101, 0x102, 0x103, (void *)0x104, (socklen_t)0x105);
s();
	(void) getsockopt(0x106, 0x107, 0x108, (void *)0x109,
				(socklen_t *)0x110);
s();
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	(void) getsockname(0x101, &addr, &addrlen);
s();
	(void) inotify_add_watch(0x104, NON_EXIST_PATH_1, 0x105);
s();
	(void) inotify_rm_watch(0x106, 0x107);

s();
	(void) syscall(SYS_io_cancel, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106);
s();
	(void) syscall(SYS_io_destroy, 0x102, 0x103, 0x104, 0x105, 0x106,
			0x107);
s();
	(void) syscall(SYS_io_getevents, 0x103, 0x104, 0x105, 0x106, 0x107,
			0x108);
s();
	(void) syscall(SYS_io_setup, 0x104, 0x105, 0x106, 0x107, 0x108, 0x109);
s();
	(void) syscall(SYS_io_submit, 0x105, 0x106, 0x107, 0x108, 0x109, 0x110);

s();
	(void) syscall(SYS_ioctl, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106);

s();
	(void) mknod(FILE_EXIST, 0x101, 0x102);
s();
	(void) mknodat(0x103, FILE_EXIST, 0x104, 0x105);

s();
	(void) mmap((void *)0x101, 0x102, 0x103, 0xFFFF, 0x105, 0x106);
s();
	(void) munmap((void *)0x102, 0x103);

	struct timeval time1;
	struct timespec time2;
	memset(&time1, 0, sizeof(time1));
	memset(&time2, 0, sizeof(time2));

s();
	(void) select(0, (fd_set *)0x104, (fd_set *)0x105, (fd_set *)0x106,
			&time1);
s();
	(void) pselect(0, (fd_set *)0x105, (fd_set *)0x106, (fd_set *)0x107,
			&time2, (const sigset_t *)0x108);

s();
	(void) swapon(NON_EXIST_PATH_1, 0x101);
s();
	(void) swapoff(NON_EXIST_PATH_2);

s();
	(void) syscall(SYS_poll, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107);

s();
	(void) mount(NON_EXIST_PATH_1, NON_EXIST_PATH_2, "ext3", 0x101,
			(void *)0x102);
s();
	(void) umount(NON_EXIST_PATH_1);
s();
	(void) umount2(NON_EXIST_PATH_2, 0x123);

s();
	(void) setxattr(NON_EXIST_PATH_1, ANY_STR, buf, BUF_SIZE, XATTR_CREATE);
s();
	(void) lsetxattr(NON_EXIST_PATH_2, ANY_STR, buf, BUF_SIZE,
				XATTR_CREATE);
s();
	(void) fsetxattr(0x107, ANY_STR, buf, BUF_SIZE, XATTR_CREATE);

s();
	(void) getxattr(NON_EXIST_PATH_1, ANY_STR, buf, BUF_SIZE);
s();
	(void) lgetxattr(NON_EXIST_PATH_2, ANY_STR, buf, BUF_SIZE);
s();
	(void) fgetxattr(0x105, ANY_STR, buf, BUF_SIZE);

s();
	(void) listxattr(NON_EXIST_PATH_1, ANY_STR, 0x101);
s();
	(void) llistxattr(NON_EXIST_PATH_2, ANY_STR, 0x102);
s();
	(void) flistxattr(0x103, ANY_STR, 0x104);

s();
	(void) removexattr(NON_EXIST_PATH_1, ANY_STR);
s();
	(void) lremovexattr(NON_EXIST_PATH_2, ANY_STR);
s();
	(void) fremovexattr(0x101, ANY_STR);

s();
	(void) syscall(SYS_ppoll, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106);

s();
	(void) epoll_ctl(0x101, 0x102, 0x103, (struct epoll_event *)0x104);
s();
	(void) epoll_wait(0x102, (struct epoll_event *)0x103, 0x104, 0x105);
s();
	(void) epoll_pwait(0x103, (struct epoll_event *)0x104, 0x105, 0x106,
			(const sigset_t *)0x107);

	/* open - unsupported flags */
s();
	(void) syscall(SYS_open, NON_EXIST_PATH_2, FLAGS_SET, FLAGS_SET,
			FLAGS_SET, FLAGS_SET, FLAGS_SET);

	/* clone - unsupported flags */
s();
	(void) syscall(SYS_clone, FLAGS_SET, FLAGS_SET, FLAGS_SET, FLAGS_SET,
			FLAGS_SET, FLAGS_SET);

	/* vfork - moved to test_4 */
}

/*
 * test_strings -- test syscalls with string arguments
 */
static void
test_strings(char *string[3])
{
	/* string args: 1 (open) */
s();
	(void) syscall(SYS_open, string[0], 0x102, 0x103, 0x104, 0x105, 0x106);

	/* string args: 2 (openat) */
s();
	(void) syscall(SYS_openat, 0x101, string[1], 0x103, 0x104, 0x105,
			0x106);

	/* string args: 1 2 (rename) */
s();
	(void) rename(string[0], string[1]);

	/* string args: 1 2 (llistxattr) */
s();
	(void) llistxattr(string[1], string[0], 0x103);

	/* string args: 1 3 (symlinkat) */
s();
	(void) syscall(SYS_symlinkat, string[0], 0x102, string[1]);

	/* string args: 2 4 (renameat) */
s();
	(void) syscall(SYS_renameat, 0x101, string[0], 0x103, string[1]);

	/* string args: 1 2 3 (mount) */
s();
	(void) mount(string[0], string[1], string[2], 0x101, (void *)0x102);

	/* string args: 1 2 3 (request_key) */
s();
	(void) syscall(SYS_request_key, string[0], string[1], string[2], 0x104);

	/* string args: 3 (init_module) */
s();
	(void) syscall(SYS_init_module, 0x101, 0x102, string[0]);

	/* string args: 4 (kexec_file_load) */
s();
	(void) syscall(SYS_kexec_file_load, 0x101, 0x102, 0x103, string[1],
			0x105);

	/* string args: 5 (fanotify_mark) */
s();
	(void) syscall(SYS_fanotify_mark, 0x101, 0x102, 0x103, 0x104,
			string[0]);
s();
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

	(void) raise(SIGUSR1);

	while (Signalled == 0)
		sleep(1);
}

/*
 * test_0 -- test basic syscalls
 */
static void test_0(char *a, char *b, char *c)
{
	MARK_START();
	test_basic_syscalls();
	MARK_END();
}

/*
 * test_1 -- test basic syscalls with fork()
 */
static void test_1(char *a, char *b, char *c)
{
	if (syscall(SYS_fork) == -1) {
		perror("fork");
		exit(-1);
	}
	test_0(a, b, c);
}

/*
 * test_2 -- test unsupported syscalls
 */
static void test_2(char *a, char *b, char *c)
{
	MARK_START();
	test_unsupported_syscalls();
	MARK_END();
}

/*
 * test_3 -- test unsupported syscalls with fork()
 */
static void test_3(char *a, char *b, char *c)
{
	if (syscall(SYS_fork) == -1) {
		perror("fork");
		exit(-1);
	}
	test_2(a, b, c);
}

/*
 * test_4 -- test vfork()
 */
static void test_4(char *a, char *b, char *c)
{
	MARK_START();

	/*
	 * test if other syscalls are correctly detected,
	 * when vfork is present
	 */
s();
	(void) syscall(SYS_open, NON_EXIST_PATH_1, 0x101, 0x102, 0x103, 0x104,
			0x105);
s();
	(void) syscall(SYS_close, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106);

s();
	switch (vfork()) {
	case 0: /* handle child */
		(void) execve(NON_EXIST_PATH_1, (char * const *)0x123456,
					(char * const *)0x654321);
		_exit(1);
	case -1:
		perror("vfork");
		exit(-1);
	}

	/*
	 * test if other syscalls are correctly detected,
	 * when vfork is present
	 */
s();
	(void) syscall(SYS_open, NON_EXIST_PATH_2, 0x102, 0x103, 0x104, 0x105,
			0x106);
s();
	(void) syscall(SYS_close, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107);
s();

	MARK_END();
}


/*
 * test_5 -- test basic syscalls after double fork()
 */
static void test_5(char *a, char *b, char *c)
{
	if (syscall(SYS_fork) == -1) {
		perror("fork");
		exit(-1);
	}
	test_1(a, b, c);
}

/*
 * test_6 -- test unsupported syscalls after double fork()
 */
static void test_6(char *a, char *b, char *c)
{
	if (syscall(SYS_fork) == -1) {
		perror("fork");
		exit(-1);
	}
	test_3(a, b, c);
}

/*
 * test_7 -- test the syscall 'signal'
 */
static void test_7(char *a, char *b, char *c)
{
	MARK_START();
	test_signal();
	MARK_END();
}

/*
 * test_8 -- test syscalls with string arguments of length < 126
 */
static void test_8(char *a, char *b, char *c)
{
	MARK_START();
	test_strings(strings[0]);
	MARK_END();
}

/*
 * test_9 -- test syscalls with string arguments of length < 382
 */
static void test_9(char *a, char *b, char *c)
{
	MARK_START();
	test_strings(strings[1]);
	MARK_END();
}

/*
 * test_10 -- test syscalls with string arguments of length < 765
 */
static void test_10(char *a, char *b, char *c)
{
	MARK_START();
	test_strings(strings[2]);
	MARK_END();
}

/*
 * test_11 -- test syscalls with string arguments of length < 1148
 */
static void test_11(char *a, char *b, char *c)
{
	MARK_START();
	test_strings(strings[3]);
	MARK_END();
}

/*
 * test_12 -- test syscalls with string arguments of length < 1531
 */
static void test_12(char *a, char *b, char *c)
{
	MARK_START();
	test_strings(strings[4]);
	MARK_END();
}

/*
 * test_13 -- test syscalls with string arguments of length < 1531
 *            with single fork
 */
static void test_13(char *a, char *b, char *c)
{
	if (syscall(SYS_fork) == -1) {
		perror("fork");
		exit(-1);
	}
	test_12(a, b, c);
}

/*
 * test_14 -- test syscalls with string arguments of length < 1531
 *            with double fork
 */
static void test_14(char *a, char *b, char *c)
{
	if (syscall(SYS_fork) == -1) {
		perror("fork");
		exit(-1);
	}
	test_13(a, b, c);
}

/*
 * run_test -- array of tests
 */
static void (*run_test[])(char *, char *, char *) = {
	test_0,
	test_1,
	test_2,
	test_3,
	test_4,
	test_5,
	test_6,
	test_7,
	test_8,
	test_9,
	test_10,
	test_11,
	test_12,
	test_13,
	test_14
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
		fprintf(stderr,
			"Error: test number can take only following values: 0..%i (%i is not allowed)\n",
			max, n);
		return -1;
	}

	printf("Starting: test_%i ...\n", n);

	run_test[n](argc > 2 ? argv[2] : NULL,
			argc > 3 ? argv[3] : NULL,
			argc > 4 ? argv[4] : NULL);

	printf("Done (test_%i)\n", n);
}
