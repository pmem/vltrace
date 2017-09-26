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
 * bench_sc.c -- testing benchmark for vltrace. This simple benchmark
 *               allow us to measure and compare different tracing tools.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

typedef void (*tx_t)();

/*
 * open_close -- tested usecase itself
 */
static void
open_close()
{
	int fd;
	int x;

	fd = open("/dev/null", O_RDONLY);
	if (fd == -1) {
		perror("open");
		exit(-1);
	}
	x = read(fd, &x, sizeof(x));
	x = write(fd, &x, sizeof(x));
	(void) close(fd);
}

/*
 * loop_tx -- run and measure tested usecase
 */
static void
loop_tx(char *name, tx_t tx_f, uint64_t qty, FILE *f)
{
	uint64_t i, tu_start, tu_end, delta;
	struct timeval tv_start, tv_end;

	if (qty == 0)
		return;

	gettimeofday(&tv_start, NULL);

	for (i = 0; i < qty; i++)
		tx_f();

	gettimeofday(&tv_end, NULL);

	if (f == NULL)
		return;

	tu_start = tv_start.tv_sec * 1000000 + tv_start.tv_usec;
	tu_end = tv_end.tv_sec * 1000000 + tv_end.tv_usec;

	delta = (tu_end - tu_start);
	delta *= 1000;

	fprintf(stderr, "%s: iteration time: %ld nsec\n", name,  delta / qty);
}

int
main(int argc, char *argv[])
{
	uint64_t iters_qty;

	if (argc != 2) {
		printf("Usage: %s <number-of-iterations>\n", argv[0]);
		printf("\t <number-of-iterations> must be greater than 0\n");
		return 1;
	}

	iters_qty = atol(argv[1]);
	if (iters_qty <= 0) {
		printf("Error: number of iterations must be greater than 0\n");
		return 1;
	}

	/* WARM-UP */
	loop_tx("open_read_write_close",
			open_close,  iters_qty / 10, NULL);
	loop_tx(">>> open_read_write_close ",
			open_close,  iters_qty, stderr);

	return 0;
}
