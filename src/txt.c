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
 * txt.c -- text messages
 */

#include <assert.h>

#include "txt.h"

/*
 * fprint_usage -- print usage message
 */
void
fprint_usage(FILE *f)
{
	size_t fw_res;

	fw_res = fwrite(_binary_usage_text_txt_start,
			(size_t)_binary_usage_text_txt_size, 1, f);

	assert(fw_res > 0);
	(void) fw_res;

	fflush(f);
}

/*
 * fprint_help -- print help message
 */
void
fprint_help(FILE *f)
{
	size_t fw_res;

	fprint_usage(f);

	fw_res = fwrite("\n", 1, 1, f);

	assert(fw_res > 0);
	(void) fw_res;

	fw_res = fwrite(_binary_help_text_txt_start,
			(size_t)_binary_help_text_txt_size, 1, f);

	assert(fw_res > 0);
	(void) fw_res;

	fflush(f);
}
