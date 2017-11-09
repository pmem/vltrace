#
# Copyright 2017, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

project(vltrace C)

include(CheckCSourceRuns)

add_cstyle(src)

find_package(PkgConfig)

if(PKG_CONFIG_FOUND)
	pkg_check_modules(LIBBCC REQUIRED libbcc)
else()
	find_package(LIBBCC REQUIRED)
endif()

if(LIBBCC_FOUND)
	set(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES} -lbcc")

	CHECK_C_SOURCE_RUNS("
#include <stdint.h>
#include <unistd.h>
#include <bcc/perf_reader.h>
int check_API(void)
{
	/* check API of bpf_open_perf_buffer() */
	perf_reader_raw_cb raw_cb;
	perf_reader_lost_cb lost_cb;
	void *cb_cookie;
	int pid, cpu, page_cnt;
	void *buff = bpf_open_perf_buffer(raw_cb, lost_cb, cb_cookie,
						pid, cpu, page_cnt);
	/* check API of bpf_prog_load() */
	enum bpf_prog_type prog_type;
	const struct bpf_insn *insns;
	int insn_len;
	const char *license;
	unsigned kern_version;
	char *log_buf;
	unsigned log_buf_size;
	int fd = bpf_prog_load(prog_type, insns, insn_len, license,
				kern_version, log_buf, log_buf_size);
	return 0;
}
int main(void)
{
	return 0;
}
	" LIBBCC_RIGHT_VERSION)

	if(NOT LIBBCC_RIGHT_VERSION)
		message(FATAL_ERROR "libbcc v0.3.0-150-g3263805 or later is required")
	endif()
endif()

add_c_flag(-D_GNU_SOURCE)
add_c_flag(-Wextra)

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
	# using Clang
	add_c_flag(-Wno-initializer-overrides)
else()
	# using GCC
	add_c_flag(-Wno-override-init)
endif()

set(SOURCES
	vltrace.c
	txt.c
	cl_parser.c
	bpf_ctx.c
	utils.c
	attach_probes.c
	ebpf_syscalls.c
	generate_ebpf.c
	print_event_cb.c)

include_directories(${PROJECT_BINARY_DIR})
include_directories(${PROJECT_BINARY_DIR}/..)
include_directories(${LIBBCC_INCLUDE_DIRS})

link_directories(${LIBBCC_LIBRARY_DIRS})

add_executable(vltrace ${SOURCES})

add_subdirectory(ebpf)

target_link_libraries(vltrace ebpf ${LIBBCC_LIBRARIES})

install(TARGETS vltrace
	CONFIGURATIONS Release RelWithDebInfo Debug None
	DESTINATION ${CMAKE_INSTALL_BINDIR}
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
