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

add_cstyle(src)

find_package(PkgConfig)
pkg_check_modules(LIBBCC REQUIRED libbcc)

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

include_directories(${PROJECT_BINARY_DIR}/..)
include_directories(${LIBBCC_INCLUDE_DIRS})

link_directories(nondebug)
link_directories(${LIBBCC_LIBRARY_DIRS})

add_executable(vltrace ${SOURCES})

add_subdirectory(ebpf)

target_link_libraries(vltrace ebpf ${LIBBCC_LIBRARIES})

install(TARGETS vltrace
	CONFIGURATIONS Release RelWithDebInfo Debug None
	DESTINATION ${CMAKE_INSTALL_BINDIR}
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
