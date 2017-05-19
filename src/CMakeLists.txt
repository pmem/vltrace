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

cmake_minimum_required(VERSION 2.8.7)
project(vltrace.exe C)

execute_process(COMMAND ../utils/copy_syscalls_64.sh
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		RESULT_VARIABLE KERNEL_HEADER)

if (NOT ${KERNEL_HEADER} EQUAL 0)
	message( FATAL_ERROR "ERROR: missing kernel header. Aborting..." )
endif ()

add_custom_target(syscalls_64 ALL ../utils/copy_syscalls_64.sh make
                  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

# .txt sources
set (TXT_SRCS
	help_text.txt
	usage_text.txt)

set(TXT_OBJS "")
foreach(FILE_SRC ${TXT_SRCS})
	get_filename_component(FILENAME ${FILE_SRC} NAME)
	get_filename_component(FILEPATH ${FILE_SRC} PATH)
	add_custom_command(OUTPUT
			${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/${FILENAME}.o
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/${FILEPATH}
		COMMAND ${CMAKE_LINKER} -r -b binary
		-o ${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/${FILENAME}.o
			${FILENAME})
	list(APPEND TXT_OBJS
		${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/${FILENAME}.o)
	#message(STATUS "Linking ${FILE_SRC}")
endforeach(FILE_SRC)

find_package(PkgConfig)
pkg_check_modules(LIBBCC REQUIRED libbcc)

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

link_directories(nondebug)
include_directories(compat)
include_directories(${LIBBCC_INCLUDE_DIRS})
link_directories(${LIBBCC_LIBRARY_DIRS})

add_executable(vltrace ${SOURCES} ${TXT_OBJS})

# XXX libbcc expects multi-treading safety. Currently it's required for
# print_event_cb.o only, although we will apply it for overall application.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
# using Clang
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-initializer-overrides")
else()
# using GCC
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-override-init")
endif()

add_subdirectory(ebpf)

target_link_libraries(vltrace ebpf ${LIBBCC_LIBRARIES})

install(TARGETS vltrace
        CONFIGURATIONS Release RelWithDebInfo Debug None
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
