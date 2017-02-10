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
project(strace.ebpf)

# read ChangeLog and parse the version
FILE (READ "${CMAKE_CURRENT_SOURCE_DIR}/ChangeLog" CHANGELOG)

STRING (REGEX MATCH "([0-9]+)\\.([0-9]+)" FULLVERSION "${CHANGELOG}")

set(STRACE_EBPF_VERSION_MAJOR ${CMAKE_MATCH_1} CACHE INTERNAL "Major." FORCE)
set(STRACE_EBPF_VERSION_MINOR ${CMAKE_MATCH_2} CACHE INTERNAL "Minor." FORCE)
set(STRACE_EBPF_VERSION
	${STRACE_EBPF_VERSION_MAJOR}.${STRACE_EBPF_VERSION_MINOR} CACHE INTERNAL
	"Version." FORCE)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in
	${CMAKE_CURRENT_BINARY_DIR}/src/config.h)

add_subdirectory(doc)
add_subdirectory(gtest)
add_subdirectory(man)
add_subdirectory(src)
add_subdirectory(utils)
