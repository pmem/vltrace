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

# read required kernel version from README.md
set(README_FILE "README.md")
execute_process(COMMAND utils/get-required-kernel.sh ${README_FILE}
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		OUTPUT_VARIABLE STRACE_EBPF_MINIMUM_KERNEL_VERSION
		OUTPUT_STRIP_TRAILING_WHITESPACE
		RESULT_VARIABLE KERNEL_RESULT)

if (NOT ${KERNEL_RESULT} EQUAL 0)
	execute_process(COMMAND echo "${STRACE_EBPF_MINIMUM_KERNEL_VERSION}")
	message(FATAL_ERROR
		"Error: cannot read required kernel version from the file ${README_FILE}")
endif ()

include(GNUInstallDirs)

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
	IMMEDIATE @ONLY)

add_custom_target(uninstall
	COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

# read ChangeLog and parse the version
FILE (READ "${CMAKE_CURRENT_SOURCE_DIR}/ChangeLog" CHANGELOG)

STRING (REGEX MATCH "([0-9]+)\\.([0-9]+)" FULLVERSION "${CHANGELOG}")

set(STRACE_EBPF_VERSION_MAJOR ${CMAKE_MATCH_1} CACHE INTERNAL "Major." FORCE)
set(STRACE_EBPF_VERSION_MINOR ${CMAKE_MATCH_2} CACHE INTERNAL "Minor." FORCE)
set(STRACE_EBPF_VERSION
	${STRACE_EBPF_VERSION_MAJOR}.${STRACE_EBPF_VERSION_MINOR} CACHE INTERNAL
	"Version." FORCE)

set(CMAKE_C_STANDARD 99)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in
	${CMAKE_CURRENT_BINARY_DIR}/src/config.h)

add_custom_target(cstyle
	COMMAND perl ${PROJECT_SOURCE_DIR}/utils/cstyle
	-pP ${PROJECT_SOURCE_DIR}/src/*.h
	${PROJECT_SOURCE_DIR}/src/*.c)

add_custom_target(check_whitespace
	COMMAND perl ${PROJECT_SOURCE_DIR}/utils/check_whitespace
	-r ${PROJECT_SOURCE_DIR}/src)

add_executable(check_license_executable utils/check_license/check-license.c)
set_property(TARGET check_license_executable PROPERTY C_STANDARD 99)
set_property(TARGET check_license_executable PROPERTY
	RUNTIME_OUTPUT_DIRECTORY
	${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY})

add_custom_target(check-license
	COMMAND
	${PROJECT_SOURCE_DIR}/utils/check_license/check-headers.sh
	${PROJECT_SOURCE_DIR}
	$<TARGET_FILE:check_license_executable>
	${PROJECT_SOURCE_DIR}/LICENSE -a)

add_dependencies(check-license check_license_executable)

enable_testing()
add_subdirectory(test)
add_subdirectory(src)
add_subdirectory(utils)
add_subdirectory(man)
