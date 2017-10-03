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
project(vltrace C)

set(VERSION_MAJOR 0)
set(VERSION_MINOR 1)
set(VERSION_PATCH 0)
set(VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})

set(CMAKE_C_STANDARD 99)
set(VLTRACE_MINIMUM_KERNEL_VERSION "4.7")

include(GNUInstallDirs)
include(CheckCCompilerFlag)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${PROJECT_BINARY_DIR}")
	message(SEND_ERROR "In-source builds are not allowed.")
endif ()

if (NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Release")
endif ()

# generate headers
set(GENERATE_HEADER ${PROJECT_SOURCE_DIR}/utils/generate_headers.sh)
execute_process(COMMAND ${GENERATE_HEADER}
		RESULT_VARIABLE KERNEL_HEADER)
if (NOT ${KERNEL_HEADER} EQUAL 0)
	message(FATAL_ERROR "ERROR: missing kernel header. Aborting...")
endif ()
add_custom_target(syscalls_64 ALL ${GENERATE_HEADER} make)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in
		${CMAKE_CURRENT_BINARY_DIR}/src/config.h)

# Checks whether flag is supported by current C compiler and appends
# it to the relevant cmake variable.
# 1st argument is a flag
# 2nd (optional) argument is a build type (debug, release, relwithdebinfo)
macro(add_c_flag flag)
	string(REPLACE - _ flag2 ${flag})
	string(REPLACE " " _ flag2 ${flag2})
	string(REPLACE = "_" flag2 ${flag2})
	set(check_name "C_HAS_${flag2}")

	check_c_compiler_flag("${flag}" "${check_name}")

	if (${${check_name}})
		if (${ARGC} EQUAL 1)
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${flag}")
		else()
			set(CMAKE_C_FLAGS_${ARGV1} "${CMAKE_C_FLAGS_${ARGV1}} ${flag}")
		endif()
	endif()
endmacro()

# Generates cstyle-$name target and attaches it as a dependency of global
# "cstyle" target. This target verifies C style of files in current source dir.
# If more arguments are used, then they are used as files to be checked
# instead.
# ${name} must be unique.
function(add_cstyle name)
	if(${ARGC} EQUAL 1)
		add_custom_target(cstyle-${name}
			COMMAND ${PERL_EXECUTABLE}
				${CMAKE_SOURCE_DIR}/utils/cstyle
				${CMAKE_CURRENT_SOURCE_DIR}/*.c
				${CMAKE_CURRENT_SOURCE_DIR}/*.h)
	else()
		add_custom_target(cstyle-${name}
			COMMAND ${PERL_EXECUTABLE}
				${CMAKE_SOURCE_DIR}/utils/cstyle ${ARGN})
	endif()
	add_dependencies(cstyle cstyle-${name})
endfunction()

# Generates check-whitespace-$name target and attaches it as a dependency
# of global "check-whitespace" target. This target verifies C files in current
# source dir do not have any whitespace errors.
# If more arguments are used, then they are used as files to be checked
# instead.
# ${name} must be unique.
function(add_check_whitespace name)
	if(${ARGC} EQUAL 1)
		add_custom_target(check-whitespace-${name}
			COMMAND ${PERL_EXECUTABLE}
				${CMAKE_SOURCE_DIR}/utils/check_whitespace
				${CMAKE_CURRENT_SOURCE_DIR}/*.c
				${CMAKE_CURRENT_SOURCE_DIR}/*.h)
	else()
		add_custom_target(check-whitespace-${name}
			COMMAND ${PERL_EXECUTABLE}
				${CMAKE_SOURCE_DIR}/utils/check_whitespace ${ARGN})
	endif()
	add_dependencies(check-whitespace check-whitespace-${name})
endfunction()

# DEBUG configuration
add_c_flag(-ggdb DEBUG)
add_c_flag(-DDEBUG DEBUG)

# RelWithDebInfo configuration
add_c_flag(-ggdb RELWITHDEBINFO)
add_c_flag(-fno-omit-frame-pointer RELWITHDEBINFO)

add_executable(check_license EXCLUDE_FROM_ALL utils/check_license/check-license.c)
add_executable(bench_sc EXCLUDE_FROM_ALL tools/bench_sc/bench_sc.c)

add_custom_target(checkers ALL)
add_custom_target(cstyle)
add_custom_target(check-whitespace)
add_custom_target(check-license
	COMMAND ${CMAKE_SOURCE_DIR}/utils/check_license/check-headers.sh
		${CMAKE_SOURCE_DIR}
		${CMAKE_BINARY_DIR}/check_license
		${CMAKE_SOURCE_DIR}/LICENSE
		-a)
add_custom_target(check-whitespace-main
	COMMAND ${PERL_EXECUTABLE}
		${CMAKE_SOURCE_DIR}/utils/check_whitespace
		${CMAKE_SOURCE_DIR}/utils/check_license/*.sh
		${CMAKE_SOURCE_DIR}/utils/*.sh
		${CMAKE_SOURCE_DIR}/README.md
		${CMAKE_SOURCE_DIR}/*.spec
		${CMAKE_SOURCE_DIR}/debian/*
		${CMAKE_SOURCE_DIR}/debian/*/*
		${CMAKE_SOURCE_DIR}/doc/*.md)
add_dependencies(check-license check_license)
add_dependencies(check-whitespace check-whitespace-main)

add_cstyle(check_license ${CMAKE_SOURCE_DIR}/utils/check_license/*.c)
add_check_whitespace(check_license ${CMAKE_SOURCE_DIR}/utils/check_license/*.c)

option(DEVELOPER_MODE "enable developer checks" OFF)
if(DEVELOPER_MODE)
	add_dependencies(checkers cstyle)
	add_dependencies(checkers check-whitespace)
	add_dependencies(checkers check-license)
endif(DEVELOPER_MODE)

enable_testing()
add_subdirectory(test)
add_subdirectory(src)
add_subdirectory(man)

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
	IMMEDIATE @ONLY)

add_custom_target(uninstall
	COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
