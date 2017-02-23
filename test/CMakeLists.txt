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

set(TEST_DIR "${CMAKE_SOURCE_DIR}/test")

add_executable(test_basic test_basic.c)

add_test(NAME "basic-match"
	COMMAND ${TEST_DIR}/test-match 0)

add_test(NAME "basic-strace"
	COMMAND ${TEST_DIR}/test-trace-command ./test_basic 0)

add_test(NAME "basic-match-FORK"
	COMMAND ${TEST_DIR}/test-match 1)

add_test(NAME "unsupported-match"
	COMMAND ${TEST_DIR}/test-match 2)

add_test(NAME "unsupported-strace"
	COMMAND ${TEST_DIR}/test-trace-command ./test_basic 2)

add_test(NAME "unsupported-match-FORK"
	COMMAND ${TEST_DIR}/test-match 3)

add_test(NAME "execve-match"
	COMMAND ${TEST_DIR}/test-match 4)

add_test(NAME "execve-strace"
	COMMAND ${TEST_DIR}/test-trace-command ./test_basic 4)

add_test(NAME "umount-match"
	COMMAND ${TEST_DIR}/test-match 5)

add_test(NAME "umount-strace"
	COMMAND ${TEST_DIR}/test-trace-command ./test_basic 5)

add_test(NAME "xattr-match"
	COMMAND ${TEST_DIR}/test-match 6)

add_test(NAME "xattr-strace"
	COMMAND ${TEST_DIR}/test-trace-command ./test_basic 6)

foreach(CMD date clear ls ping cat dir du uname free df)
	execute_process(COMMAND which ${CMD}
			OUTPUT_VARIABLE PATH
			OUTPUT_STRIP_TRAILING_WHITESPACE)
	if (${CMD} STREQUAL ping)
		set(ARGS "-c1 127.0.0.1")
	elseif (${CMD} STREQUAL cat)
		set(ARGS "/etc/fstab")
	elseif (${CMD} STREQUAL du)
		set(ARGS "Makefile")
	else ()
		unset(ARGS)
	endif ()

	add_test(NAME ${CMD}
		COMMAND ${TEST_DIR}/test-trace-command ${PATH} ${ARGS})
endforeach(CMD)
