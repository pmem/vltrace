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

set(TEST_APP "./test_basic")

set(TEST_DIR "${CMAKE_SOURCE_DIR}/test")

add_executable(test_basic test_basic.c)

#
# TESTS
#

#
# 1) tests using match and *.match files
#

add_test(NAME "[match]-basic"
	COMMAND ${TEST_DIR}/test-match ${TEST_APP} 0)

add_test(NAME "[match][fork]-basic"
	COMMAND ${TEST_DIR}/test-match ${TEST_APP} 1)

add_test(NAME "[match]-unsupported"
	COMMAND ${TEST_DIR}/test-match ${TEST_APP} 2)

add_test(NAME "[match][fork]-unsupported"
	COMMAND ${TEST_DIR}/test-match ${TEST_APP} 3)

add_test(NAME "[match]-vfork"
	COMMAND ${TEST_DIR}/test-match ${TEST_APP} 4)

add_test(NAME "[match]-umount"
	COMMAND ${TEST_DIR}/test-match ${TEST_APP} 5)

add_test(NAME "[match]-xattr"
	COMMAND ${TEST_DIR}/test-match ${TEST_APP} 6)

#
# 2) tests comparing strace.ebpf with system strace
#

# a) tests of the dedicated app

add_test(NAME "[strace]-basic"
	COMMAND ${TEST_DIR}/test-strace ${TEST_APP} 0)

add_test(NAME "[strace]-unsupported"
	COMMAND ${TEST_DIR}/test-strace ${TEST_APP} 2)

add_test(NAME "[strace]-vfork"
	COMMAND ${TEST_DIR}/test-strace ${TEST_APP} 4)

add_test(NAME "[strace]-umount"
	COMMAND ${TEST_DIR}/test-strace ${TEST_APP} 5)

add_test(NAME "[strace]-xattr"
	COMMAND ${TEST_DIR}/test-strace ${TEST_APP} 6)

# b) tests of system command with full path

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

	add_test(NAME "[strace]-${CMD}"
		COMMAND ${TEST_DIR}/test-strace ${PATH} ${ARGS})
endforeach(CMD)

# c) tests of system command without full path

add_test(NAME "[strace][no-path]-date"
	COMMAND ${TEST_DIR}/test-strace date)

add_test(NAME "[strace][no-path]-clear"
	COMMAND ${TEST_DIR}/test-strace clear)

add_test(NAME "[strace][no-path]-ls"
	COMMAND ${TEST_DIR}/test-strace ls)
