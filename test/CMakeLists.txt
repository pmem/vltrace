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

add_c_flag(-Wno-unused-result)
include_directories(${PROJECT_BINARY_DIR})
add_executable(test_syscalls test_syscalls.c)

# check if the running kernel meets version requirements
execute_process(COMMAND utils/check-kernel.sh ${VLTRACE_MINIMUM_KERNEL_VERSION}
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		RESULT_VARIABLE VLTRACE_KERNEL_OK)

add_cstyle(test)

if (NOT ${VLTRACE_KERNEL_OK} EQUAL 0)
	message( WARNING "Tests skipped (required kernel >= ${VLTRACE_MINIMUM_KERNEL_VERSION})" )
else ()

	# running kernel meets version requirements, so we can add tests
	set(TEST_APP "./test_syscalls")
	set(TEST_DIR "${CMAKE_SOURCE_DIR}/test")

	#
	# TESTS
	#
	foreach(STR_LEN 126 382)
		# 1
		add_test(NAME "${STR_LEN}-basic-syscalls"
			COMMAND ${TEST_DIR}/test-match ${TEST_APP} 0 ${STR_LEN})

		# 2
		add_test(NAME "${STR_LEN}-basic-syscalls-with-fork"
			COMMAND ${TEST_DIR}/test-match -f ${TEST_APP} 1 ${STR_LEN})

		# 3
		add_test(NAME "${STR_LEN}-basic-syscalls-with-double-fork"
			COMMAND ${TEST_DIR}/test-match -f ${TEST_APP} 5 ${STR_LEN})

		# 4
		add_test(NAME "${STR_LEN}-unsupported-syscalls"
			COMMAND ${TEST_DIR}/test-match ${TEST_APP} 2 ${STR_LEN})

		# 5
		add_test(NAME "${STR_LEN}-unsupported-syscalls-with-fork"
			COMMAND ${TEST_DIR}/test-match -f ${TEST_APP} 3 ${STR_LEN})

		# 6
		add_test(NAME "${STR_LEN}-unsupported-syscalls-with-double-fork"
			COMMAND ${TEST_DIR}/test-match -f ${TEST_APP} 6 ${STR_LEN})

		# 7
		add_test(NAME "${STR_LEN}-syscall-vfork"
			COMMAND ${TEST_DIR}/test-match ${TEST_APP} 4 ${STR_LEN})

		# 8
		add_test(NAME "${STR_LEN}-syscall-sigaction"
			COMMAND ${TEST_DIR}/test-match ${TEST_APP} 7 ${STR_LEN})

	endforeach(STR_LEN)

	add_test(NAME "126-syscalls-string-arguments"
			COMMAND ${TEST_DIR}/test-match ${TEST_APP} 8 126)
	add_test(NAME "382-syscalls-string-arguments"
			COMMAND ${TEST_DIR}/test-match ${TEST_APP} 9 382)
	add_test(NAME "765-syscalls-string-arguments"
			COMMAND ${TEST_DIR}/test-match ${TEST_APP} 10 765)
	add_test(NAME "1148-syscalls-string-arguments"
			COMMAND ${TEST_DIR}/test-match ${TEST_APP} 11 1148)
	add_test(NAME "1531-syscalls-string-arguments"
			COMMAND ${TEST_DIR}/test-match ${TEST_APP} 12 1531)
	add_test(NAME "1531-syscalls-string-arguments-with-fork"
			COMMAND ${TEST_DIR}/test-match -f ${TEST_APP} 13 1531)
	add_test(NAME "1531-syscalls-string-arguments-with-double-fork"
			COMMAND ${TEST_DIR}/test-match -f ${TEST_APP} 14 1531)
endif ()
