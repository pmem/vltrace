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
#

#
# test/common.sh -- common setup for strace.ebpf tests
#

OPT_STRACE_EBPF="-t -K' ' -e trace=kp-kern-all"

STRACE_EBPF=../src/strace.ebpf
[ ! -x $STRACE_EBPF ] \
	&& echo "Error: executable file '$STRACE_EBPF' does not exist" \
	&& exit 1

RUN_STRACE="ulimit -l 10240 && ulimit -n 10240 && $STRACE_EBPF $OPT_STRACE_EBPF"

#
# require_superuser -- require superuser capabilities
#
function require_superuser() {
	local user_id=$(sudo -n id -u)
	[ "$user_id" == "0" ] && return
	echo "Superuser rights required, please enter root's password:"
	sudo date > /dev/null
	[ $? -eq 0 ] && return
	echo "Authentication failed, aborting..."
	exit 1
}

#
# save_logs -- save all logs of the current test
#
# usage: save_logs <file-mask> <name-pattern>
#
function save_logs() {
	FILE_MASK=$1
	NAME_PATTERN=$2
	if [ "${STRACE_EBPF_TEST_SAVE_LOGS}" ]; then
		DIR_NAME="logs-${NAME_PATTERN}-$(date +%F_%T_%N)-$$"
		mkdir $DIR_NAME
		cp $FILE_MASK $DIR_NAME/
		echo "NOTICE: all log files were saved in the directory: $DIR_NAME"
	fi
}
