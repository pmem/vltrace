#!/bin/bash -e
#
# Copyright 2016-2017, Intel Corporation
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
# run-build.sh - is called inside a Docker container,
#                starts a build of strace.ebpf
#

[ "$1" == "" ] \
	&& echo "Usage: $0 <required-kernel-version>" \
	&& exit 1

source ../functions.sh

V_REQ=$1
V_ACT=$(uname -r)
REQ_KV=$(format_kernel_version $V_REQ)
ACT_KV=$(format_kernel_version $V_ACT)

SKIP_MESSAGE="Notice: skipping tests (too old kernel: required >= $V_REQ, actual = $V_ACT)"

echo
echo

# Build all and run tests
cd $WORKDIR
if [ -n "$COMPILER" ]; then
	export CC=$COMPILER
fi

for release in Debug Release; do

	mkdir build
	cd build

	echo "$ cmake .. -DCMAKE_INSTALL_PREFIX=/tmp/strace.ebpf -DCMAKE_BUILD_TYPE=$release"
	cmake .. -DCMAKE_INSTALL_PREFIX=/tmp/strace.ebpf -DCMAKE_BUILD_TYPE=$release
	echo

	echo "$ make cstyle"
	make cstyle
	echo

	echo "$ make"
	make
	echo

	if [ $ACT_KV -ge $REQ_KV ]; then
		# check if debugfs is mounted
		set +e
		mount | grep -e "debugfs" >/dev/null
		if [ $? -ne 0 ]; then
			sudo mount -t debugfs debugfs /sys/kernel/debug
			if [ $? -eq 0 ]; then
				echo "Mounted: $(mount | grep -e 'debugfs')"
				echo
			else
				echo "Error: required mounted debugfs" >&2 && exit 1
			fi
		fi
		mount | grep -e "tracefs" >/dev/null
		if [ $? -ne 0 ]; then
			sudo mount -t tracefs tracefs /sys/kernel/debug/tracing
			if [ $? -eq 0 ]; then
				echo "Mounted: $(mount | grep -e 'tracefs')"
				echo
			else
				echo "Error: required mounted tracefs" >&2 && exit 1
			fi
		fi
		set -e

		echo "$ ctest --output-on-failure"
		ctest --output-on-failure
		echo
	else
		echo $SKIP_MESSAGE
		echo
	fi

	echo "$ make install"
	make install
	echo

	echo "$ make uninstall"
	make uninstall
	echo

	cd ..
	rm -rf build
done
