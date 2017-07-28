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
# run-build.sh - is called inside a Docker container, starts a build of vltrace
#

VLTRACE_MINIMUM_KERNEL_VERSION="4.7"

source ../functions.sh

ACTUAL_KERNEL_VERSION=$(uname -r)
REQ_KV=$(format_kernel_version $VLTRACE_MINIMUM_KERNEL_VERSION)
ACT_KV=$(format_kernel_version $ACTUAL_KERNEL_VERSION)

echo
echo

# temporary workaround for Travis issue with mounting permissions
ME=$(whoami)
sudo chown -R $ME $WORKDIR

# Build all and run tests
cd $WORKDIR
if [ -n "$COMPILER" ]; then
	export CC=$COMPILER
fi

for release in Debug Release; do

	mkdir build
	cd build

	echo "$ cmake .. -DCMAKE_INSTALL_PREFIX=/tmp/vltrace -DDEVELOPER_MODE=ON -DCMAKE_BUILD_TYPE=$release"
	cmake .. -DCMAKE_INSTALL_PREFIX=/tmp/vltrace -DDEVELOPER_MODE=ON -DCMAKE_BUILD_TYPE=$release
	echo

	echo "$ make"
	make
	echo

	# check if debugfs and tracefs are mounted
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

	if [ $ACT_KV -ge $REQ_KV ]; then
		echo "$ ctest -V"
		ctest -V
	elif [ $ACT_KV -ge 404 ]; then
		echo "Notice: running basic tests available for kernels >= 4.4"
		echo

		# create /run/lock directory, because it may not exist
		sudo mkdir -p /run/lock

		VLTRACE="ulimit -l 10240 && ulimit -n 10240 && src/vltrace -t --expr kp-all"
		DATE=$(which date)

		echo "$ sudo bash -c \"$VLTRACE $DATE\""
		sudo bash -c "$VLTRACE -s 126 $DATE"
	else
		echo "Notice: skipping tests (too old kernel: "\
			"required >= $VLTRACE_MINIMUM_KERNEL_VERSION, "\
			"actual = $ACTUAL_KERNEL_VERSION)"
	fi

	echo
	echo "$ make install"
	make install
	echo

	echo "$ make uninstall"
	make uninstall
	echo

	cd ..
	rm -rf build
done
