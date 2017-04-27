#!/bin/bash
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
# test/utils/view-tests-short.sh -- view results of ctests for strace.ebpf
#                                   in short form
#
# Usage: view-tests-short.sh [long] [<minimum-value>]
#

[ "$1" == "long" ] && LONG=1 && shift || LONG=0
[ "$1" != "" ] && MIN=$1 || MIN=1

MAX=$(ls -1 log* | cut -c4- | cut -d'.' -f1 | sort -n | tail -n1)
TESTS=$(seq -s' ' $MAX)

for n in $TESTS; do
	[ ! -f ./log${n}.txt ] && continue
	[ $n -lt 10 ] \
		&& echo -n "TEST  $n" \
		|| echo -n "TEST $n"
	NAME=$(cat ./log${n}.txt | grep Start | head -n1 | cut -d" " -f7)
	P=$(cat ./log${n}.txt | grep Passed | wc -l)
	F=$(cat ./log${n}.txt | grep "\*\*\*Failed" | wc -l)
	A=$(($P + $F))
	echo "   All $A   Passed $P   Failed $F   ($NAME)"
done
