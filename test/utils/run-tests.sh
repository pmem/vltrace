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
# test/utils/run-tests.sh -- run ctests for vltrace
#

TEMP_FILE=$(mktemp)

MAX=$1
if [ "$MAX" == "" ]; then
	echo "Usage: $0 <number-of-iterations> <tests-to-run>"
	echo "  e.g. $0 10 1 2 3 - runs tests (1,2,3) ten (10) times"
	exit 1
else
shift
fi

TESTS=$*
if [ "$TESTS" == "" ]; then
	TOTAL=$(ctest -N | tail -n1 | cut -d' ' -f3)
	TESTS=$(seq -s' ' $TOTAL)
fi

echo
echo "Number of iterations: $MAX"
echo "Tests to run: $TESTS"
echo

N=1
while [ $N -le $MAX ]; do
	echo "--- ITERATION #$N ---"
	for n in $TESTS; do
		if [ "$RUN_TEST_EXIT_ON_ERROR" != "1" ]; then
			echo "--- TEST #$N ---" >> log${n}.txt
			ctest -V -I ${n},${n} 2>&1 | tee -a log${n}.txt
		else
			echo > $TEMP_FILE
			tailf $TEMP_FILE &
			echo >> $TEMP_FILE
			echo "--- TEST #$n ---" >> $TEMP_FILE
			ctest -V -I ${n},${n} >> $TEMP_FILE 2>&1
			RV=$?
			cat $TEMP_FILE >> log${n}.txt
			rm -f $TEMP_FILE
			[ $RV -ne 0 ] && exit 1
		fi
	done
	N=$(($N + 1))
done

rm -f $TEMP_FILE
