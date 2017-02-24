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
# test/utils/view-tests.sh -- view results of ctests for strace.ebpf
#                             (has to be run in the build directory)
#

TOTAL=$(ctest -N | tail -n1 | cut -d' ' -f3)
[ "$TOTAL" == "" ] \
	&& echo "$0 has to be run in the ctest build directory" \
	&& exit 1

TESTS=$(seq -s' ' $TOTAL)

for n in $TESTS; do
	[ ! -f ./log${n}.txt ] && continue
	echo -n "TEST $n"
	NAME=$(cat ./log${n}.txt | grep Start | head -n1 | cut -d" " -f7)
	P=$(cat ./log${n}.txt | grep Passed | wc -l)
	F=$(cat ./log${n}.txt | grep "\*\*\*Failed" | wc -l)
	A=$(($P + $F))
	echo "   All $A   Passed $P   Failed $F   ($NAME)"
	echo "----------------------------------------"
	if [[ $NAME =~ ^\[match\] ]]; then
		ERR=$(grep "Error:" ./log${n}.txt | cut -d" " -f5 | sort | uniq)
		for e in $ERR; do
			C=$(grep "Error:" ./log${n}.txt | cut -d" " -f5 | grep $e | wc -l)
			[ "$1" == "" ] \
				&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$e" \
				|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$e\t$NAME"
		done
	else
		L=$(grep -e "<" ./log${n}.txt | cut -d" " -f2 | sort | uniq)
		[ "$L" != "" ] && \
		for l in $L; do
			C=$(grep -e "<" ./log${n}.txt | cut -d" " -f2 | grep $l | wc -l)
			[ "$1" == "" ] \
				&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$l" \
				|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$l\t$NAME"
		done

		R=$(grep -e ">" ./log${n}.txt | cut -d">" -f2 | cut -d'	' -f2 | cut -d' ' -f1 | sort | uniq)
		if [ "$R" != "" ]; then
			echo "Extras:"
			for r in $R; do
				C=$(grep -e ">" ./log${n}.txt | cut -d">" -f2 | cut -d'	' -f2 | cut -d' ' -f1 | grep $r | wc -l)
				[ "$1" == "" ] \
					&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$r" \
					|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$r\t$NAME"
			done
		fi

		D=$(grep -e "|" ./log${n}.txt | grep -v "(strace.ebpf)" | cut -d" " -f2 | sort | uniq)
		if [ "$D" != "" ]; then
			echo "Diffs:"
			for d in $D; do
				C=$(grep -e "|" ./log${n}.txt | grep -v "(strace.ebpf)" | cut -d" " -f2 | grep $d | wc -l)
				[ "$1" == "" ] \
					&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$d" \
					|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$d\t$NAME"
			done
		fi
	fi
	echo
done
