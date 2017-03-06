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
#
# Usage: view-tests.sh [long] [<minimum-value>]
#

[ "$1" == "long" ] && LONG=1 && shift || LONG=0
[ "$1" != "" ] && MIN=$1 || MIN=1

MAX=$(ls -1 log* | cut -c4- | cut -d'.' -f1 | sort -n | tail -n1)
TESTS=$(seq -s' ' $MAX)

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
		NUM_ERR=$(grep "Error " ./log${n}.txt | cut -c10 | sort | uniq)
		for err in $NUM_ERR; do
		case $err in
		0)
			MSG="unknown-error"
			C=$(grep "Error 0" ./log${n}.txt | wc -l)
			[ $C -lt $MIN ] && continue
			[ $LONG -eq 0 ] \
				&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG" \
				|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG\t$NAME"
			;;
		1) # missed syscall
			MSG="missed-syscall: "
			FLD=6
			ERR=$(grep "Error 1" ./log${n}.txt | cut -d" " -f$FLD | sort | uniq)
			for e in $ERR; do
				C=$(grep "Error 1" ./log${n}.txt | cut -d" " -f$FLD | grep $e | wc -l)
				[ $C -lt $MIN ] && continue
				[ $LONG -eq 0 ] \
					&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$e" \
					|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$e\t$NAME"
			done
			;;
		2) # wrong arguments of syscall
			MSG="wrong-arguments: "
			FLD=8
			ERR=$(grep "Error 2" ./log${n}.txt | cut -d" " -f$FLD | sort | uniq)
			for e in $ERR; do
				C=$(grep "Error 2" ./log${n}.txt | cut -d" " -f$FLD | grep $e | wc -l)
				[ $C -lt $MIN ] && continue
				[ $LONG -eq 0 ] \
					&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$e" \
					|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$e\t$NAME"
			done
			;;
		3)
			MSG="missing-output"
			C=$(grep "Error 3" ./log${n}.txt | wc -l)
			[ $C -lt $MIN ] && continue
			[ $LONG -eq 0 ] \
				&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG" \
				|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG\t$NAME"
			;;
		4)
			MSG="truncated-output"
			C=$(grep "Error 4" ./log${n}.txt | wc -l)
			[ $C -lt $MIN ] && continue
			[ $LONG -eq 0 ] \
				&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG" \
				|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG\t$NAME"
			;;
		*)
			echo "UNKNOWN ERROR"
		esac
		done
	else
		MSG="missed-syscall: "
		L=$(grep -e "<" ./log${n}.txt | cut -d" " -f2 | sort | uniq)
		[ "$L" != "" ] && \
		for l in $L; do
			C=$(grep -e "<" ./log${n}.txt | cut -d" " -f2 | grep $l | wc -l)
			[ $C -lt $MIN ] && continue
			[ $LONG -eq 0 ] \
				&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$l" \
				|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$l\t$NAME"
		done

		MSG="wrong-arguments: "
		D=$(grep -e "|" ./log${n}.txt | grep -v "(strace.ebpf)" | cut -d" " -f2 | sort | uniq)
		if [ "$D" != "" ]; then
			for d in $D; do
				C=$(grep -e "|" ./log${n}.txt | grep -v "(strace.ebpf)" | cut -d" " -f2 | grep $d | wc -l)
				[ $C -lt $MIN ] && continue
				[ $LONG -eq 0 ] \
					&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$d" \
					|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$d\t$NAME"
			done
		fi

		MSG="extra-syscall: "
		R=$(grep -e ">" ./log${n}.txt | cut -d">" -f2 | cut -d'	' -f2 | cut -d' ' -f1 | sort | uniq)
		if [ "$R" != "" ]; then
			for r in $R; do
				C=$(grep -e ">" ./log${n}.txt | cut -d">" -f2 | cut -d'	' -f2 | cut -d' ' -f1 | grep $r | wc -l)
				[ $C -lt $MIN ] && continue
				[ $LONG -eq 0 ] \
					&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$r" \
					|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$r\t$NAME"
			done
		fi
	fi
	echo
done
