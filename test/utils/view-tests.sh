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
# test/utils/view-tests.sh -- view results of ctests for vltrace
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
	NUM_ERR=$(grep "Error " ./log${n}.txt | cut -d' ' -f3 | cut -d':' -f1 | sort | uniq)
	for err in $NUM_ERR; do
		case $err in
		0) # unknown error
			MSG="unknown-error"
			C=$(grep "Error 0" ./log${n}.txt | wc -l)
			[ $C -lt $MIN ] && continue
			[ $LONG -eq 0 ] \
				&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG" \
				|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG\t$NAME"
			;;
		1) # missed entry probe of syscall
			MSG="missed-entry-syscall: "
			FLD=9
			ERR=$(grep "Error $err" ./log${n}.txt | cut -d" " -f$FLD | sort | uniq)
			for e in $ERR; do
				C=$(grep "Error $err" ./log${n}.txt | cut -d" " -f$FLD | grep $e | wc -l)
				[ $C -lt $MIN ] && continue
				[ $LONG -eq 0 ] \
					&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$e " \
					|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$e \t$NAME"
			done
			;;
		2) # missed exit probe of syscall
			MSG="missed-exit-syscall: "
			FLD=9
			ERR=$(grep "Error $err" ./log${n}.txt | cut -d" " -f$FLD | sort | uniq)
			for e in $ERR; do
				C=$(grep "Error $err" ./log${n}.txt | cut -d" " -f$FLD | grep $e | wc -l)
				[ $C -lt $MIN ] && continue
				[ $LONG -eq 0 ] \
					&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$e " \
					|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$e \t$NAME"
			done
			;;
		3) # wrong arguments of syscall
			MSG="wrong-arguments: "
			FLD=8
			ERR=$(grep "Error $err" ./log${n}.txt | cut -d" " -f$FLD | sort | uniq)
			for e in $ERR; do
				C=$(grep "Error $err" ./log${n}.txt | cut -d" " -f$FLD | grep $e | wc -l)
				[ $C -lt $MIN ] && continue
				[ $LONG -eq 0 ] \
					&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$e " \
					|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$e \t$NAME"
			done
			;;
		4) # missing output
			MSG="missing-output"
			C=$(grep "Error $err" ./log${n}.txt | wc -l)
			[ $C -lt $MIN ] && continue
			[ $LONG -eq 0 ] \
				&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG" \
				|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG\t$NAME"
			;;
		5) # truncated output
			MSG="truncated-output"
			C=$(grep "Error $err" ./log${n}.txt | wc -l)
			[ $C -lt $MIN ] && continue
			[ $LONG -eq 0 ] \
				&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG" \
				|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG\t$NAME"
			;;
		6) # unexpected output
			MSG="unexpected-output"
			C=$(grep "Error $err" ./log${n}.txt | wc -l)
			[ $C -lt $MIN ] && continue
			[ $LONG -eq 0 ] \
				&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG" \
				|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG\t$NAME"
			;;
		7) # bpf_probe_read error
			MSG="bpf_probe_read-error: "
			FLD=11
			ERR=$(grep "Error $err" ./log${n}.txt | cut -d" " -f$FLD | sort | uniq)
			for e in $ERR; do
				C=$(grep "Error $err" ./log${n}.txt | cut -d" " -f$FLD | grep $e | wc -l)
				[ $C -lt $MIN ] && continue
				[ $LONG -eq 0 ] \
					&& echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$e " \
					|| echo -e "   $((100*$C/$A))%\t($C/$A)\t$MSG$e \t$NAME"
			done
			;;
		*) # unknown error
			echo "UNKNOWN ERROR"
			;;
		esac
	done
	echo
done
