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
# test/utils/report-tests.sh -- generate test report
#
# Usage: report-tests.sh <file-with-output-of-$(view-tests.sh long [<minimum>])>
#    or: report-tests.sh [<minimum>]
#

[ "$1" != "" ] && [ -f $1 ] \
	&& OUTPUT="cat $1" \
	|| OUTPUT="$(dirname $0)/view-tests.sh long $1"

echo
ERR=$($OUTPUT | grep '%' | cut -f3 | cut -d" " -f1 | sort | uniq)
if [ "$ERR" != "" ]; then
	for e in $ERR; do
		case $e in
		missed-entry-syscall:)
			SC=$($OUTPUT | grep "$e" | cut -f3 | cut -d" " -f2 | sort | uniq)
			for s in $SC; do
				echo "- missed ENTRY probe of syscall: $s"
				$OUTPUT | grep "$e $s " | sed "s/\t$e $s\t/\t\t/g"
				echo
			done
			;;
		missed-exit-syscall:)
			SC=$($OUTPUT | grep "$e" | cut -f3 | cut -d" " -f2 | sort | uniq)
			for s in $SC; do
				echo "- missed EXIT probe of syscall: $s"
				$OUTPUT | grep "$e $s " | sed "s/\t$e $s\t/\t\t/g"
				echo
			done
			;;
		wrong-arguments:)
			SC=$($OUTPUT | grep "$e" | cut -f3 | cut -d" " -f2 | sort | uniq)
			for s in $SC; do
				echo "- wrong arguments: $s"
				$OUTPUT | grep "$e $s " | sed "s/\t$e $s\t/\t\t/g"
				echo
			done
			;;
		missing-output)
			echo "- missing output - follow-fork did not follow (no output of at least one process):"
			$OUTPUT | grep "$e" | sed "s/\t$e\t/\t\t/g"
			;;
		truncated-output)
			echo "- truncated output - follow-fork stopped following:"
			$OUTPUT | grep "$e" | sed "s/\t$e\t/\t\t/g"
			;;
		unexpected-output)
			echo "- unexpected output:"
			$OUTPUT | grep "$e" | sed "s/\t$e\t/\t\t/g"
			;;
		bpf_probe_read-error:)
			SC=$($OUTPUT | grep "$e" | cut -f3 | cut -d" " -f2 | sort | uniq)
			for s in $SC; do
				echo "- bpf_probe_read error: $s"
				$OUTPUT | grep "$e $s " | sed "s/\t$e $s\t/\t\t/g"
				echo
			done
			;;
		*)
			echo "Unsupported event: $e"
			;;
		esac
		echo
	done
fi
exit
