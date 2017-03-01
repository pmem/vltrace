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
# get_line_of_pattern -- get a line number of the first pattern in the file
#                        get_line_of_pattern <file> <pattern>
#
function get_line_of_pattern() {
	local LINE=$(grep -n "$2" $1 | cut -d: -f1 | head -n1)
	echo $LINE
}

#
# cut_part_file -- cut part of the file $1
#                  starting from the pattern $2
#                  ending at the pattern $3
#
function cut_part_file() {

	local FILE=$1
	local PATTERN1=$2
	local PATTERN2=$3

	local LINE1=$(get_line_of_pattern $FILE "$PATTERN1")
	[ "$LINE1" == "" ] \
		&& echo "Error: cut_part_file(): no pattern \"$PATTERN1\" found in file $FILE" >&2 \
		&& exit 1

	local LINE2=$(get_line_of_pattern $FILE "$PATTERN2")
	[ "$LINE2" == "" ] \
		&& echo "Error: cut_part_file(): no pattern \"$PATTERN2\" found in file $FILE" >&2 \
		&& exit 1

	sed -n ${LINE1},${LINE2}p $FILE
}

#
# split_forked_file - split log files of forked processes
#                     split_forked_file <file> <name-part1> <name-part2>
#
function split_forked_file() {
	NAME1=$2
	NAME2=$3

	local INPUT=$(mktemp)
	local GREP=$(mktemp)

	cp $1 $INPUT

	local N=0
	local PID="fork"
	while true; do
		NAME="${NAME1}-${N}-${NAME2}"
		touch $NAME
		set +e
		grep    "$PID" $INPUT > $NAME
		grep -v "$PID" $INPUT > $GREP
		cp $GREP $INPUT
		set -e
		[ $(cat $INPUT | wc -l) -eq 0 ] && break
		PID=$(head -n1 $INPUT | cut -d" " -f2)
		N=$(($N + 1))
	done
	rm -f $GREP $INPUT
	echo $N
}

#
# get_files -- print list of files in the current directory matching the given regex to stdout
#
# This function has been implemented to workaround a race condition in
# `find`, which fails if any file disappears in the middle of the operation.
#
# example, to list all *.log files in the current directory
#	get_files ".*\.log"
function get_files() {
	set +e
	ls -1 | grep -E "^$*$"
	set -e
}

#
# check -- check test results (using .match files)
#
function check() {
	local MATCH_OUT="match-${TEST_NUM}.log"
	set +e
	[ "$TEST_DIR" != "$(pwd)" ] && cp -v -f $TEST_DIR/*-${TEST_NUM}.log.match .
	$TEST_DIR/match $(get_files ".*-${TEST_NUM}\.log\.match") >$MATCH_OUT 2>&1
	RV=$?
	set -e
	[ $RV -eq 0 ] && rm -f $MATCH_OUT && return

	# match failed
	tail -n11 $MATCH_OUT
	local NC=$(tail -n3 $MATCH_OUT | head -n1 | cut -d'$' -f1 | wc -c)
	local OUT=$(tail -n3 $MATCH_OUT | head -n2 | cut -c${NC}- | cut -d" " -f5)
	SC_MATCH=$(echo $OUT | cut -d" " -f1)
	SC_IS=$(echo $OUT | cut -d" " -f2)
	echo "------"
	[ "$SC_MATCH" != "$SC_IS" ] \
		&& echo "Error: missed syscall $SC_MATCH" \
		|| echo "Error: wrong arguments of syscall $SC_MATCH"
	echo "------"

	save_logs "*-$TEST_NUM.log" "match-$(basename $TEST_FILE)-$TEST_NUM"

	return $RV
}
