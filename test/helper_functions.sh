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
	if [ "${VLTRACE_TEST_SAVE_LOGS}" ]; then
		DIR_NAME="logs-${NAME_PATTERN}-$(date +%F_%T_%N)-$$"
		mkdir $DIR_NAME
		cp $FILE_MASK $DIR_NAME/
		echo "NOTICE: all log files were saved in the directory: $DIR_NAME"
	fi
}

#
# get_line_of_pattern -- get a line number of the first pattern in the file
#                        get_line_of_pattern <file> <pattern>
#
function get_line_of_pattern() {
	local LINE=$(grep -n -e "$2" $1 | cut -d: -f1 | head -n1)
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
		&& echo "ERROR: cut_part_file(): the start-pattern \"$PATTERN1\" not found in file $FILE" >&2 \
		&& return

	local LINE2=$(get_line_of_pattern $FILE "$PATTERN2")
	[ "$LINE2" == "" ] \
		&& LINE2=$(cat $FILE | wc -l) # print the file till the end

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
		[ "$PID" == "fork" ] \
			&& grep "$PID" $INPUT | sort -k3 -r > $NAME \
			|| grep "$PID" $INPUT > $NAME
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
# check -- check test results (using .match files)
#
function check() {
	local MATCH_OUT="match-${TEST_NUM}.log"
	set +e

	# copy match files in case of out-of-tree build
	[ "$TEST_DIR" != "$(pwd)" ] && cp -v -f $TEST_DIR/*-${TEST_NUM}.log.match .

	# create missing log files
	ls -1 *-${TEST_NUM}.log.match | sed 's/\.match//g' | xargs touch

	# finally run 'match'
	$TEST_DIR/match *-${TEST_NUM}.log.match >$MATCH_OUT 2>&1
	RV=$?
	set -e
	[ $RV -eq 0 ] && rm -f $MATCH_OUT && return

	# match failed - print few last lines
	tail -n11 $MATCH_OUT

	echo "------"

	# output does not match the pattern
	if [ "$(tail -n1 $MATCH_OUT | grep -e 'did not match pattern')" != "" ]; then
		# check if log is truncated
		local LINE=$(tail -n2 $MATCH_OUT | grep 'EOF')
		if [ "$LINE" == "" ]; then
			local NC=$(tail -n3 $MATCH_OUT | head -n1 | cut -d'$' -f1 | wc -c)
			local NAMES=$(tail -n3 $MATCH_OUT | head -n2 | cut -c${NC}- | cut -d" " -f5)
			local RESLT=$(tail -n3 $MATCH_OUT | head -n2 | cut -c${NC}- | cut -d" " -f4)
			SC_MATCH=$(echo $NAMES | cut -d" " -f1)
			SC_ACTUA=$(echo $NAMES | cut -d" " -f2)
			RS_MATCH=$(echo $RESLT | cut -d" " -f1)
			RS_ACTUA=$(echo $RESLT | cut -d" " -f2)
			if [ "$RS_MATCH" == "----------------" ]; then
				NUM="1" && TYPE="ENTRY"
			else
				NUM="2" && TYPE="EXIT"
			fi
			if [ "$SC_MATCH" == "$SC_ACTUA" -a "$RS_MATCH" == "$RS_ACTUA" ]; then
				set +e
				READ_ERROR=$(tail -n2 $MATCH_OUT | head -n1 | grep -e "(bpf_probe_read < 0)")
				set -e
				if [ "$READ_ERROR" == "" ]; then
					echo "Error 3: wrong arguments of syscall $SC_MATCH"
				else
					echo "Error 7: bpf_probe_read error (bpf_probe_read < 0) in syscall: $SC_MATCH"
				fi
			else
				echo "Error $NUM: missed $TYPE probe of syscall $SC_MATCH"
			fi
		else
			LN=$(echo $LINE | cut -d':' -f2 | cut -d' ' -f1)
			[ $LN -eq 1 ] \
				&& echo "Error 4: missing output" \
				|| echo "Error 5: truncated output"
		fi
	else if [ "$(tail -n1 $MATCH_OUT | grep -e 'unexpected output')" != "" ]; then
		echo "Error 6: unexpected output"
	else
		echo "Error 0: unknown error"
	fi; fi;

	echo "------"

	save_logs "*-$TEST_NUM.log" "match-$(basename $TEST_FILE)-$TEST_NUM"

	return $RV
}
