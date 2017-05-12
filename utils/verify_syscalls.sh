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
# utils/verify_syscalls.sh -- check if all syscalls are included in src/syscalls_numbers.h
#

SYSCALLS="src/syscalls_numbers.h"
SC_IN_TABLE=$(mktemp)

grep -e "EBPF_SYSCALL" src/ebpf_syscalls.c | grep -e "__NR_" | cut -d"(" -f2 | cut -d"," -f1 > $SC_IN_TABLE

N1=$(cat $SC_IN_TABLE | wc -l)
N2=$(cat $SC_IN_TABLE | sort | uniq | wc -l)

[ $N1 -ne $N2 ] && echo "Error: doubled syscall number" && exit 1

MISSING=0
for sc in $(cat $SC_IN_TABLE); do
	grep -e "$sc" $SYSCALLS > /dev/null
	[ $? -ne 0 ] && echo "Syscall missing in $SYSCALLS: $sc" && MISSING=1
done

[ $MISSING -eq 0 ] && echo "Check passed (all syscalls are included in $SYSCALLS)"

rm -f $SC_IN_TABLE
