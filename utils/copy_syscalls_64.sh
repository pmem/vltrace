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
# copy_syscalls_64.sh -- shell script for finding and coping syscalls_64.sh header
#

HEADER_MOD="syscalls_64_mod.h_gen"
HEADER_NUM="syscalls_64_num.h_gen"

DEFINE_MOD="SYSCALLS_64_MOD_H_GEN"
DEFINE_NUM="SYSCALLS_64_NUM_H_GEN"

if [ -f $HEADER_MOD -a -f $HEADER_NUM ]; then
	if [ "$1" != "make" ]; then
		echo "-- Found header: $HEADER_MOD";
		echo "-- Found header: $HEADER_NUM";
	fi
	exit 0 # headers $HEADER_MOD and $HEADER_NUM exists
fi

KERNEL=$(uname -r)
FILES=$(mktemp)

[ "$1" != "make" ] \
	&& echo -n "-- Looking for kernel header syscalls_64.h "
find /usr -name "syscalls_64.h" 2>/dev/null | grep -e 'generated' | grep -e "$KERNEL" > $FILES
[ $(cat $FILES | wc -l) -eq 0 ] \
	&& find -L /usr -name "syscalls_64.h" 2>/dev/null | grep -e 'generated' | grep -e "$KERNEL" > $FILES

[ $(cat $FILES | wc -l) -eq 0 ] \
	&& echo \
	&& echo "ERROR: missing kernel header 'arch/x86/include/generated/asm/syscalls_64.h'" \
	&& echo \
	&& echo "Hint:  install 'kernel-devel' (RHEL, Fedora, CentOS) or 'linux-headers' (Debian, Ubuntu) package" \
	&& echo \
	&& exit 1

HEADER=$(cat $FILES | tail -n1)

[ ! -f $HEADER ] \
	&& echo \
	&& echo "ERROR: missing kernel header 'arch/x86/include/generated/asm/syscalls_64.h'" \
	&& echo \
	&& exit 1

[ "$1" != "make" ] \
	&& echo "- done"
echo "-- Found kernel header: $HEADER"

# generate two new headers
rm -f $HEADER_MOD $HEADER_NUM
echo "/*"                                   >> $HEADER_MOD
echo " * Generated from the kernel header:" >> $HEADER_MOD
echo " * $HEADER"                           >> $HEADER_MOD
echo " */"                                  >> $HEADER_MOD
echo ""                                     >> $HEADER_MOD
cp $HEADER_MOD $HEADER_NUM

# generate new header - removed the 'sys_' prefix
echo "#ifndef $DEFINE_MOD"        >> $HEADER_MOD
echo "#define $DEFINE_MOD"        >> $HEADER_MOD
cat $HEADER | sed 's/\ sys_/\ /g' >> $HEADER_MOD
echo "#endif /* $DEFINE_MOD */  " >> $HEADER_MOD
echo "-- Generated header: $HEADER_MOD"

# generate new header with defines of syscall numbers
echo "#ifndef $DEFINE_NUM"        >> $HEADER_NUM
echo "#define $DEFINE_NUM"        >> $HEADER_NUM
cat $HEADER | sed 's/\ sys_/\ /g' | \
while IFS='' read -r line || [[ -n "$line" ]]; do
	echo $line | grep -e "__SYSCALL_64" -e "__SYSCALL_COMMON" >/dev/null 2>&1
	[ $? -ne 0 ] && echo "$line" >> $HEADER_NUM && continue
	NUMBER=$(echo $line | cut -d'(' -f2 | cut -d',' -f1)
	NAME=$(echo $line | cut -d',' -f2 | cut -d' ' -f2)
	echo "#define __NR_${NAME} $NUMBER" >> $HEADER_NUM
done
echo "#endif /* $DEFINE_NUM */  " >> $HEADER_NUM
echo "-- Generated header: $HEADER_NUM"
