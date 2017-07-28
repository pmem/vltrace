#!/usr/bin/python3
#
# Copyright (c) 2017, Intel Corporation
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
#     * Neither the name of Intel Corporation nor the names of its
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

EM_str_1 = 1 << 0  # syscall has string as 1. argument
EM_str_2 = 1 << 1  # syscall has string as 2. argument
EM_str_3 = 1 << 2  # syscall has string as 3. argument
EM_str_4 = 1 << 3  # syscall has string as 4. argument
EM_str_5 = 1 << 4  # syscall has string as 5. argument
EM_str_6 = 1 << 5  # syscall has string as 6. argument

EM_fd_1 = 1 << 6  # syscall has fd as a 1. arg
EM_fd_2 = 1 << 7  # syscall has fd as a 2. arg
EM_fd_3 = 1 << 8  # syscall has fd as a 3. arg
EM_fd_4 = 1 << 9  # syscall has fd as a 4. arg
EM_fd_5 = 1 << 10  # syscall has fd as a 5. arg
EM_fd_6 = 1 << 11  # syscall has fd as a 6. arg

EM_path_1 = 1 << 12  # syscall has path as 1. arg
EM_path_2 = 1 << 13  # syscall has path as 2. arg
EM_path_3 = 1 << 14  # syscall has path as 3. arg
EM_path_4 = 1 << 15  # syscall has path as 4. arg
EM_path_5 = 1 << 16  # syscall has path as 5. arg
EM_path_6 = 1 << 17  # syscall has path as 6. arg

EM_fileat = 1 << 18  # '*at' type syscall (dirfd + path)
EM_fileat2 = 1 << 19  # double '*at' type syscall (dirfd + path)
EM_rfd = 1 << 21  # syscall returns a file descriptor

EM_aep_arg_4 = 1 << 25  # AT_EMPTY_PATH can be at the 4th argument (fstatat and newfstatat)
EM_aep_arg_5 = 1 << 26  # AT_EMPTY_PATH can be at the 5th argument (linkat and fchownat)

EM_fd_from_path = EM_rfd | EM_path_1
EM_fd_from_fd = EM_rfd | EM_fd_1
EM_fd_from_dirfd_path = EM_rfd | EM_fd_1 | EM_path_2

EM_isfileat = EM_fd_1 | EM_path_2 | EM_fileat
EM_isfileat2 = EM_fd_3 | EM_path_4 | EM_fileat2

EM_str_all = EM_str_1 | EM_str_2 | EM_str_3 | EM_str_4 | EM_str_5 | EM_str_6
EM_path_all = EM_path_1 | EM_path_2 | EM_path_3 | EM_path_4 | EM_path_5 | EM_path_6
EM_fd_all = EM_fd_1 | EM_fd_2 | EM_fd_3 | EM_fd_4 | EM_fd_5 | EM_fd_6

Arg_is_str = [EM_str_1, EM_str_2, EM_str_3, EM_str_4, EM_str_5, EM_str_6]
Arg_is_path = [EM_path_1, EM_path_2, EM_path_3, EM_path_4, EM_path_5, EM_path_6]
Arg_is_fd = [EM_fd_1, EM_fd_2, EM_fd_3, EM_fd_4, EM_fd_5, EM_fd_6]


class SyscallInfo:
    def __init__(self, name, mask, nargs, nstrargs):
        self.name = name
        self.mask = mask
        self.nargs = nargs
        self.nstrargs = nstrargs

    ####################################################################################################################
    def is_mask(self, mask):
        return (self.mask & mask) == mask

    ####################################################################################################################
    def has_mask(self, mask):
        return self.mask & mask
