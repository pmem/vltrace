#!/usr/bin/python3
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

import logging

from utils import *
from syscallinfo import *


########################################################################################################################
# SyscallTable
########################################################################################################################
class SyscallTable:
    def __init__(self):
        self.log_sctbl = logging.getLogger("syscalltable")

        self.table = []

    ####################################################################################################################
    def valid_index(self, ind):
        if ind < len(self.table):
            i = ind
        else:
            i = len(self.table) - 1
        return i

    ####################################################################################################################
    def get(self, ind):
        i = self.valid_index(ind)
        return self.table[i]

    ####################################################################################################################
    def name(self, ind):
        i = self.valid_index(ind)
        return self.table[i].name

    ####################################################################################################################
    # read_syscall_table -- read the syscall table from the file
    ####################################################################################################################
    def read_syscall_table(self, fh):
        fmt = 'I4sP32sIIIiI6s6s'
        size_fmt = struct.calcsize(fmt)

        size_check, = read_fmt_data(fh, 'i')
        if size_check != size_fmt:
            self.log_sctbl.error("wrong format of syscalls table:")
            self.log_sctbl.error("      format size : {0:d}".format(size_fmt))
            self.log_sctbl.error("      data size   : {0:d}".format(size_check))
            return -1

        count, = read_fmt_data(fh, 'i')
        self.log_sctbl.debug("format of syscall table OK, reading {0:d} records...".format(count))

        for i in range(count):
            try:
                data = read_fmt_data(fh, fmt)
                num, num_str, pname, name, length, nargs, mask, avail, nstrargs, positions, _padding = data

                bname = bytes(name)
                sname = str(bname.decode(errors="ignore"))
                name = sname.split('\0')[0]
                name = name[4:]

                syscall = SyscallInfo(name, mask, nargs, nstrargs)
                self.table.append(syscall)

            except EndOfFile:
                break

            except CriticalError as err:
                print("ERROR: {0:s}".format(err.message), file=stderr)
                exit(-1)

            except:  # pragma: no cover
                print("ERROR: unexpected error", file=stderr)
                raise

        self.log_sctbl.debug("read {0:d} records of syscall table.".format(count))

        return 0
