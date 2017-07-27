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

from syscall import *
from utils import *


########################################################################################################################
# ListSyscalls
########################################################################################################################
class ListSyscalls(list):
    def __init__(self, script_mode, debug_mode, verbose_mode):

        list.__init__(self)

        self.log_anls = logging.getLogger("analysis")

        self.script_mode = script_mode
        self.debug_mode = debug_mode
        self.verbose_mode = verbose_mode

        self.print_progress = not (self.debug_mode or self.script_mode)

        self.time0 = 0

        self.cwd_table = []

    ####################################################################################################################
    def print(self):
        for syscall in self:
            syscall.print()

    ####################################################################################################################
    def print_always(self):
        for syscall in self:
            syscall.print_always()

    ####################################################################################################################
    # look_for_matching_record -- look for matching record in a list of incomplete syscalls
    ####################################################################################################################
    def look_for_matching_record(self, info_all, pid_tid, sc_id, name, retval):
        for syscall in self:
            check = syscall.check_read_data(info_all, pid_tid, sc_id, name, retval, DEBUG_OFF)
            if check == CHECK_OK:
                self.remove(syscall)
                return syscall
        return -1

    ####################################################################################################################
    def log_print_path(self, is_pmem, name, path):
        if is_pmem:
            self.log_anls.debug("{0:20s} \"{1:s}\" [PMEM]".format(name, path))
        else:
            self.log_anls.debug("{0:20s} \"{1:s}\"".format(name, path))

    ####################################################################################################################
    @staticmethod
    def log_build_msg(msg, is_pmem, path):
        if is_pmem:
            msg += " \"{0:s}\" [PMEM]".format(path)
        else:
            msg += " \"{0:s}\"".format(path)
        return msg

    ####################################################################################################################
    def set_first_cwd(self, cwd):
        assert_msg(len(self.cwd_table) == 0, "cwd_table is not empty")
        self.cwd_table.append(cwd)

    ####################################################################################################################
    def set_cwd(self, new_cwd, syscall):
        self.cwd_table[syscall.pid_ind] = new_cwd

    ####################################################################################################################
    def get_cwd(self, syscall):
        return self.cwd_table[syscall.pid_ind]
