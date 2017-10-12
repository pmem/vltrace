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

E_KP_ENTRY = 0
E_KP_EXIT = 1
E_TP_ENTRY = 2
E_TP_EXIT = 3
E_MASK = 0x03

FIRST_PACKET = 0  # this is the first packet for this syscall
LAST_PACKET = 7   # this is the last packet for this syscall
READ_ERROR = 1 << 10  # bpf_probe_read error occurred

STATE_INIT = 0
STATE_IN_ENTRY = 1
STATE_ENTRY_COMPLETED = 2
STATE_COMPLETED = 3
STATE_CORRUPTED_ENTRY = 4

CNT_NONE = 0
CNT_ENTRY = 1
CNT_EXIT = 2

RESULT_SUPPORTED = 0

CHECK_OK = 0
CHECK_NO_ENTRY = 1
CHECK_NO_EXIT = 2
CHECK_WRONG_ID = 3
CHECK_SAVE_IN_ENTRY = 4
CHECK_NOT_FIRST_PACKET = 5

EM_no_ret = 1 << 20  # syscall does not return

RT_SIGRETURN_SYS_EXIT = 0xFFFFFFFFFFFFFFFF  # = sys_exit of rt_sigreturn

DEBUG_OFF = 0
DEBUG_ON = 1


def is_entry(etype):
    return (etype & 0x01) == 0


def is_exit(etype):
    return (etype & 0x01) == 1


########################################################################################################################
# Syscall
########################################################################################################################
class Syscall(SyscallInfo):
    str_entry = "------------------ ------------------"
    arg_str_mask = [1, 2, 4, 8, 16, 32]

    ####################################################################################################################
    def __init__(self, pid_tid, sc_id, sc_info, buf_size, debug_mode):

        SyscallInfo.__init__(self, sc_info.name, sc_info.mask, sc_info.nargs, sc_info.nstrargs)

        self.log_parse = logging.getLogger("parser")

        self.debug_mode = debug_mode

        self.state = STATE_INIT
        self.content = CNT_NONE

        self.pid_tid = pid_tid
        self.sc_id = sc_id
        self.time_start = 0
        self.time_end = 0
        self.args = []
        self.ret = 0
        self.iret = 0
        self.err = 0

        self.string = ""
        self.num_str = 0
        self.str_fini = -1

        self.info_all = 0
        self.arg_first = FIRST_PACKET
        self.arg_last = LAST_PACKET
        self.is_cont = 0
        self.will_be_cont = 0
        self.read_error = 0

        self.truncated = 0

        self.strings = []

        self.buf_size = int(buf_size)
        self.buf_size_2 = int(buf_size / 2)
        self.buf_size_3 = int(buf_size / 3)

        self.str_max_1 = self.buf_size - 2
        self.str_max_2 = self.buf_size_2 - 2
        self.str_max_3 = self.buf_size_3 - 2

        self.fmt_args = 'QQQQQQ'
        self.size_fmt_args = struct.calcsize(self.fmt_args)

        self.fmt_exit = 'q'
        self.size_fmt_exit = struct.calcsize(self.fmt_exit)

        self.pid_ind = -1
        self.is_pmem = 0
        self.unsupported_type = RESULT_SUPPORTED

    ####################################################################################################################
    def __lt__(self, other):
        return self.time_start < other.time_start

    ####################################################################################################################
    def is_string(self, n):
        if (self.mask & self.arg_str_mask[n]) == self.arg_str_mask[n]:
            return 1
        else:
            return 0

    ####################################################################################################################
    # get_str_arg -- get next (of number 'self.num_str') string argument
    #                from the 'buf_str' buffer containing string arguments
    ####################################################################################################################
    def get_str_arg(self, buf_str):
        string = ""
        max_len = 0

        if self.nstrargs == 1 or self.info_all >> 2:
            max_len = self.str_max_1
            string = buf_str

        elif self.nstrargs == 2:
            max_len = self.str_max_2
            self.num_str += 1
            if self.num_str == 1:
                string = buf_str[0:self.buf_size_2]
            elif self.num_str == 2:
                string = buf_str[self.buf_size_2: 2 * self.buf_size_2]
            else:  # pragma: no cover
                assert_msg(self.num_str <= 2, "unsupported number of string arguments ({0:d}), "
                                              "input file may be corrupted".format(self.nstrargs))

        elif self.nstrargs == 3:
            max_len = self.str_max_3
            self.num_str += 1
            if self.num_str == 1:
                string = buf_str[0:self.buf_size_3]
            elif self.num_str == 2:
                string = buf_str[self.buf_size_3: 2 * self.buf_size_3]
            elif self.num_str == 3:
                string = buf_str[2 * self.buf_size_3: 3 * self.buf_size_3]
            else:  # pragma: no cover
                assert_msg(self.num_str <= 3, "unsupported number of string arguments ({0:d}), "
                                              "input file may be corrupted".format(self.nstrargs))

        else:  # pragma: no cover
            assert_msg(self.nstrargs <= 3, "unsupported number of string arguments ({0:d}), input file may be corrupted"
                       .format(self.nstrargs))

        str_p = str(string.decode(errors="ignore"))
        str_p = str_p.split('\0')[0]
        self.string += str_p

        # check if string ended
        if len(str_p) == (max_len + 1):
            # string did not ended
            self.str_fini = 0
            if self.will_be_cont == 0:
                # error: string is truncated
                self.truncated = len(self.strings) + 1  # set it to string index + 1
                self.str_fini = 1
        else:
            # string is completed, save it
            self.str_fini = 1

        if not self.str_fini:
            return -1

        self.strings.append(self.string)
        self.string = ""

        return len(self.strings) - 1

    ####################################################################################################################
    def print_single_record(self, debug):
        if self.state == STATE_ENTRY_COMPLETED:
            self.print_entry(debug)
            return

        if self.state == STATE_COMPLETED:
            if self.mask & EM_no_ret:
                self.print_entry(debug)
            else:
                self.print_exit(debug)
            return

        if self.state == STATE_CORRUPTED_ENTRY:
            self.log_print("corrupted entry packet information of syscall {0:s}:".format(self.name), debug)
            self.log_print("0x{0:016X} 0x{1:016X} {2:s} {3:s} [corrupted entry packet]"
                           .format(self.time_start, self.pid_tid, self.str_entry, self.name), debug)

    ####################################################################################################################
    def print_always(self):
        if self.debug_mode and self.state not in (STATE_INIT, STATE_ENTRY_COMPLETED, STATE_COMPLETED):
            print("DEBUG(print_always): syscall: {0:s}, state: {1:d}".format(self.name, self.state))

        self.print_entry(DEBUG_OFF)

        if (self.content & CNT_EXIT) and (self.mask & EM_no_ret == 0):
            self.print_exit(DEBUG_OFF)

        if not (self.content & (CNT_ENTRY | CNT_EXIT)):
            print("0x{0:016X} 0x{1:016X} {2:s} {3:s} [corrupted packet]".
                  format(self.time_start, self.pid_tid, self.str_entry, self.name))

    ####################################################################################################################
    def log_print(self, msg, debug):
        if debug:
            self.log_parse.debug(msg)
        else:
            print(msg)

    ####################################################################################################################
    # print_entry -- print entry info of the syscall
    ####################################################################################################################
    def print_entry(self, debug):
        if not (self.content & CNT_ENTRY):
            return

        if self.read_error:
            warn_str = "BPF read error occurred, a string argument is empty in syscall: {0:s}".format(self.name)
            if self.debug_mode:
                self.log_parse.warning(warn_str)
            else:
                print("WARNING: " + warn_str)

        msg = "0x{0:016X} 0x{1:016X} {2:s} {3:s}".format(self.time_start, self.pid_tid, self.str_entry, self.name)

        assert_msg(self.nargs == len(self.args), "incorrect number of syscall arguments, input file may be corrupted")

        for n in range(0, self.nargs):
            if self.is_string(n):
                msg += " \"{0:s}\"".format(self.strings[self.args[n]])
            else:
                msg += " 0x{0:016X}".format(self.args[n])

        self.log_print(msg, debug)

    ####################################################################################################################
    # print_exit -- print exit info of the syscall
    ####################################################################################################################
    def print_exit(self, debug):
        assert_msg(self.content & CNT_EXIT, "print_exit: no exit content")

        if len(self.name) > 0:
            self.log_print("0x{0:016X} 0x{1:016X} 0x{2:016X} 0x{3:016X} {4:s}".format(
                            self.time_end, self.pid_tid, self.err, self.ret, self.name), debug)
        else:
            self.log_print("0x{0:016X} 0x{1:016X} 0x{2:016X} 0x{3:016X} sys_exit 0x{4:016X}".format(
                            self.time_end, self.pid_tid, self.err, self.ret, self.sc_id), debug)

    ####################################################################################################################
    def print_mismatch_info(self, etype, pid_tid, sc_id, name):
        self.log_parse.debug("WARNING: current packet does not match the previous one:")
        self.log_parse.debug("         previous packet: {0:016X} {1:s} (sc_id:{2:d}) state {3:d}"
                             .format(self.pid_tid, self.name, self.sc_id, self.state))
        self.log_parse.debug("         current packet:  {0:016X} {1:s} (sc_id:{2:d}) etype {3:d}"
                             .format(pid_tid, name, sc_id, etype))

    ####################################################################################################################
    # check_read_data -- check if the recently read data record contains correct data
    ####################################################################################################################
    def check_read_data(self, info_all, pid_tid, sc_id, name, retval, debug_on):
        etype = info_all & E_MASK
        arg_first = (info_all >> 2) & 0x7

        if self.state == STATE_INIT and arg_first != FIRST_PACKET:
            if debug_on:
                self.log_parse.debug("WARNING: missed first packet of syscall: {0:016X} {1:s}".format(pid_tid, name))
            return CHECK_NOT_FIRST_PACKET

        if self.state == STATE_INIT and is_exit(etype):
            if sc_id == RT_SIGRETURN_SYS_EXIT or (retval == 0 and name in ("clone", "fork", "vfork")):
                return CHECK_OK

            return CHECK_NO_ENTRY

        if self.state == STATE_IN_ENTRY and is_exit(etype):
            if debug_on:
                self.log_parse.debug("WARNING: read the exit record when in 'in-entry' state of syscall: {0:016X} {1:s}"
                                     .format(self.pid_tid, self.name))
                self.print_mismatch_info(etype, pid_tid, sc_id, name)
            return CHECK_SAVE_IN_ENTRY

        wrong_id = not (pid_tid == self.pid_tid and sc_id == self.sc_id)

        if self.state == STATE_ENTRY_COMPLETED and (is_entry(etype) or (is_exit(etype) and wrong_id)):
            return CHECK_NO_EXIT

        if wrong_id:
            if debug_on:
                self.log_parse.debug("WARNING: missing packets of syscall: {0:016X} {1:s}"
                                     .format(self.pid_tid, self.name))
                self.print_mismatch_info(etype, pid_tid, sc_id, name)
            return CHECK_WRONG_ID

        return CHECK_OK

    ####################################################################################################################
    # add_data -- add the read data to the syscall record
    ####################################################################################################################
    def add_data(self, info_all, bdata, timestamp):
        etype = info_all & E_MASK
        info_all &= ~E_MASK

        assert_msg(etype in (E_KP_ENTRY, E_KP_EXIT, E_TP_EXIT), "unknown entry type")

        if etype == E_KP_ENTRY:
            if self.state not in (STATE_INIT, STATE_IN_ENTRY):
                self.log_parse.error("wrong state for KProbe entry type: {0:d}".format(self.state))
            # kprobe entry handler
            return self.add_kprobe_entry(info_all, bdata, timestamp)

        # kprobe exit handler or raw tracepoint sys_exit ((etype == E_KP_EXIT) or (etype == E_TP_EXIT))
        return self.add_exit(bdata, timestamp)

    ####################################################################################################################
    # add_kprobe_entry -- add the kprobe entry info to the syscall record
    ####################################################################################################################
    def add_kprobe_entry(self, info_all, bdata, timestamp):
        self.time_start = timestamp

        if info_all & READ_ERROR:
            self.read_error = 1

        if info_all & ~READ_ERROR:
            self.info_all = info_all
            self.arg_first = (info_all >> 2) & 0x7  # bits 2-4
            self.arg_last = (info_all >> 5) & 0x7  # bits 5-7
            self.will_be_cont = (info_all >> 8) & 0x1  # bit 8 (will be continued)
            self.is_cont = (info_all >> 9) & 0x1  # bit 9 (is a continuation)

        if self.state == STATE_INIT and self.arg_first > FIRST_PACKET:
            self.log_parse.error("missed first packet of syscall : {0:s}".format(self.name))
            self.log_parse.error("       packet       : 0x{0:x}".format(self.info_all))
            self.log_parse.error("       arg_first    : {0:d}".format(self.arg_first))
            self.log_parse.error("       arg_last     : {0:d}".format(self.arg_last))
            self.log_parse.error("       will_be_cont : {0:d}".format(self.will_be_cont))
            self.log_parse.error("       is_cont      : {0:d}".format(self.is_cont))
            self.state = STATE_CORRUPTED_ENTRY
            return self.state

        # check if it is a continuation of a string
        if self.arg_first == self.arg_last:
            assert_msg(self.is_cont == 1, "packet is not marked as a continuation, input file may be corrupted")

            if self.str_fini:
                return self.state

            if len(bdata) <= self.size_fmt_args:
                self.state = STATE_CORRUPTED_ENTRY
                return self.state

            buf_str = bdata[self.size_fmt_args:]
            str_p = str(buf_str.decode(errors="ignore"))
            str_p = str_p.split('\0')[0]
            self.string += str_p
            max_len = self.buf_size - 2

            # check if string ended
            if len(str_p) == (max_len + 1):
                # string did not end
                self.str_fini = 0

                if self.will_be_cont == 0:
                    # error: string is truncated
                    self.truncated = len(self.strings) + 1  # set it to string index + 1
                    self.str_fini = 1
            else:
                # string is completed, save it
                self.str_fini = 1

            if self.str_fini:
                self.strings.append(self.string)
                self.args.append(len(self.strings) - 1)
                self.string = ""

            # return from: if self.arg_first == self.arg_last
            return self.state

        # is it a continuation of last argument (full name mode)?
        if self.is_cont:
            # it is a continuation of the last string argument
            if self.str_fini:
                # printing string was already finished, so skip it
                self.arg_first += 1
                self.is_cont = 0
                self.str_fini = 0
        else:
            # syscall.arg_first argument was printed in the previous packet
            self.arg_first += 1

        # is it the last packet of this syscall (end of syscall) ?
        if self.arg_last == LAST_PACKET:
            end_of_syscall = 1
            # and set the true number of the last argument
            self.arg_last = self.nargs
        else:
            end_of_syscall = 0

        data_args = bdata[0: self.size_fmt_args]
        buf_str = bdata[self.size_fmt_args:]

        if len(data_args) < self.size_fmt_args:
            if self.nargs == 0:
                self.content = CNT_ENTRY
                self.state = STATE_ENTRY_COMPLETED
            else:
                self.state = STATE_CORRUPTED_ENTRY

            return self.state

        args = struct.unpack(self.fmt_args, data_args)

        for n in range((self.arg_first - 1), self.arg_last):
            if self.is_string(n):
                index = self.get_str_arg(buf_str)
                if index >= 0:
                    self.args.append(index)
            else:
                self.args.append(args[n])

        if end_of_syscall:
            self.num_str = 0  # reset counter of string arguments
            self.str_fini = 1
            self.content = CNT_ENTRY

            if self.mask & EM_no_ret:  # SyS_exit and SyS_exit_group do not return
                self.state = STATE_COMPLETED
            else:
                self.state = STATE_ENTRY_COMPLETED
        else:
            self.state = STATE_IN_ENTRY

        return self.state

    ####################################################################################################################
    def get_return_value(self, bdata):
        assert_msg(len(bdata) >= self.size_fmt_exit, "no return value, input file may be corrupted")
        bret = bdata[0: self.size_fmt_exit]
        retval, = struct.unpack(self.fmt_exit, bret)
        return retval

    ####################################################################################################################
    # save_exit -- save the exit info to the syscall record
    ####################################################################################################################
    def save_exit(self, retval, timestamp):
        if self.state == STATE_INIT:
            self.time_start = timestamp
        self.time_end = timestamp

        # split return value into result and errno
        if retval >= 0:
            self.ret = retval
            self.iret = retval
            self.err = 0
        else:
            self.ret = 0xFFFFFFFFFFFFFFFF
            self.iret = -1
            self.err = -retval

        self.content |= CNT_EXIT

    ####################################################################################################################
    # add_exit -- add the exit info to the syscall record and mark as completed
    ####################################################################################################################
    def add_exit(self, bdata, timestamp):
        retval = self.get_return_value(bdata)
        self.save_exit(retval, timestamp)
        self.state = STATE_COMPLETED
        return self.state

    ####################################################################################################################
    # is_complete -- check if syscall has both entry and exit info completed
    ####################################################################################################################
    def is_complete(self):
        all_data = CNT_ENTRY | CNT_EXIT
        has_only_entry = (self.content & CNT_ENTRY) and (self.mask & EM_no_ret == EM_no_ret)
        has_only_exit = (self.content & CNT_EXIT) and ((self.ret == 0 and self.name in ("clone", "fork", "vfork")) or
                                                       self.sc_id == RT_SIGRETURN_SYS_EXIT)
        return (self.content & all_data == all_data) or has_only_entry or has_only_exit
