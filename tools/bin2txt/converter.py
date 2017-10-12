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

from os import stat

from syscall import *
from syscalltable import *

# minimum required version of vltrace log
VLTRACE_VMAJOR = 0
VLTRACE_VMINOR = 1

VLTRACE_TAB_SIGNATURE = "VLTRACE_TAB"  # signature of vltrace syscall table
VLTRACE_LOG_SIGNATURE = "VLTRACE_LOG"  # signature of vltrace log

# currently only the x86_64 architecture is supported
ARCH_x86_64 = 1
Archs = ["Unknown", "x86_64"]

DO_GO_ON = 0
DO_REINIT = 1

SYSCALL_NOT_FOUND = -1


########################################################################################################################
# Converter
########################################################################################################################
class Converter:
    def __init__(self, fileout, max_packets, offline_mode, script_mode, debug_mode, verbose_mode):

        self.script_mode = script_mode
        self.debug_mode = debug_mode
        self.offline_mode = offline_mode
        self.verbose_mode = verbose_mode

        self.print_progress = not (self.debug_mode or self.script_mode or not self.offline_mode)
        self.print_single_record = not self.offline_mode

        self.syscall_table = SyscallTable()
        self.syscall = Syscall(0, 0, SyscallInfo("", 0, 0, 0), 0, 0)
        self.buf_size = 0

        if max_packets:
            self.max_packets = int(max_packets)
        else:
            self.max_packets = -1

        log_format = '%(levelname)s(%(name)s): %(message)s'

        if debug_mode:
            level = logging.DEBUG
        elif verbose_mode:
            level = logging.INFO
        else:
            level = logging.WARNING

        if fileout:
            logging.basicConfig(format=log_format, level=level, filename=fileout)
        else:
            logging.basicConfig(format=log_format, level=level)

        self.log_conv = logging.getLogger("converter")

        self.list_ok = list()
        self.list_no_exit = list()
        self.list_no_entry = list()
        self.list_others = list()

    ####################################################################################################################
    def read_syscall_table(self, fh):
        self.syscall_table.read_syscall_table(fh)

    ####################################################################################################################
    @staticmethod
    def print_always(alist):
        for syscall in alist:
            syscall.print_always()

    ####################################################################################################################
    def print_other_lists(self):
        if len(self.list_no_entry):
            print("\nWARNING: list 'list_no_entry' is not empty!")
            self.print_always(self.list_no_entry)

        if len(self.list_no_exit):
            print("\nWARNING: list 'list_no_exit' is not empty!")
            self.print_always(self.list_no_exit)

        if len(self.list_others):
            print("\nWARNING: list 'list_others' is not empty!")
            self.print_always(self.list_others)

    ####################################################################################################################
    def print_log(self):
        self.print_always(self.list_ok)

    ####################################################################################################################
    def process_complete_syscall(self, syscall):  # pragma: no cover - overloaded method cannot be tested
        assert(syscall.is_complete())

        if self.offline_mode:
            self.list_ok.append(syscall)

        return syscall

    ####################################################################################################################
    # look_for_matching_record -- look for matching record in a list of incomplete syscalls
    ####################################################################################################################
    @staticmethod
    def look_for_matching_record(alist, info_all, pid_tid, sc_id, name, retval):
        for syscall in alist:
            check = syscall.check_read_data(info_all, pid_tid, sc_id, name, retval, DEBUG_OFF)
            if check == CHECK_OK:
                alist.remove(syscall)
                return syscall
        return SYSCALL_NOT_FOUND

    ####################################################################################################################
    # decide_what_to_do_next - decide what to do next basing on the check done
    ####################################################################################################################
    def decide_what_to_do_next(self, check, info_all, pid_tid, sc_id, name, retval, timestamp):

        if CHECK_NO_EXIT == check:
            syscall = self.look_for_matching_record(self.list_no_entry, self.syscall.info_all, self.syscall.pid_tid,
                                                    self.syscall.sc_id, self.syscall.name, self.syscall.ret)
            if syscall == SYSCALL_NOT_FOUND:
                self.list_no_exit.append(self.syscall)
                self.syscall.log_parse.debug("Notice: no exit info found, packet saved to 'list_no_exit': "
                                             "{0:016X} {1:s}".format(self.syscall.pid_tid, self.syscall.name))
                return DO_REINIT

            self.syscall.log_parse.debug("Notice: found matching exit for syscall: {0:016X} {1:s}"
                                         .format(self.syscall.pid_tid, self.syscall.name))
            self.syscall.save_exit(syscall.ret, syscall.time_end)
            self.syscall.state = STATE_COMPLETED
            self.syscall = self.process_complete_syscall(self.syscall)
            return DO_REINIT

        if CHECK_NO_ENTRY == check:
            syscall = self.look_for_matching_record(self.list_no_exit, info_all, pid_tid, sc_id, name, retval)
            if syscall == SYSCALL_NOT_FOUND:
                self.syscall.log_parse.debug("WARNING: no entry found: exit without entry info found: {0:016X} {1:s}"
                                             .format(pid_tid, name))
                self.syscall.save_exit(retval, timestamp)
                self.list_no_entry.append(self.syscall)
                self.syscall.log_parse.debug("Notice: packet saved (to 'list_no_entry'): {0:016X} {1:s}"
                                             .format(self.syscall.pid_tid, self.syscall.name))
                return DO_REINIT

            self.syscall = syscall
            self.syscall.log_parse.debug("Notice: found matching entry for syscall: {0:016X} {1:s}"
                                         .format(pid_tid, name))
            return DO_GO_ON

        if CHECK_NOT_FIRST_PACKET == check:
            syscall = self.look_for_matching_record(self.list_others, info_all, pid_tid, sc_id, name, retval)
            if syscall == SYSCALL_NOT_FOUND:
                self.syscall.log_parse.debug("WARNING: no matching first packet found: {0:016X} {1:s}"
                                             .format(pid_tid, name))
                return DO_REINIT

            self.syscall = syscall
            self.syscall.log_parse.debug("Notice: found matching first packet for syscall: {0:016X} {1:s}"
                                         .format(pid_tid, name))
            return DO_GO_ON

        if check in (CHECK_SAVE_IN_ENTRY, CHECK_WRONG_ID):
            self.list_others.append(self.syscall)
            self.syscall.log_parse.debug("Notice: packet saved (to 'list_others'): {0:016X} {1:s}"
                                         .format(self.syscall.pid_tid, self.syscall.name))
            return DO_REINIT

        return DO_GO_ON

    ####################################################################################################################
    # analyse_read_data - analyse the read data
    ####################################################################################################################
    def analyse_read_data(self, state, info_all, pid_tid, sc_id, bdata, timestamp):
        sc_info = self.syscall_table.get(sc_id)
        name = self.syscall_table.name(sc_id)
        retval = self.syscall.get_return_value(bdata)

        result = DO_REINIT
        while result != DO_GO_ON:

            if state == STATE_COMPLETED:
                state = STATE_INIT

            if state == STATE_INIT:
                self.syscall = Syscall(pid_tid, sc_id, sc_info, self.buf_size, self.debug_mode)

            check = self.syscall.check_read_data(info_all, pid_tid, sc_id, name, retval, DEBUG_ON)
            result = self.decide_what_to_do_next(check, info_all, pid_tid, sc_id, name, retval, timestamp)

            if result == DO_REINIT:
                if state == STATE_INIT:
                    self.syscall = Syscall(pid_tid, sc_id, sc_info, self.buf_size, self.debug_mode)
                    return state, self.syscall

                state = STATE_INIT

        return state, self.syscall

    ####################################################################################################################
    # check_signature -- check signature
    ####################################################################################################################
    @staticmethod
    def check_signature(fh, signature):
        sign, = read_fmt_data(fh, '12s')
        bsign = bytes(sign)
        sign = str(bsign.decode(errors="ignore"))
        sign = sign.split('\0')[0]

        if sign != signature:
            raise CriticalError("wrong signature of vltrace log: {0:s} (expected: {1:s})".format(sign, signature))

    ####################################################################################################################
    # check_version -- check version
    ####################################################################################################################
    @staticmethod
    def check_version(fh, major, minor):
        vmajor, vminor, vpatch = read_fmt_data(fh, 'III')
        if vmajor < major or (vmajor == major and vminor < minor):
            raise CriticalError("wrong version of vltrace log: {0:d}.{1:d}.{2:d} (required: {3:d}.{4:d}.0 or later)"
                                .format(vmajor, vminor, vpatch, major, minor))

    ####################################################################################################################
    # check_architecture -- check hardware architecture
    ####################################################################################################################
    @staticmethod
    def check_architecture(fh, architecture):
        arch, = read_fmt_data(fh, 'I')
        if arch != architecture:
            if arch in range(len(Archs)):
                iarch = arch
            else:
                iarch = 0

            raise CriticalError("wrong architecture of vltrace log: {0:s} ({1:d}) (required: {2:s})"
                                .format(Archs[iarch], arch, Archs[architecture]))

    ####################################################################################################################
    def process_cwd(self, cwd):  # pragma: no cover - overloaded method cannot be tested
        return

    ####################################################################################################################
    # read_and_parse_data - read and parse data from a vltrace binary log file
    ####################################################################################################################
    # noinspection PyUnboundLocalVariable
    def read_and_parse_data(self, path_to_trace_log):
        sizei = struct.calcsize('i')
        sizeI = struct.calcsize('I')
        sizeQ = struct.calcsize('Q')
        sizeIQQQ = sizeI + 3 * sizeQ

        file_size = 0

        fh = open_file(path_to_trace_log, 'rb')

        try:
            statinfo = stat(path_to_trace_log)
            file_size = statinfo.st_size

            self.check_signature(fh, VLTRACE_TAB_SIGNATURE)
            self.check_version(fh, VLTRACE_VMAJOR, VLTRACE_VMINOR)
            self.check_architecture(fh, ARCH_x86_64)

            self.read_syscall_table(fh)

            self.check_signature(fh, VLTRACE_LOG_SIGNATURE)

            # read and init global buf_size
            self.buf_size, = read_fmt_data(fh, 'i')

            # read length of CWD
            cwd_len, = read_fmt_data(fh, 'i')

            # read CWD
            bdata = read_bdata(fh, cwd_len)

            # decode and set CWD
            cwd = str(bdata.decode(errors="ignore"))
            cwd = cwd.split('\0')[0]
            self.process_cwd(cwd)

            # read header = command line
            data_size, argc = read_fmt_data(fh, 'ii')
            data_size -= sizei  # subtract size of argc only, because 'data_size' does not include its own size
            bdata = read_bdata(fh, data_size)
            argv = str(bdata.decode(errors="ignore"))
            argv = argv.replace('\0', ' ')

        except EndOfFile:
            print("ERROR: log file is truncated: {0:s}".format(path_to_trace_log), file=stderr)
            exit(-1)

        except CriticalError as err:
            print("ERROR: {0:s}".format(err.message), file=stderr)
            exit(-1)

        except:  # pragma: no cover
            print("ERROR: unexpected error", file=stderr)
            raise

        if not self.script_mode:
            # noinspection PyTypeChecker
            self.log_conv.info("Command line: {0:s}".format(argv))
            # noinspection PyTypeChecker
            self.log_conv.info("Current working directory: {0:s}\n".format(cwd))
            print("Reading packets:")

        n = 0
        state = STATE_INIT
        while True:
            try:
                if n >= self.max_packets > 0:
                    if not self.script_mode:
                        print("done (read maximum number of packets: {0:d})".format(n))
                    break

                # read data from the file
                data_size, info_all, pid_tid, sc_id, timestamp = read_fmt_data(fh, 'IIQQQ')
                # subtract size of all read fields except of 'data_size' itself,
                # because 'data_size' does not include its own size
                data_size -= sizeIQQQ
                bdata = read_bdata(fh, data_size)

                # print progress
                n += 1
                if self.print_progress:
                    print("\r{0:d} ({1:d}% bytes) ".format(n, int((100 * fh.tell()) / file_size)), end=' ')

                # analyse the read data and assign 'self.syscall' appropriately
                state, self.syscall = self.analyse_read_data(state, info_all, pid_tid, sc_id, bdata, timestamp)

                # add the read data to the syscall record
                state = self.syscall.add_data(info_all, bdata, timestamp)

                if state == STATE_COMPLETED and self.syscall.is_complete():
                    self.syscall = self.process_complete_syscall(self.syscall)

                if self.print_single_record:
                    self.syscall.print_single_record(DEBUG_OFF)
                elif self.debug_mode:
                    self.syscall.print_single_record(DEBUG_ON)

                if self.syscall.truncated:
                    string = self.syscall.strings[self.syscall.truncated - 1]
                    self.syscall.log_parse.error("string argument is truncated: {0:s}".format(string))

            except CriticalError as err:
                print("ERROR: {0:s}".format(err.message), file=stderr)
                exit(-1)

            except EndOfFile:
                break

            except:  # pragma: no cover
                print("ERROR: unexpected error", file=stderr)
                raise

        fh.close()

        if self.print_progress:
            print("\rDone (read {0:d} packets).".format(n))

        if len(self.list_no_entry):
            self.list_ok += self.list_no_entry
        if len(self.list_no_exit):
            self.list_ok += self.list_no_exit
        if len(self.list_others):
            self.list_ok += self.list_others
        self.list_ok.sort()
