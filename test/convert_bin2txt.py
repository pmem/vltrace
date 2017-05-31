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

from sys import exc_info, stderr
import argparse
import struct

DEBUG = 0

STATE_INIT = 0
STATE_IN_ENTRY = 1
STATE_ENTRY_COMPLETED = 2
STATE_COMPLETED = 3
STATE_CORRUPTED_ENTRY = 4
STATE_UNKNOWN_EVENT = 5

CNT_NONE = 0
CNT_ENTRY = 1
CNT_EXIT = 2

E_KP_ENTRY = 0
E_KP_EXIT = 1
E_TP_ENTRY = 2
E_TP_EXIT = 3

CHECK_OK = 0
CHECK_SKIP = 1
CHECK_IGNORE = 2
CHECK_NO_ENTRY = 3
CHECK_NO_EXIT = 4
CHECK_WRONG_ID = 5
CHECK_LOOK_FOR_EXIT = 6
CHECK_REINIT = 7
CHECK_SAVE_IN_ENTRY = 8

DO_REINIT = 0
DO_CONTINUE = 1
DO_GO_ON = 2

EM_no_ret = 1 << 12


###############################################################################
# open_file -- open file with error handling
###############################################################################
def open_file(path, flags):
    fh = -1
    try:
        fh = open(path, flags)
    except FileNotFoundError:
        print("Error: file not found:", path, file=stderr)
        exit(1)
    return fh


###############################################################################
# read_bdata - read binary data from file
###############################################################################
def read_bdata(fh, size):
    bdata = fh.read(size)
    if len(bdata) < size:
        raise EndOfFile(len(bdata))
    return bdata


###############################################################################
# read_fmt_data -- read formatted data from file fh
###############################################################################
def read_fmt_data(fh, fmt):
    size = struct.calcsize(fmt)
    bdata = read_bdata(fh, size)
    return struct.unpack(fmt, bdata)


###############################################################################
class EndOfFile(Exception):
    def __init__(self, val):
        self.val = val

    def __str__(self):
        return repr(self.val)


###############################################################################
class SyscallInfo:
    def __init__(self, num, num_str, pname, name, length, nargs, mask, avail, nstrargs, positions):
        bname = bytes(name)
        sname = str(bname.decode(errors="ignore"))
        name = sname.split('\0')[0]
        name = name[4:]

        self.num = num
        self.num_str = num_str
        self.pname = pname
        self.name = name
        self.length = length
        self.nargs = nargs
        self.mask = mask
        self.avail = avail
        self.nstrargs = nstrargs
        self.positions = positions


###############################################################################
class SyscallTable:
    def __init__(self):
        self.table = []

    def valid_index(self, ind):
        if ind < len(self.table):
            i = ind
        else:
            i = len(self.table) - 1
        return i

    def get(self, ind):
        i = self.valid_index(ind)
        return self.table[i]

    def name(self, ind):
        i = self.valid_index(ind)
        return self.table[i].name

    def read(self, path_to_syscalls_table_dat):
        fmt = 'I4sP32sIIIiI6s6s'
        size_fmt = struct.calcsize(fmt)

        fh = open_file(path_to_syscalls_table_dat, 'rb')

        size_check, = read_fmt_data(fh, 'i')
        if size_check != size_fmt:
            print("Error: wrong format of syscalls table file:", path_to_syscalls_table_dat, file=stderr)
            print("       format size : ", size_fmt, file=stderr)
            print("       data size   : ", size_check, file=stderr)
            return -1

        while True:
            try:
                data = read_fmt_data(fh, fmt)
                num, num_str, pname, name, length, nargs, mask, avail, nstrargs, positions, _padding = data
                syscall = SyscallInfo(num, num_str, pname, name, length, nargs, mask, avail, nstrargs, positions)
            except EndOfFile as err:
                if err.val > 0:
                    print("Input file is truncated:", path_to_syscalls_table_dat, file=stderr)
                break
            except:
                print("Unexpected error:", exc_info()[0], file=stderr)
                raise
            else:
                self.table.append(syscall)

        fh.close()
        return 0


###############################################################################
def is_entry(etype):
    return (etype & 0x01) == 0


###############################################################################
def is_exit(etype):
    return (etype & 0x01) == 1


###############################################################################
class Syscall:
    __str = "---------------- ----------------"
    __arg_str_mask = [1, 2, 4, 8, 16, 32]

    ###############################################################################
    def __init__(self, pid_tid, sc_id, sc_info, buf_size):
        self.state = STATE_INIT
        self.content = CNT_NONE

        self.pid_tid = pid_tid
        self.sc_id = sc_id
        self.time_start = 0
        self.time_end = 0
        self.args = []
        self.ret = 0
        self.err = 0

        self.sc = sc_info
        self.name = sc_info.name

        self.string = ""
        self.num_str = 0
        self.str_fini = -1

        self.packet = 0
        self.arg_begin = 0
        self.arg_end = 7
        self.arg_is_cont = 0
        self.arg_will_cont = 0
        self.truncated = 0

        self.all_strings = []

        self.BUF_SIZE = int(buf_size)
        self.BUF_SIZE_2 = int(buf_size / 2)
        self.BUF_SIZE_3 = int(buf_size / 3)

        self.STR_MAX_1 = self.BUF_SIZE - 2
        self.STR_MAX_2 = self.BUF_SIZE_2 - 2
        self.STR_MAX_3 = self.BUF_SIZE_3 - 2

        self.fmt_args = 'QQQQQQ'
        self.size_fmt_args = struct.calcsize(self.fmt_args)

        self.fmt_exit = 'q'
        self.size_fmt_exit = struct.calcsize(self.fmt_exit)

    ###############################################################################
    def __lt__(self, other):
        return self.time_start < other.time_start

    ###############################################################################
    def is_cont(self):
        return self.arg_begin == self.arg_end

    ###############################################################################
    def is_string(self, n):
        if self.sc.mask & self.__arg_str_mask[n] == self.__arg_str_mask[n]:
            return 1
        else:
            return 0

    ###############################################################################
    def get_str_arg(self, aux_str):
        string = ""
        max_len = 0

        if self.packet:
            max_len = self.STR_MAX_1
            string = aux_str

        elif self.sc.nstrargs == 1:
            max_len = self.STR_MAX_1
            string = aux_str

        elif self.sc.nstrargs == 2:
            max_len = self.STR_MAX_2
            self.num_str += 1
            if self.num_str == 1:
                string = aux_str[0:self.BUF_SIZE_2]
            elif self.num_str == 2:
                string = aux_str[self.BUF_SIZE_2: 2 * self.BUF_SIZE_2]
            else:
                assert (self.num_str <= 2)

        elif self.sc.nstrargs == 3:
            max_len = self.STR_MAX_3
            self.num_str += 1
            if self.num_str == 1:
                string = aux_str[0:self.BUF_SIZE_3]
            elif self.num_str == 2:
                string = aux_str[self.BUF_SIZE_3: 2 * self.BUF_SIZE_3]
            elif self.num_str == 3:
                string = aux_str[2 * self.BUF_SIZE_3: 3 * self.BUF_SIZE_3]
            else:
                assert (self.num_str <= 3)

        else:
            print("\n\nERROR: unsupported number of string arguments:", self.sc.nstrargs)
            assert (self.sc.nstrargs <= 3)

        str_p = str(string.decode(errors="ignore"))
        str_p = str_p.split('\0')[0]
        self.string += str_p

        # check if string ended
        if len(str_p) == (max_len + 1):
            # string did not ended
            self.str_fini = 0
            if self.arg_will_cont == 0:
                # error: string is truncated
                self.truncated = 1
                self.str_fini = 1
        else:
            # string is completed, save it
            self.str_fini = 1

        if self.str_fini:
            self.all_strings.append(self.string)
            self.string = ""
            return len(self.all_strings) - 1
        else:
            return -1

    ###############################################################################
    def print_debug(self):
        if not DEBUG:
            return

        if self.state not in (STATE_IN_ENTRY, STATE_ENTRY_COMPLETED, STATE_COMPLETED):
            print("DEBUG STATE =", self.state)

        if self.state == STATE_ENTRY_COMPLETED:
            self.print_entry()
        elif self.state == STATE_COMPLETED:
            if self.sc.mask & EM_no_ret:
                self.print_entry()
            else:
                self.print_exit()

    ###############################################################################
    def print_always(self):
        if self.state != STATE_COMPLETED:
            print("DEBUG STATE =", self.state)

        self.print_entry()

        if (self.state == STATE_COMPLETED) and (self.sc.mask & EM_no_ret == 0):
            self.print_exit()

    ###############################################################################
    def print(self):
        if DEBUG:
            return
        self.print_always()

    ###############################################################################
    def print_entry(self):
        if not (self.content & CNT_ENTRY):
            return
        print("{0:016X} {1:016X} {2:s} {3:s}".format(
            self.time_start, self.pid_tid, self.__str, self.name), end='')
        for n in range(0, self.sc.nargs):
            print(" ", end='')
            if self.is_string(n):
                print(self.all_strings[self.args[n]], end='')
            else:
                print("{0:016X}".format(self.args[n]), end='')
        print()
        if self.sc.nstrargs != len(self.all_strings):
            print("self.sc.nstrargs =", self.sc.nstrargs)
            print("len(self.all_strings) =", len(self.all_strings))
            assert(self.sc.nstrargs == len(self.all_strings))

    ###############################################################################
    def print_exit(self):
        if not (self.content & CNT_EXIT):
            return
        if self.sc.avail:
            print("{0:016X} {1:016X} {2:016X} {3:016X} {4:s}".format(
                self.time_end, self.pid_tid, self.err, self.ret, self.name))
        else:
            print("{0:016X} {1:016X} {2:016X} {3:016X} sys_exit {4:016X}".format(
                self.time_end, self.pid_tid, self.err, self.ret, self.sc_id))

    ###############################################################################
    def check(self, packet_type, pid_tid, sc_id, name, retval):

        etype = packet_type & 0x03
        ret = CHECK_OK

        if (name == "fork") and is_exit(etype) and (retval == 0):
            return CHECK_IGNORE

        if self.state == STATE_INIT and is_exit(etype):
            if sc_id == 0xFFFFFFFFFFFFFFFF:  # 0xFFFFFFFFFFFFFFFF = sys_exit of rt_sigreturn
                return CHECK_REINIT
            return CHECK_NO_ENTRY

        if self.state == STATE_IN_ENTRY and is_exit(etype):
            print("Error: packet type mismatch:", etype, "state:", self.state)
            return CHECK_SAVE_IN_ENTRY

        if self.state == STATE_ENTRY_COMPLETED and is_entry(etype):
            if self.debug_mode and self.name != "fork":
                print("Notice: exit info not found:", self.name)
            return CHECK_NO_EXIT

        if pid_tid != self.pid_tid or sc_id != self.sc_id:
            ret = CHECK_WRONG_ID

        if (ret == CHECK_WRONG_ID) and (self.state == STATE_ENTRY_COMPLETED) and is_exit(etype):
            return CHECK_LOOK_FOR_EXIT

        return ret

    ###############################################################################
    def add_data(self, packet_type, bdata, timestamp):
        etype = packet_type & 0x03
        packet_type >>= 2
        if etype == E_KP_ENTRY:
            assert (self.state in (STATE_INIT, STATE_IN_ENTRY))
            # kprobe entry handler
            return self.add_kprobe_entry(packet_type, bdata, timestamp)
        elif (etype == E_KP_EXIT) or (etype == E_TP_EXIT):
            # kprobe exit handler or raw tracepoint sys_exit
            return self.add_exit(bdata, timestamp)
        else:
            return STATE_UNKNOWN_EVENT

    ###############################################################################
    def add_kprobe_entry(self, packet, bdata, timestamp):
        self.time_start = timestamp
        if packet:
            self.packet = packet
            self.arg_begin = packet & 0x7  # bits 0-2
            self.arg_end = (packet >> 3) & 0x7  # bits 3-5
            self.arg_will_cont = (packet >> 6) & 0x1  # bit 6 (will be continued)
            self.arg_is_cont = (packet >> 7) & 0x1  # bit 7 (is a continuation)

        if self.state == STATE_INIT and self.arg_begin > 0:
            print("Error: missed first packet:", self.name, file=stderr)
            self.state = STATE_CORRUPTED_ENTRY
            return self.state

        # is it a continuation of a string ?
        if self.is_cont():
            if self.str_fini:
                return self.state
            if len(bdata) <= self.size_fmt_args:
                self.state = STATE_CORRUPTED_ENTRY
                return self.state
            aux_str = bdata[self.size_fmt_args:]

            str_p = str(aux_str.decode(errors="ignore"))
            str_p = str_p.split('\0')[0]

            self.string += str_p

            max_len = self.BUF_SIZE - 2
            # check if string ended
            if len(str_p) == (max_len + 1):
                # string did not ended
                self.str_fini = 0
                if self.arg_will_cont == 0:
                    # error: string is truncated
                    self.truncated = 1
                    self.str_fini = 1
            else:
                # string is completed, save it
                self.str_fini = 1

            if self.str_fini:
                self.all_strings.append(self.string)
                self.args.append(len(self.all_strings) - 1)
                self.string = ""

            return self.state

        # is it a continuation of last argument (full name mode)?
        if self.arg_is_cont:
            # it is a continuation of the last string argument
            if self.str_fini:
                # printing string was already finished, so skip it
                self.arg_begin += 1
                self.arg_is_cont = 0
                self.str_fini = 0
        else:
            # syscall.arg_begin argument was printed in the previous packet
            self.arg_begin += 1

        # is it the last packet of this syscall (end of syscall) ?
        if self.arg_end == 7:
            end_of_syscall = 1
            # and set the true number of the last argument
            self.arg_end = self.sc.nargs
        else:
            end_of_syscall = 0

        data_args = bdata[0: self.size_fmt_args]
        aux_str = bdata[self.size_fmt_args:]

        if len(data_args) < self.size_fmt_args:
            if self.sc.nargs == 0:
                self.content = CNT_ENTRY
                self.state = STATE_ENTRY_COMPLETED
            else:
                self.state = STATE_CORRUPTED_ENTRY
            return self.state

        args = struct.unpack(self.fmt_args, data_args)

        for n in range((self.arg_begin - 1), self.arg_end):
            if self.is_string(n):
                index = self.get_str_arg(aux_str)
                if index >= 0:
                    if len(self.args) < n + 1:
                        self.args.append(index)
                    else:
                        self.args[n] = index
            else:
                if len(self.args) < n + 1:
                    self.args.append(args[n])
                else:
                    self.args[n] = args[n]

        if end_of_syscall:
            self.num_str = 0  # reset counter of string arguments
            self.str_fini = 1
            self.content = CNT_ENTRY
            if self.sc.mask & EM_no_ret:  # SyS_exit and SyS_exit_group do not return
                self.state = STATE_COMPLETED
            else:
                self.state = STATE_ENTRY_COMPLETED
        else:
            self.state = STATE_IN_ENTRY

        return self.state

    ###############################################################################
    def get_ret(self, bdata):
        retval = -1
        if len(bdata) >= self.size_fmt_exit:
            bret = bdata[0: self.size_fmt_exit]
            retval, = struct.unpack(self.fmt_exit, bret)
        return retval

    ###############################################################################
    def add_exit(self, bdata, timestamp):
        if self.state == STATE_INIT:
            self.time_start = timestamp
        self.time_end = timestamp

        retval = self.get_ret(bdata)

        # split return value into result and errno
        if retval >= 0:
            self.ret = retval
            self.err = 0
        else:
            self.ret = 0xFFFFFFFFFFFFFFFF
            self.err = -retval

        self.content |= CNT_EXIT
        self.state = STATE_COMPLETED

        return self.state


###############################################################################
# ListSyscalls
###############################################################################
class ListSyscalls(list):

    def __init__(self):
        list.__init__(self)
        self.time0 = 0

    def get_rel_time(self, timestamp):
        if self.time0:
            return timestamp - self.time0
        else:
            self.time0 = timestamp
            return 0

    def make_time_relative(self):
        for n in range(len(self)):
            self[n].time_start = self.get_rel_time(self[n].time_start)
            self[n].time_end = self.get_rel_time(self[n].time_end)

    def print(self):
        for n in range(len(self)):
            syscall = self[n]
            syscall.print()

    def print_always(self):
        for n in range(len(self)):
            syscall = self[n]
            syscall.print_always()

    def search(self, packet_type, pid_tid, sc_id, name, retval):
        for n in range(len(self)):
            syscall = self[n]
            check = syscall.check(packet_type, pid_tid, sc_id, name, retval)
            #  print("CHECK =", check)
            if check == CHECK_OK:
                del self[n]
                return syscall
        return -1


###############################################################################
# AnalyzingTool
###############################################################################
class AnalyzingTool:

    def __init__(self):
        self.syscall_table = []
        self.syscall = []

        self.list_ok = ListSyscalls()
        self.list_no_exit = ListSyscalls()
        self.list_in_entry = ListSyscalls()

    def read_syscall_table(self, path_to_syscalls_table_dat):
        self.syscall_table = SyscallTable()
        if self.syscall_table.read(path_to_syscalls_table_dat):
            print("Error while reading syscalls table")
            exit(-1)

    def print_log(self):
        self.list_ok.print()

        if len(self.list_in_entry):
            print("\nWarning: list 'list_in_entry' is not empty!")
            self.list_in_entry.sort()
            self.list_in_entry.make_time_relative()
            self.list_in_entry.print_always()

        if len(self.list_no_exit):
            print("\nNotice: list 'list_no_exit' is not empty!")
            self.list_no_exit.sort()
            self.list_no_exit.make_time_relative()
            self.list_no_exit.print_always()

    ###############################################################################
    # analyze_check - analyze check result
    ###############################################################################
    def analyze_check(self, check, packet_type, pid_tid, sc_id, name, retval):

        if CHECK_IGNORE == check:
            return DO_CONTINUE

        elif CHECK_SKIP == check:
            if DEBUG:
                print("Warning: skipping wrong packet type {0:d} of {1:s} ({2:d})"
                      .format(packet_type, self.syscall_table.name(sc_id), sc_id))
            return DO_CONTINUE

        elif CHECK_NO_ENTRY == check:
            self.syscall = self.list_no_exit.search(packet_type, pid_tid, sc_id, name, retval)
            if self.syscall == -1:
                if self.debug_mode:
                    print("Notice: NO ENTRY found: exit without entry info found: {0:s} (sc_id:{1:d})"
                          .format(name, sc_id))
                return DO_REINIT
            return DO_GO_ON

        elif CHECK_NO_EXIT == check:
            self.list_no_exit.append(self.syscall)
            return DO_REINIT

        elif CHECK_LOOK_FOR_EXIT == check:
            old_syscall = self.syscall
            self.syscall = self.list_no_exit.search(packet_type, pid_tid, sc_id, name, retval)
            self.list_no_exit.append(old_syscall)
            if self.syscall == -1:
                if DEBUG:
                    print("Notice: CHECK_LOOK_FOR_EXIT: no EXIT found")
                return DO_REINIT
            return DO_GO_ON

        elif CHECK_WRONG_ID == check:
            print("ERROR: CHECK_WRONG_ID")
            return DO_REINIT

        elif CHECK_SAVE_IN_ENTRY == check:
            self.list_in_entry.append(self.syscall)
            self.syscall = self.list_no_exit.search(packet_type, pid_tid, sc_id, name, retval)
            if self.syscall == -1:
                print("ERROR: CHECK_SAVE_IN_ENTRY: no EXIT found")
                return DO_REINIT
            return DO_GO_ON

    ###############################################################################
    # read_and_parse_data - read and parse data
    ###############################################################################
    def read_and_parse_data(self, path_to_trace_log):
        sizei = struct.calcsize('i')
        sizeI = struct.calcsize('I')
        sizeQ = struct.calcsize('Q')

        fh = open_file(path_to_trace_log, 'rb')

        # read and init global BUF_SIZE
        BUF_SIZE, = read_fmt_data(fh, 'i')

        # read length of CWD
        cwd_len, = read_fmt_data(fh, 'i')
        bdata = fh.read(cwd_len)
        cwd = str(bdata.decode(errors="ignore"))
        CWD = cwd.replace('\0', ' ')
        print("Current working directory:", CWD)

        # read header = command line
        data_size, argc = read_fmt_data(fh, 'ii')
        data_size -= sizei
        bdata = fh.read(data_size)
        argv = str(bdata.decode(errors="ignore"))
        argv = argv.replace('\0', ' ')
        print("Command line:", argv)

        state = STATE_INIT
        while True:
            try:
                if state == STATE_COMPLETED:
                    state = STATE_INIT

                data_size, packet_type, pid_tid, sc_id, timestamp = read_fmt_data(fh, 'IIQQQ')
                data_size = data_size - (sizeI + 3 * sizeQ)

                # read the rest of data
                bdata = read_bdata(fh, data_size)

                if state == STATE_INIT:
                    # noinspection PyTypeChecker
                    self.syscall = Syscall(pid_tid, sc_id, self.syscall_table.get(sc_id), BUF_SIZE)

                name = self.syscall_table.name(sc_id)
                retval = self.syscall.get_ret(bdata)

                check = self.syscall.check(packet_type, pid_tid, sc_id, name, retval)
                result = self.analyze_check(check, packet_type, pid_tid, sc_id, name, retval)
                if result == DO_CONTINUE:
                    continue
                elif result == DO_REINIT:
                    # noinspection PyTypeChecker
                    self.syscall = Syscall(pid_tid, sc_id, self.syscall_table.get(sc_id), BUF_SIZE)

                state = self.syscall.add_data(packet_type, bdata, timestamp)

                if state == STATE_COMPLETED:
                    self.list_ok.append(self.syscall)

                self.syscall.print_debug()

            except EndOfFile as err:
                if err.val > 0:
                    print("Log file is truncated:", path_to_trace_log, file=stderr)
                break
            except:
                print("Unexpected error:", exc_info()[0], file=stderr)
                raise

        fh.close()

        if len(self.list_in_entry):
            self.list_ok += self.list_in_entry

        if len(self.list_no_exit):
            self.list_ok += self.list_no_exit

        self.list_ok.sort()
        self.list_ok.make_time_relative()


###############################################################################
# main
###############################################################################

def main():
    parser = argparse.ArgumentParser(description="Convert tracing logs from binary to text format")
    parser.add_argument("-s", "--table", required=True, help="path to 'syscalls_table.dat'")
    parser.add_argument("-b", "--binlog", required=True, help="input file - tracing log in binary format")
    parser.add_argument("-t", "--txtlog", required=False, help="output file - tracing log in text format")
    args = parser.parse_args()

    at = AnalyzingTool()
    at.read_syscall_table(args.table)
    at.read_and_parse_data(args.binlog)
    at.print_log()

if __name__ == "__main__":
    main()
