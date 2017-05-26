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

STATE_INIT = 0
STATE_IN_ENTRY = 1
STATE_ENTRY = 2
STATE_EXITED = 3
STATE_CORRUPTED = 4
STATE_UNKNOWN_EVENT = 5

E_KP_ENTRY = 0
E_KP_EXIT = 1
E_TP_ENTRY = 2
E_TP_EXIT = 3


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

        self.num = num
        self.num_str = num_str
        self.pname = pname
        self.name = sname.split('\0')[0]
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

    def get(self, ind):
        if ind < len(self.table):
            i = ind
        else:
            i = len(self.table) - 1
        return self.table[i]

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
class Timestamp:
    def __init__(self):
        self.time0 = 0

    def get_rel_time(self, timestamp):
        if self.time0:
            return timestamp - self.time0
        else:
            self.time0 = timestamp
            return 0


###############################################################################
class Syscall:
    __str = "---------------- ----------------"
    __arg_str_mask = [1, 2, 4, 8, 16, 32]

    ###############################################################################
    def __init__(self, pid_tid, sc_id, sc_info, buf_size):
        self.state = STATE_INIT

        self.pid_tid = pid_tid
        self.sc_id = sc_id
        self.time_start = 0
        self.time_end = 0
        self.args = []
        self.ret = 0
        self.err = 0

        self.sc = sc_info
        self.name = sc_info.name
        self.length = sc_info.length

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
    def print_entry(self):
        print("{0:016X} {1:016X} {2:s} {3:s}".format(
            self.time_start, self.pid_tid, self.__str, self.name[4:self.length]), end='')
        for n in range(0, self.sc.nargs):
            print(" ", end='')
            if self.is_string(n):
                print(self.all_strings[self.args[n]], end='')
            else:
                print("{0:016X}".format(self.args[n]), end='')
        print()

    ###############################################################################
    def print_exit(self):
        if self.sc.avail:
            print("{0:016X} {1:016X} {2:016X} {3:016X} {4:s}".format(
                self.time_end, self.pid_tid, self.err, self.ret, self.name[4:self.length]))
        else:
            print("{0:016X} {1:016X} {2:016X} {3:016X} sys_exit {4:016X}".format(
                self.time_end, self.pid_tid, self.err, self.ret, self.sc_id))

    ###############################################################################
    def add_data(self, packet_type, bdata, timestamp):
        etype = packet_type & 0x03
        packet_type >>= 2
        if etype == E_KP_ENTRY:
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
            self.state = STATE_CORRUPTED
            return self.state

        # is it a continuation of a string ?
        if self.is_cont():
            if self.str_fini:
                return self.state
            fmt_args = 'qqqqqq'
            size_fmt_args = struct.calcsize(fmt_args)
            if len(bdata) <= size_fmt_args:
                return self.state
            aux_str = bdata[size_fmt_args:]

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

        fmt_args = 'QQQQQQ'
        size_fmt_args = struct.calcsize(fmt_args)
        data_args = bdata[0: size_fmt_args]
        aux_str = bdata[size_fmt_args:]

        if len(data_args) < size_fmt_args:
            if self.sc.nargs == 0:
                self.state = STATE_ENTRY
            else:
                self.state = STATE_CORRUPTED
            return self.state

        args = struct.unpack(fmt_args, data_args)

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
            self.state = STATE_ENTRY
        else:
            self.state = STATE_IN_ENTRY

        return self.state

    ###############################################################################
    def add_exit(self, bdata, timestamp):
        self.time_end = timestamp

        fmt_exit = 'q'
        size_fmt_exit = struct.calcsize(fmt_exit)
        bdata = bdata[0: size_fmt_exit]
        retval, = struct.unpack(fmt_exit, bdata)

        # split return value into result and errno
        if retval >= 0:
            self.ret = retval
            self.err = 0
        else:
            self.ret = 0xFFFFFFFFFFFFFFFF
            self.err = -retval

        self.state = STATE_EXITED

        return self.state


###############################################################################
# convert_bin2txt - convert binary log to text
###############################################################################
def convert_bin2txt(path_to_syscalls_table_dat, path_to_trace_log):
    sizei = struct.calcsize('i')
    sizeI = struct.calcsize('I')
    sizeQ = struct.calcsize('Q')

    syscall_table = SyscallTable()
    if syscall_table.read(path_to_syscalls_table_dat):
        print("Error while reading syscalls table")
        exit(-1)

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

    ts = Timestamp()
    state = STATE_EXITED
    # read data
    while True:
        try:
            data_size, packet_type, pid_tid, sc_id, timestamp = read_fmt_data(fh, 'IIQQQ')
            data_size = data_size - (sizeI + 3 * sizeQ)

            # read the rest of data
            bdata = read_bdata(fh, data_size)

            timestamp = ts.get_rel_time(timestamp)

            if state != STATE_IN_ENTRY:
                # noinspection PyTypeChecker
                syscall = Syscall(pid_tid, sc_id, syscall_table.get(sc_id), BUF_SIZE)
            state = syscall.add_data(packet_type, bdata, timestamp)

            if state == STATE_ENTRY:
                syscall.print_entry()
            elif state == STATE_EXITED:
                syscall.print_exit()

        except EndOfFile as err:
            if err.val > 0:
                print("Log file is truncated:", path_to_trace_log, file=stderr)
            break
        except:
            print("Unexpected error:", exc_info()[0], file=stderr)
            raise

    fh.close()
    return


###############################################################################
# main
###############################################################################

def main():
    parser = argparse.ArgumentParser(description="Convert tracing logs from binary to text format")
    parser.add_argument("-s", "--table", required=True, help="path to 'syscalls_table.dat'")
    parser.add_argument("-b", "--binlog", required=True, help="input file - tracing log in binary format")
    parser.add_argument("-t", "--txtlog", required=False, help="output file - tracing log in text format")
    args = parser.parse_args()

    convert_bin2txt(args.table, args.binlog)


if __name__ == "__main__":
    main()
