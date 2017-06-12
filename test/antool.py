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

from sys import exc_info, stderr, stdout
import argparse
import struct

RESULT_SUPPORTED = 0
RESULT_YET_UNSUPPORTED = 1
RESULT_UNSUPPORTED_RELATIVE = 2
RESULT_UNSUPPORTED_FLAG = 3
RESULT_UNSUPPORTED = 4

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
CHECK_WRONG_EXIT = 6
CHECK_SAVE_IN_ENTRY = 7

DO_REINIT = 0
DO_CONTINUE = 1
DO_GO_ON = 2

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
EM_no_ret = 1 << 20  # syscall does not return
EM_rfd = 1 << 21  # syscall returns a file descriptor

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

FLAG_RENAME_WHITEOUT = (1 << 2)  # renameat2's flag: whiteout source
FLAG_O_ASYNC = 0o20000  # open's flag

# fallocate flags:
F_FALLOC_FL_COLLAPSE_RANGE = 0x08
F_FALLOC_FL_ZERO_RANGE = 0x10
F_FALLOC_FL_INSERT_RANGE = 0x20

# fcntl's flags:
F_SETFD = 2
F_SETOWN = 8
F_GETOWN = 9
F_SETSIG = 10
F_GETSIG = 11
F_SETOWN_EX = 15
F_GETOWN_EX = 16
F_OFD_GETLK = 36
F_OFD_SETLK = 37
F_OFD_SETLKW = 38
F_SETLEASE = 1024
F_GETLEASE = 1025
F_NOTIFY = 1026
F_ADD_SEALS = 1033
F_GET_SEALS = 1034

O_CLOEXEC = 0o2000000
AT_EMPTY_PATH = 0x1000


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
    def __init__(self, pid_tid, sc_id, sc_info, buf_size, debug):
        self.debug_mode = debug
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

        self.sc = sc_info
        self.name = sc_info.name
        self.mask = sc_info.mask

        self.string = ""
        self.num_str = 0
        self.str_fini = -1

        self.packet = 0
        self.arg_begin = 0
        self.arg_end = 7
        self.arg_is_cont = 0
        self.arg_will_cont = 0
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
        self.unsupported = RESULT_SUPPORTED

    def __lt__(self, other):
        return self.time_start < other.time_start

    def is_mask(self, mask):
        return self.mask & mask == mask

    def has_mask(self, mask):
        return self.mask & mask

    def is_cont(self):
        return self.arg_begin == self.arg_end

    ###############################################################################
    def is_string(self, n):
        if self.sc.mask & self.__arg_str_mask[n] == self.__arg_str_mask[n]:
            return 1
        else:
            return 0

    ###############################################################################
    def get_str_arg(self, n, aux_str):
        string = ""
        max_len = 0

        if self.packet:
            max_len = self.str_max_1
            string = aux_str

        elif self.sc.nstrargs == 1:
            max_len = self.str_max_1
            string = aux_str

        elif self.sc.nstrargs == 2:
            max_len = self.str_max_2
            self.num_str += 1
            if self.num_str == 1:
                string = aux_str[0:self.buf_size_2]
            elif self.num_str == 2:
                string = aux_str[self.buf_size_2: 2 * self.buf_size_2]
            else:
                assert (self.num_str <= 2)

        elif self.sc.nstrargs == 3:
            max_len = self.str_max_3
            self.num_str += 1
            if self.num_str == 1:
                string = aux_str[0:self.buf_size_3]
            elif self.num_str == 2:
                string = aux_str[self.buf_size_3: 2 * self.buf_size_3]
            elif self.num_str == 3:
                string = aux_str[2 * self.buf_size_3: 3 * self.buf_size_3]
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
                self.truncated = n + 1
                self.str_fini = 1
        else:
            # string is completed, save it
            self.str_fini = 1

        if self.str_fini:
            self.strings.append(self.string)
            self.string = ""
            return len(self.strings) - 1
        else:
            return -1

    ###############################################################################
    def debug_print(self):
        if self.truncated:
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
        if self.debug_mode and self.state not in (STATE_ENTRY_COMPLETED, STATE_COMPLETED):
            print("DEBUG STATE =", self.state)

        self.print_entry()

        if (self.state == STATE_COMPLETED) and (self.sc.mask & EM_no_ret == 0):
            self.print_exit()

    ###############################################################################
    def print(self):
        if self.debug_mode:
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
                print("{0:s}".format(self.strings[self.args[n]]), end='')
            else:
                print("{0:016X}".format(self.args[n]), end='')
        print()

        if self.sc.nstrargs != len(self.strings):
            print("self.sc.nstrargs =", self.sc.nstrargs)
            print("len(self.strings) =", len(self.strings))
            assert (self.sc.nstrargs == len(self.strings))

    ###############################################################################
    def print_exit(self):
        if not (self.content & CNT_EXIT):
            return
        if len(self.name) > 0:
            print("{0:016X} {1:016X} {2:016X} {3:016X} {4:s}".format(
                self.time_end, self.pid_tid, self.err, self.ret, self.name))
        else:
            print("{0:016X} {1:016X} {2:016X} {3:016X} sys_exit {4:016X}".format(
                self.time_end, self.pid_tid, self.err, self.ret, self.sc_id))

    def print_mismatch_info(self, etype, pid_tid, sc_id, name):
        print("Error: packet type mismatch: etype {0:d} while state {1:d}".format(etype, self.state))
        print("       previous syscall: {0:016X} {1:s} (sc_id:{2:d}) state {3:d}"
              .format(self.pid_tid, self.name, self.sc_id, self.state))
        print("        current syscall: {0:016X} {1:s} (sc_id:{2:d}) etype {3:d}"
              .format(pid_tid, name, sc_id, etype))

    ###############################################################################
    def do_check(self, packet_type, pid_tid, sc_id, name, retval):

        etype = packet_type & 0x03
        ret = CHECK_OK

        if pid_tid != self.pid_tid or sc_id != self.sc_id:
            ret = CHECK_WRONG_ID

        if self.state == STATE_INIT and is_exit(etype):
            if sc_id == 0xFFFFFFFFFFFFFFFF:  # 0xFFFFFFFFFFFFFFFF = sys_exit of rt_sigreturn
                return CHECK_OK
            if retval == 0 and name in ("clone", "fork", "vfork"):
                return CHECK_OK
            return CHECK_NO_ENTRY

        if self.state == STATE_IN_ENTRY and is_exit(etype):
            self.print_mismatch_info(etype, pid_tid, sc_id, name)
            return CHECK_SAVE_IN_ENTRY

        if self.state == STATE_ENTRY_COMPLETED:
            if is_entry(etype):
                if self.debug_mode and self.name not in ("clone", "fork", "vfork"):
                    print("Notice: exit info not found:", self.name)
                return CHECK_NO_EXIT
            elif is_exit(etype) and ret == CHECK_WRONG_ID:
                return CHECK_WRONG_EXIT

        if ret != CHECK_OK:
            self.print_mismatch_info(etype, pid_tid, sc_id, name)

        return ret

    ###############################################################################
    def add_data(self, packet_type, bdata, timestamp):
        etype = packet_type & 0x03
        packet_type >>= 2
        if etype == E_KP_ENTRY:
            if self.state not in (STATE_INIT, STATE_IN_ENTRY):
                print("Error: wrong state for etype == E_KP_ENTRY:", self.state, file=stderr)
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
            print("Error: missed first packet of syscall :", self.name, file=stderr)
            print("       packet :", self.packet, file=stderr)
            print("       arg_begin :", self.arg_begin, file=stderr)
            print("       arg_end :", self.arg_end, file=stderr)
            print("       arg_will_cont :", self.arg_will_cont, file=stderr)
            print("       arg_is_cont :", self.arg_is_cont, file=stderr)

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

            max_len = self.buf_size - 2
            # check if string ended
            if len(str_p) == (max_len + 1):
                # string did not ended
                self.str_fini = 0
                if self.arg_will_cont == 0:
                    # error: string is truncated
                    self.truncated = len(self.args) + 1
                    self.str_fini = 1
            else:
                # string is completed, save it
                self.str_fini = 1

            if self.str_fini:
                self.strings.append(self.string)
                self.args.append(len(self.strings) - 1)
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
                index = self.get_str_arg(n, aux_str)
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
            self.iret = retval
            self.err = 0
        else:
            self.ret = 0xFFFFFFFFFFFFFFFF
            self.iret = -1
            self.err = -retval

        self.content |= CNT_EXIT
        self.state = STATE_COMPLETED

        return self.state


###############################################################################
# ListSyscalls
###############################################################################
# noinspection PyTypeChecker
class ListSyscalls(list):
    def __init__(self, script_mode, debug_mode):
        list.__init__(self)
        self.script_mode = script_mode
        self.debug_mode = debug_mode
        self.cwd = ""
        self.time0 = 0

        self.pid_table = []
        self.npids = 0

        self.all_strings = ["(stdin)", "(stdout)", "(stderr)"]
        self.all_fd_tables = []

        self.pmem_paths = str("")
        self.path_is_pmem = [0, 0, 0]

        self.unsupported_yet = 0
        self.unsupported_rel = 0
        self.unsupported_flag = 0
        self.unsupported = 0

    def check_if_path_is_pmem(self, string):
        string = str(string)
        for n in range(len(self.pmem_paths)):
            if string.find(self.pmem_paths[n]) == 0:
                return 1
        return 0

    def all_strings_append(self, string, is_pmem):
        if self.all_strings.count(string) == 0:
            self.all_strings.append(string)
            self.path_is_pmem.append(is_pmem)
            str_ind = len(self.all_strings) - 1
        else:
            str_ind = self.all_strings.index(string)
        return str_ind

    @staticmethod
    def fd_table_assign(table, fd, val):
        for i in range(len(table), fd + 1):
            table.append(-1)
        table[fd] = val

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
            self[n].print()

    def print_always(self):
        for n in range(len(self)):
            self[n].print_always()

    def search(self, packet_type, pid_tid, sc_id, name, retval):
        for n in range(len(self)):
            syscall = self[n]
            check = syscall.do_check(packet_type, pid_tid, sc_id, name, retval)
            if check == CHECK_OK:
                del self[n]
                return syscall
        return -1

    def count_pids(self, fhout):
        last_pid = -1
        pid_ind = 0
        length = len(self)
        if not self.script_mode:
            print("\nCounting PIDs:")
        for n in range(len(self)):
            if not self.script_mode:
                print("\r{0:d} of {1:d} ({2:d}%)".format(n + 1, length, int((100 * (n + 1)) / length)), end='')
            pid = self[n].pid_tid >> 32
            if pid != last_pid:
                last_pid = pid
                if self.pid_table.count(pid) == 0:
                    self.pid_table.append(pid)
                    pid_ind = len(self.pid_table) - 1
                else:
                    pid_ind = self.pid_table.index(pid)
            self[n].pid_ind = pid_ind
        self.npids = len(self.pid_table)
        if not self.script_mode:
            print(" done.")

        if self.debug_mode:
            for n in range(len(self.pid_table)):
                print("PID[{0:d}] = {1:016X}".format(n, self.pid_table[n]), file=fhout)

    def arg_is_pmem(self, n, narg):
        if narg > self[n].sc.nargs:
            return 0
        narg -= 1
        if self[n].has_mask(Arg_is_path[narg] | Arg_is_fd[narg]):
            str_ind = self[n].args[narg]
            if str_ind != -1 and str_ind < len(self.path_is_pmem) and self.path_is_pmem[str_ind]:
                return 1
        return 0

    def check_fallocate_flags(self, n):
        ret = 0
        if self[n].args[1] == F_FALLOC_FL_COLLAPSE_RANGE:
            self[n].unsupported_flag = "FALLOC_FL_COLLAPSE_RANGE"
            ret = 1
        elif self[n].args[1] == F_FALLOC_FL_ZERO_RANGE:
            self[n].unsupported_flag = "FALLOC_FL_ZERO_RANGE"
            ret = 1
        elif self[n].args[1] == F_FALLOC_FL_INSERT_RANGE:
            self[n].unsupported_flag = "FALLOC_FL_INSERT_RANGE"
            ret = 1
        if ret == 1:
            self[n].unsupported = RESULT_UNSUPPORTED_FLAG
            return 1
        else:
            return 0

    def check_fcntl_flags(self, n):
        ret = 0
        if self[n].args[1] == F_SETFD and (self[n].args[2] & O_CLOEXEC == 0):
            self[n].unsupported_flag = "F_SETFD: not possible to clear O_CLOEXEC flag"
            ret = 1
        elif self[n].args[1] == F_SETOWN:
            self[n].unsupported_flag = "F_SETOWN"
            ret = 1
        elif self[n].args[1] == F_GETOWN:
            self[n].unsupported_flag = "F_GETOWN"
            ret = 1
        elif self[n].args[1] == F_SETSIG:
            self[n].unsupported_flag = "F_SETSIG"
            ret = 1
        elif self[n].args[1] == F_GETSIG:
            self[n].unsupported_flag = "F_GETSIG"
            ret = 1
        elif self[n].args[1] == F_SETOWN_EX:
            self[n].unsupported_flag = "F_SETOWN_EX"
            ret = 1
        elif self[n].args[1] == F_GETOWN_EX:
            self[n].unsupported_flag = "F_GETOWN_EX"
            ret = 1
        elif self[n].args[1] == F_OFD_GETLK:
            self[n].unsupported_flag = "F_OFD_GETLK"
            ret = 1
        elif self[n].args[1] == F_OFD_SETLK:
            self[n].unsupported_flag = "F_OFD_SETLK"
            ret = 1
        elif self[n].args[1] == F_OFD_SETLKW:
            self[n].unsupported_flag = "F_OFD_SETLKW"
            ret = 1
        elif self[n].args[1] == F_SETLEASE:
            self[n].unsupported_flag = "F_SETLEASE"
            ret = 1
        elif self[n].args[1] == F_GETLEASE:
            self[n].unsupported_flag = "F_GETLEASE"
            ret = 1
        elif self[n].args[1] == F_NOTIFY:
            self[n].unsupported_flag = "F_NOTIFY"
            ret = 1
        elif self[n].args[1] == F_ADD_SEALS:
            self[n].unsupported_flag = "F_ADD_SEALS"
            ret = 1
        elif self[n].args[1] == F_GET_SEALS:
            self[n].unsupported_flag = "F_GET_SEALS"
            ret = 1
        if ret == 1:
            self[n].unsupported = RESULT_UNSUPPORTED_FLAG
            return 1
        else:
            return 0

    def check_if_supported(self, n):
        if len(self[n].strings) > 0:
            if (len(self[n].strings[0]) > 0 and self[n].strings[0][0] != '/') or self[n].strings[0] == "":
                if self[n].name in ("chroot", "getxattr", "lgetxattr", "setxattr", "lsetxattr"):
                    self[n].unsupported = RESULT_UNSUPPORTED_RELATIVE
                    return

        if not self[n].is_pmem:
            return

        if self[n].has_mask(EM_rfd):  # open & openat - O_ASYNC
            if (self[n].is_mask(Arg_is_path[0]) and self[n].args[1] & FLAG_O_ASYNC and self[n].name == "open") or \
               (self[n].is_mask(Arg_is_fd[0] | Arg_is_path[1] | EM_fileat) and self[n].args[2] & FLAG_O_ASYNC and
               self[n].name == "openat"):
                self[n].unsupported_flag = "O_ASYNC"
                self[n].unsupported = RESULT_UNSUPPORTED_FLAG
            return

        if self[n].is_mask(EM_isfileat):
            if self[n].name in ("execveat", "name_to_handle_at"):
                self[n].unsupported = RESULT_UNSUPPORTED
            elif self[n].name in ("futimesat", "utimensat"):
                self[n].unsupported = RESULT_YET_UNSUPPORTED
            # renameat2 - RENAME_WHITEOUT
            elif self[n].sc.nargs == 5 and self[n].name in "renameat2" and self[n].args[4] & FLAG_RENAME_WHITEOUT:
                self[n].unsupported_flag = "RENAME_WHITEOUT"
                self[n].unsupported = RESULT_UNSUPPORTED_FLAG
            return

        # fallocate - FALLOC_FL_COLLAPSE_RANGE or FALLOC_FL_ZERO_RANGE or FALLOC_FL_INSERT_RANGE
        if self[n].has_mask(EM_fd_1):
            if self[n].name == "fallocate" and self[n].args[1] & self.check_fallocate_flags(n):
                return
            if self[n].name == "fcntl" and self.check_fcntl_flags(n):
                return

        if self.arg_is_pmem(n, 1):
            if self[n].name in (
                    "chroot", "execve", "readahead",
                    "setxattr", "lsetxattr", "fsetxattr",
                    "listxattr", "llistxattr", "flistxattr",
                    "removexattr", "lremovexattr", "fremovexattr"):
                self[n].unsupported = RESULT_UNSUPPORTED
            elif self[n].name in (
                    "dup", "dup2", "dup3", "utime", "utimes", "flock"):
                self[n].unsupported = RESULT_YET_UNSUPPORTED

        if (self.arg_is_pmem(n, 1) or self.arg_is_pmem(n, 3)) and self[n].name in ("copy_file_range", "splice"):
            self[n].unsupported = RESULT_YET_UNSUPPORTED
            return

        if (self.arg_is_pmem(n, 1) or self.arg_is_pmem(n, 2)) and self[n].name in ("sendfile", "sendfile64"):
            self[n].unsupported = RESULT_YET_UNSUPPORTED
            return

        if self.arg_is_pmem(n, 5) and self[n].name == "mmap":
            self[n].unsupported = RESULT_YET_UNSUPPORTED
            return

        return

    def handle_fileat(self, n, arg1, arg2, fhout):
        dirfd = self[n].args[arg1]
        if dirfd == 0xFFFFFFFFFFFFFF9C:  # AT_FDCWD
            dirfd = -100
        path = self[n].strings[self[n].args[arg2]]
        fd_out = self[n].iret

        # check if AT_EMPTY_PATH is set
        if self[n].sc.nargs > (arg2 + 1) and self[n].has_mask(Arg_is_path[arg2 + 1] | Arg_is_fd[arg2 + 1]) == 0 and\
           self[n].args[arg2 + 1] & AT_EMPTY_PATH:
            path = ""

        dir_str = ""
        newpath = path
        unknown_dirfd = 0
        if (len(path) > 0 and path[0] != '/') or path == "":
            fd_table = self.all_fd_tables[self[n].pid_ind]
            if dirfd == -100:
                dir_str = self.cwd
                newpath = dir_str + "/" + path
            elif 0 <= dirfd < len(fd_table):
                str_ind = fd_table[dirfd]
                self[n].args[arg1] = str_ind
                dir_str = self.all_strings[str_ind]
                newpath = dir_str + "/" + path
            elif self[n].has_mask(EM_rfd) and fd_out != -1:
                unknown_dirfd = 1

        if newpath != path:
            print(" {0:s} {1:s}".format(dir_str, path), end='', file=fhout)
        else:
            print(" ({0:d}) {1:s}".format(dirfd, path), end='', file=fhout)

        is_pmem = self.check_if_path_is_pmem(newpath)
        str_ind = self.all_strings_append(path, is_pmem)
        self[n].args[arg2] = str_ind
        path = newpath
        self[n].is_pmem |= is_pmem
        if is_pmem:
            print(" [PMEM]", end='', file=fhout)
        if unknown_dirfd:
            print("Error: unknown dirfd :", dirfd, file=fhout)
        return path, is_pmem, fd_out

    def match_fd_with_path(self, cwd, pmem_paths, fhout):
        self.cwd = cwd
        paths = str(pmem_paths)
        self.pmem_paths = paths.split(':')

        fd_table = [0, 1, 2]
        for p in range(len(self.pid_table)):
            self.all_fd_tables.append(fd_table)

        length = len(self)
        if not self.script_mode:
            print("\nAnalyzing:")

        for n in range(length):
            if fhout != stdout and not self.script_mode:
                print("\r{0:d} of {1:d} ({2:d}%)".format(n + 1, length, int((100 * (n + 1)) / length)), end='')

            # syscalls: SyS_open or SyS_creat
            if self[n].is_mask(EM_fd_from_path):
                path = self[n].strings[0]
                if len(path) > 0 and path[0] != '/':
                    path = self.cwd + "/" + path
                is_pmem = self.check_if_path_is_pmem(path)
                self[n].is_pmem = is_pmem
                str_ind = self.all_strings_append(path, is_pmem)
                self[n].args[0] = str_ind
                if is_pmem:
                    print("{0:20s} {1:s} [PMEM]".format(self[n].name, path), file=fhout)
                else:
                    print("{0:20s} {1:s}".format(self[n].name, path), file=fhout)
                fd_out = self[n].iret
                if fd_out != -1:
                    fd_table = self.all_fd_tables[self[n].pid_ind]
                    self.fd_table_assign(fd_table, fd_out, str_ind)

            # all *at syscalls
            elif self[n].is_mask(EM_isfileat):
                print("{0:20s}".format(self[n].name), end='', file=fhout)
                path, is_pmem, fd_out = self.handle_fileat(n, 0, 1, fhout)
                # syscall SyS_openat
                if self[n].has_mask(EM_rfd) and fd_out != -1:
                    str_ind = self.all_strings_append(path, is_pmem)
                    fd_table = self.all_fd_tables[self[n].pid_ind]
                    self.fd_table_assign(fd_table, fd_out, str_ind)
                if self[n].is_mask(EM_isfileat2):
                    self.handle_fileat(n, 2, 3, fhout)
                print(file=fhout)

            # syscalls: SyS_dup*
            elif self[n].is_mask(EM_fd_from_fd):
                fd_table = self.all_fd_tables[self[n].pid_ind]
                fd_in = self[n].args[0]
                fd_out = self[n].iret
                if 0 <= fd_in < len(fd_table):
                    str_ind = fd_table[fd_in]
                    self[n].args[0] = str_ind
                    path = self.all_strings[str_ind]
                    if self.path_is_pmem[str_ind]:
                        self[n].is_pmem = 1
                        print("{0:20s} {1:s} [PMEM]".format(self[n].name, path), file=fhout)
                    else:
                        print("{0:20s} {1:s}".format(self[n].name, path), file=fhout)
                    if fd_out != -1:
                        self.fd_table_assign(fd_table, fd_out, str_ind)
                else:
                    self[n].args[0] = -1
                    print("{0:20s} ({1:d})".format(self[n].name, fd_in), file=fhout)
                    if fd_out != -1:
                        print("Error: unknown fd :", fd_in, file=fhout)

            # close ()
            elif self[n].name == "close":
                fd_in = self[n].args[0]
                fd_table = self.all_fd_tables[self[n].pid_ind]
                if 0 <= fd_in < len(fd_table):
                    str_ind = fd_table[fd_in]
                    fd_table[fd_in] = -1
                    path = self.all_strings[str_ind]
                    if self.path_is_pmem[str_ind]:
                        self[n].is_pmem = 1
                        print("{0:20s} {1:s} [PMEM]".format(self[n].name, path), file=fhout)
                    else:
                        print("{0:20s} {1:s}".format(self[n].name, path), file=fhout)
                else:
                    print("{0:20s} (0x{1:016X})".format(self[n].name, fd_in), file=fhout)

            # syscalls with path or file descriptor
            elif self[n].has_mask(EM_path_all | EM_fd_all):
                print("{0:20s}".format(self[n].name), end='', file=fhout)
                for narg in range(self[n].sc.nargs):
                    if self[n].has_mask(Arg_is_str[narg]):
                        path = self[n].strings[self[n].args[narg]]
                        if self[n].has_mask(Arg_is_path[narg]) and len(path) > 0 and path[0] != '/':
                            path = self.cwd + "/" + path
                        is_pmem = self.check_if_path_is_pmem(path)
                        self[n].is_pmem |= is_pmem
                        str_ind = self.all_strings_append(path, is_pmem)
                        self[n].args[narg] = str_ind
                        if is_pmem:
                            print(" {0:s} [PMEM]".format(path), end='', file=fhout)
                        else:
                            print(" {0:s}".format(path), end='', file=fhout)
                    if self[n].has_mask(Arg_is_fd[narg]):
                        fd_table = self.all_fd_tables[self[n].pid_ind]
                        fd = self[n].args[narg]
                        if fd in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
                            fd = -1
                        if 0 <= fd < len(fd_table):
                            str_ind = fd_table[fd]
                            path = self.all_strings[str_ind]
                            if self.path_is_pmem[str_ind]:
                                self[n].is_pmem = 1
                                print(" {0:s} [PMEM]".format(path), end='', file=fhout)
                            else:
                                print(" {0:s}".format(path), end='', file=fhout)
                            self[n].args[narg] = str_ind
                        else:
                            if fd < 1024:
                                print(" ({0:d})".format(fd), end='', file=fhout)
                            else:
                                print(" (0x{0:016X})".format(fd), end='', file=fhout)
                            self[n].args[narg] = -1
                print(file=fhout)

            self.check_if_supported(n)

        if fhout != stdout and not self.script_mode:
            print(" done.")

    def print_local(self, n):
        print("   {0:20s}\t\t".format(self[n].name), end='')
        for nstr in range(len(self[n].strings)):
            print(" {0:s}".format(self[n].strings[nstr]), end='')
        print()

    def print_global(self, n):
        print("   {0:20s}\t\t".format(self[n].name), end='')
        for narg in range(self[n].sc.nargs):
            if self[n].has_mask(Arg_is_str[narg] | Arg_is_fd[narg]):
                str_ind = self[n].args[narg]
                if str_ind != -1:
                    if self.path_is_pmem[str_ind]:
                        print(" {0:s} [PMEM]  ".format(self.all_strings[str_ind]), end='')
                    else:
                        print(" {0:s}".format(self.all_strings[str_ind]), end='')

    def print_unsupported(self, n):
        if not self.unsupported:
            print("\nUnsupported syscall detected:")
            self.unsupported = 1
        self.print_global(n)
        print()

    def print_unsupported_flag(self, n):
        if not self.unsupported_flag:
            print("\nUnsupported syscall's flag detected:")
            self.unsupported_flag = 1
        self.print_global(n)
        print(" [unsupported flag:]", self[n].unsupported_flag)

    def print_unsupported_relative(self, n):
        if not self.unsupported_rel:
            print("\nUnsupported syscall with relative path detected:")
            self.unsupported_rel = 1
        self.print_local(n)

    def print_unsupported_yet(self, n):
        if not self.unsupported_yet:
            print("\nYet-unsupported syscall detected (will be supported):")
            self.unsupported_yet = 1
        self.print_global(n)
        print()

    def print_unsupported_syscalls(self):
        length = len(self)

        for n in range(length):
            if self[n].unsupported == RESULT_UNSUPPORTED:
                self.print_unsupported(n)

        for n in range(length):
            if self[n].unsupported == RESULT_UNSUPPORTED_FLAG:
                self.print_unsupported_flag(n)

        for n in range(length):
            if self[n].unsupported == RESULT_UNSUPPORTED_RELATIVE:
                self.print_unsupported_relative(n)

        for n in range(length):
            if self[n].unsupported == RESULT_YET_UNSUPPORTED:
                self.print_unsupported_yet(n)

        if not self.unsupported and not self.unsupported_rel and not self.unsupported_yet:
            print("\nAll syscalls are supported.")


###############################################################################
# AnalyzingTool
###############################################################################
class AnalyzingTool:
    def __init__(self, fileout, max_packets, script_mode, debug_mode):
        self.script_mode = script_mode
        self.debug_mode = debug_mode
        self.cwd = ""
        self.syscall_table = []
        self.syscall = []

        self.list_ok = ListSyscalls(script_mode, debug_mode)
        self.list_no_exit = ListSyscalls(script_mode, debug_mode)
        self.list_others = ListSyscalls(script_mode, debug_mode)

        if fileout:
            self.fileout = fileout
            self.fhout = open_file(fileout, 'wt')
        else:
            self.fileout = ""
            self.fhout = stdout

        if max_packets:
            self.max_packets = int(max_packets)
        else:
            self.max_packets = -1

    def read_syscall_table(self, path_to_syscalls_table_dat):
        self.syscall_table = SyscallTable()
        if self.syscall_table.read(path_to_syscalls_table_dat):
            print("Error while reading syscalls table", file=stderr)
            exit(-1)

    def print_log(self):
        self.list_ok.print()

        if self.debug_mode and len(self.list_no_exit):
            print("\nWarning: list 'list_no_exit' is not empty!")
            self.list_no_exit.sort()
            self.list_no_exit.print_always()

        if self.debug_mode and len(self.list_others):
            print("\nWarning: list 'list_others' is not empty!")
            self.list_others.sort()
            self.list_others.print_always()

    ###############################################################################
    # analyze_check - analyze check result
    ###############################################################################
    def analyze_check(self, check, packet_type, pid_tid, sc_id, name, retval):

        if CHECK_IGNORE == check:
            return DO_CONTINUE

        elif CHECK_SKIP == check:
            if self.debug_mode:
                print("Warning: skipping wrong packet type {0:d} of {1:s} ({2:d})"
                      .format(packet_type, self.syscall_table.name(sc_id), sc_id))
            return DO_CONTINUE

        elif CHECK_NO_EXIT == check:
            self.list_no_exit.append(self.syscall)
            return DO_REINIT

        elif check in (CHECK_NO_ENTRY, CHECK_SAVE_IN_ENTRY, CHECK_WRONG_EXIT):
            old_syscall = self.syscall
            if CHECK_SAVE_IN_ENTRY == check:
                self.list_others.append(self.syscall)
            if retval != 0 or name not in ("clone", "fork", "vfork"):
                self.syscall = self.list_no_exit.search(packet_type, pid_tid, sc_id, name, retval)
            if CHECK_WRONG_EXIT == check:
                self.list_no_exit.append(old_syscall)
            if retval == 0 and name in ("clone", "fork", "vfork"):
                return DO_REINIT
            if self.debug_mode:
                if self.syscall == -1:
                    print("Warning: NO ENTRY found: exit without entry info found: {0:s} (sc_id:{1:d})"
                          .format(name, sc_id))
                else:
                    print("Notice: found matching ENTRY for: {0:s} (sc_id:{1:d} pid:{2:016X}):"
                          .format(name, sc_id, pid_tid))
            if self.syscall == -1:
                return DO_REINIT
            else:
                return DO_GO_ON

        elif CHECK_WRONG_ID == check:
            self.list_others.append(self.syscall)
            return DO_REINIT

    ###############################################################################
    # read_and_parse_data - read and parse data
    ###############################################################################
    def read_and_parse_data(self, path_to_trace_log):
        sizei = struct.calcsize('i')
        sizeI = struct.calcsize('I')
        sizeQ = struct.calcsize('Q')

        fh = open_file(path_to_trace_log, 'rb')

        # read and init global buf_size
        buf_size, = read_fmt_data(fh, 'i')

        # read length of CWD
        cwd_len, = read_fmt_data(fh, 'i')
        bdata = fh.read(cwd_len)
        cwd = str(bdata.decode(errors="ignore"))
        self.cwd = cwd.replace('\0', ' ')
        print("Current working directory:", self.cwd, file=self.fhout)

        # read header = command line
        data_size, argc = read_fmt_data(fh, 'ii')
        data_size -= sizei
        bdata = fh.read(data_size)
        argv = str(bdata.decode(errors="ignore"))
        argv = argv.replace('\0', ' ')
        print("Command line:", argv, file=self.fhout)

        if not self.debug_mode and not self.script_mode:
            print("Reading packets:")
        n = 0
        state = STATE_INIT
        while True:
            try:
                if not self.debug_mode and not self.script_mode:
                    print("\r{0:d}".format(n), end=' ')
                n += 1

                if state == STATE_COMPLETED:
                    if n > self.max_packets > 0:
                        if not self.script_mode:
                            print("done (read maximum number of packets: {0:d})".format(n - 1))
                        break
                    state = STATE_INIT

                data_size, packet_type, pid_tid, sc_id, timestamp = read_fmt_data(fh, 'IIQQQ')
                data_size = data_size - (sizeI + 3 * sizeQ)

                # read the rest of data
                bdata = read_bdata(fh, data_size)

                if state == STATE_INIT:
                    self.syscall = Syscall(pid_tid, sc_id, self.syscall_table.get(sc_id), buf_size, self.debug_mode)

                name = self.syscall_table.name(sc_id)
                retval = self.syscall.get_ret(bdata)

                check = self.syscall.do_check(packet_type, pid_tid, sc_id, name, retval)
                result = self.analyze_check(check, packet_type, pid_tid, sc_id, name, retval)
                if result == DO_CONTINUE:
                    continue
                elif result == DO_REINIT:
                    self.syscall = Syscall(pid_tid, sc_id, self.syscall_table.get(sc_id), buf_size, self.debug_mode)

                state = self.syscall.add_data(packet_type, bdata, timestamp)

                if state == STATE_COMPLETED:
                    self.list_ok.append(self.syscall)

                if self.debug_mode:
                    self.syscall.debug_print()

                if self.syscall.truncated:
                    truncated = self.syscall.truncated
                    print("Error: string argument number {0:d} is truncated!: {1:s}"
                          .format(truncated, self.syscall.args[truncated - 1]), file=stderr)
                    exit(-1)

            except EndOfFile as err:
                if err.val > 0:
                    print("Warning: log file is truncated:", path_to_trace_log, file=stderr)
                break
            except:
                print("Unexpected error:", exc_info()[0], file=stderr)
                raise

        if not self.debug_mode and not self.script_mode and n <= self.max_packets:
            print("\rDone (read {0:d} packets).".format(n))
        fh.close()

        if len(self.list_no_exit):
            self.list_ok += self.list_no_exit

        if len(self.list_others):
            self.list_ok += self.list_others

        self.list_ok.sort()
        # self.list_ok.make_time_relative()

    def count_pids(self):
        self.list_ok.count_pids(self.fhout)

    def match_fd_with_path(self, pmem_paths):
        self.list_ok.match_fd_with_path(self.cwd, pmem_paths, self.fhout)

    def print_unsupported_syscalls(self):
        self.list_ok.print_unsupported_syscalls()


###############################################################################
# main
###############################################################################

def main():
    parser = argparse.ArgumentParser(
                        description="Analyze vltrace binary logs and check if all syscalls are supported by pmemfile")

    parser.add_argument("-t", "--table", required=True, help="path to vltrace file 'syscalls_table.dat'")
    parser.add_argument("-b", "--binlog", required=True, help="input file - vltrace log in binary format")

    parser.add_argument("-c", "--convert", action='store_true', required=False,
                        help="converter mode - only converts vltrace log from binary to text format")

    parser.add_argument("-p", "--pmem", required=False, help="paths to pmem filesystem")
    parser.add_argument("-m", "--max_packets", required=False, help="maximum number of packets to be read")

    parser.add_argument("-s", "--script", action='store_true', required=False,
                        help="script mode - do not print progress")
    parser.add_argument("-l", "--log", action='store_true', required=False, help="print output log in analyze mode")
    parser.add_argument("-o", "--output", required=False, help="output file")
    parser.add_argument("-d", "--debug", action='store_true', required=False, help="debug mode")

    args = parser.parse_args()

    at = AnalyzingTool(args.output, args.max_packets, args.script, args.debug)
    at.read_syscall_table(args.table)
    at.read_and_parse_data(args.binlog)

    if args.convert or args.log:
        at.print_log()

    if not args.convert:
        at.count_pids()
        at.match_fd_with_path(args.pmem)
        at.print_unsupported_syscalls()


if __name__ == "__main__":
    main()
