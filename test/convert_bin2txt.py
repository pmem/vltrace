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

BUF_SIZE = 0 # size of buffer for string arguments

Arg_str_mask = (1, 2, 4, 8, 16, 32)
Time_start = 0

Str_fini = 1 # printing last string was finished
N_str = 0    # counter of string arguments

class EndOfFile(Exception):
    def __init__(self, val):
        self.val = val
    def __str__(self):
        return repr(self.val)

###############################################################################
# open_file -- open file with error handling
###############################################################################

def open_file(path, flags):

    try:
        fh = open(path, flags)
    except FileNotFoundError:
        print("Error: file not found:", path, file=stderr)
        exit(1)

    return fh

###############################################################################
# read_data -- read data from file fh
###############################################################################

def read_data(fh, size, fmt):

        bd = fh.read(size)
        if (len(bd) < size):
            raise EndOfFile(len(bd))
        return struct.unpack(fmt, bd)

###############################################################################
# read_syscalls_table -- read syscalls table
###############################################################################

def read_syscalls_table(path_to_syscalls_table_dat):

    fmt = 'I4sP32sIIIiI6s6s'
    size_fmt = struct.calcsize(fmt)
    sizei = struct.calcsize('i')
    sc_table = []

    fh = open_file(path_to_syscalls_table_dat, 'rb')

    size_check, = read_data(fh, sizei, 'i')
    if (size_check != size_fmt):
        print("Error: wrong format of syscalls table file:", path_to_syscalls_table_dat, file=stderr)
        print("       format size : ", size_fmt, file=stderr)
        print("       data size   : ", size_check, file=stderr)
        raise

    while True:
        try:
            syscall = read_data(fh, size_fmt, fmt)
        except EndOfFile as err:
            if (err.val > 0):
                print("Input file is truncated:", path_to_syscalls_table_dat, file=stderr)
            break
        except:
            print("Unexpected error:", exc_info()[0], file=stderr)
            raise
        else:
            sc_table.append(syscall)

    fh.close()
    return sc_table

###############################################################################
# read_log_entry - read next log entry
###############################################################################

def read_log_entry(fh, sized):

    bdata = fh.read(sized)
    if (len(bdata) < sized):
        raise EndOfFile(len(bdata))
    return bdata

###############################################################################
# get_n_strs -- get number of string arguments
###############################################################################

def get_n_strs(mask):

    nstrargs = 0
    for n in range(0, 6):
        if (mask & Arg_str_mask[n] == Arg_str_mask[n]):
            nstrargs += 1
    return nstrargs

###############################################################################
# is_string -- checks if the argument is a string
###############################################################################

def is_string(n, mask):

    global Arg_str_mask

    if (mask & Arg_str_mask[n] == Arg_str_mask[n]):
        return 1
    else:
        return 0

###############################################################################
# print_string -- print string argument
###############################################################################

def print_string(n_str, str_fini, nstrargs, bdata, packet):

    BUF_SIZE_2 = int(BUF_SIZE / 2)
    BUF_SIZE_3 = int(BUF_SIZE / 3)

    STR_MAX_1  = BUF_SIZE - 2
    STR_MAX_2  = BUF_SIZE_2 - 2
    STR_MAX_3  = BUF_SIZE_3 - 2

    str_will_be_continued = (packet >> 7) & 0x1 # bit 7 (string will be continued)

    n_str += 1

    if (packet):
        max_len = STR_MAX_1
        string = bdata
    elif (nstrargs == 1):
        max_len = STR_MAX_1
        string = bdata
    elif (nstrargs == 2):
        max_len = STR_MAX_2
        if (n_str == 1):
            string = bdata[0:BUF_SIZE_2]
        elif (n_str == 2):
            string = bdata[BUF_SIZE_2: 2 * BUF_SIZE_2]
        else:
            raise
    elif (nstrargs == 3):
        max_len = STR_MAX_3
        if (n_str == 1):
            string = bdata[0:BUF_SIZE_3]
        elif (n_str == 2):
            string = bdata[BUF_SIZE_3: 2 * BUF_SIZE_3]
        elif (n_str == 3):
            string = bdata[2 * BUF_SIZE_3: 3 * BUF_SIZE_3]
        else:
            raise
    else:
        print("\n\nERROR: unsupported number of string arguments:", nstrargs)
        raise

    string = str(string.decode(errors="ignore"))
    string = string.split('\0')[0]

    length = len(string)
    # check if string is truncated
    if (length == (max_len + 1)):
        if (str_will_be_continued == 0):
            # print warning that string is truncated
            print("[WARNING: string truncated]", end='')
        str_fini = 0
    else:
        str_fini = 1

    print(string, end='')

    return (n_str , str_fini)

###############################################################################
# print_arg -- print syscall's arguments
###############################################################################

def print_arg(n, args, mask, n_str, str_fini, nstrargs, bdata, packet):

    if (is_string(n, mask) == 1):
        n_str, str_fini = print_string(n_str, str_fini, nstrargs, bdata, packet)
    else:
        print("{0:016X}".format(args[n]), end='')

    return (n_str , str_fini)

###############################################################################
# process_log_kprobe_entry - process kprobe entry log
###############################################################################

def process_log_kprobe_entry(i, etype, bdata, sized, sc_table):

    res_str = "---------------- ----------------"
    global Time_start
    global Str_fini
    global N_str

    fmt_entry = 'qQQq'
    size_fmt_entry = struct.calcsize(fmt_entry)
    data1 = bdata[0 : size_fmt_entry]
    bdata = bdata[size_fmt_entry:]

    packet, pid, time, sc_id = struct.unpack(fmt_entry, data1)
    if (sc_id >= 0 and sc_id < len(sc_table)):
        num, num_str, pname, name, length, args_qty, masks, at, nstr, pos, padding = sc_table[sc_id]
        name = str(name.decode(errors="ignore"))

    if (Time_start == 0):
        Time_start = time

    arg_begin = 0
    arg_end = 7
    arg_is_cont = 0

    if (packet):
        arg_begin   =  packet & 0x7	      # bits 0-2
        arg_end     = (packet >> 3) & 0x7 # bits 3-5
        arg_is_cont = (packet >> 6) & 0x1 # bit 6 (is a continuation)

    # is it a continuation of a string ?
    if (arg_begin == arg_end):
        assert(arg_is_cont == 1)
        if (Str_fini == 1):
            return
        fmt_args = 'qqqqqq'
        size_fmt_args = struct.calcsize(fmt_args)
        if (len(bdata) <= size_fmt_args):
            return
        aux_str = bdata[size_fmt_args:]

        string = str(aux_str.decode(errors="ignore"))
        string = string.split('\0')[0]

        max_len = BUF_SIZE - 2
        length = len(string)

        print(string, end='')
        if (length < max_len):
            Str_fini = 1
        return

    if (arg_begin == 0):
        dtime = time - Time_start
        print("{0:016X} {1:016X} {2:s} {3:s}".format(dtime, pid, res_str, name[4:length]), end='')

    # is it a continuation of last argument (full name mode)?
    if (arg_is_cont):
        # it is a continuation of last argument
        if (Str_fini):
            # printing string was already finished, so skip it
            arg_begin += 1
            arg_is_cont = 0
            Str_fini = 0
    else:
        # arg_begin argument was printed in the previous packet
        arg_begin += 1

    # should we print EOL ?
    if (arg_end == 7):
        print_eol = 1
        # and set the true value of the last argument
        arg_end = args_qty
    else:
        print_eol = 0

    fmt_args = 'QQQQQQ'
    size_fmt_args = struct.calcsize(fmt_args)
    data2 = bdata[0 : size_fmt_args]
    bdata = bdata[size_fmt_args:]

    if (len(data2) < size_fmt_args):
        print()
        return
    args = struct.unpack(fmt_args, data2)
    nstrargs = get_n_strs(masks)

    for n in range((arg_begin - 1), arg_end):
        if ((n > arg_begin - 1) or (arg_is_cont == 0) or Str_fini):
            print(" ", end='')
        N_str, Str_fini = print_arg(n, args, masks, N_str, Str_fini, nstrargs, bdata, packet)

    # should we print EOL ?
    if (print_eol):
        N_str = 0 # reset counter of string arguments
        Str_fini = 1
        print()


###############################################################################
# process_log_exit - process kprobe exit or raw tracepoint sys_exit log
###############################################################################

def process_log_exit(i, etype, bdata, sized, sc_table):

    global Time_start

    fmt_exit = 'QQQq'
    size_fmt_exit = struct.calcsize(fmt_exit)
    bdata = bdata[0 : size_fmt_exit]

    pid, time, id, retval = struct.unpack(fmt_exit, bdata)

    if (id >= 0 and id < len(sc_table)):
        num, num_str, pname, name, length, qty, masks, at, nstr, pos, padding = sc_table[id]
        name = str(name.decode(errors="ignore"))
        name = name.split('\0')[0]

    if (Time_start > 0):
        dtime = time - Time_start
    else:
        Time_start = time
        dtime = 0;

    # split return value into result and errno
    if (retval >= 0):
        res = retval
        err = 0
    else:
        res = 0xFFFFFFFFFFFFFFFF
        err = -retval

    if (id >= 0 and id < len(sc_table)):
        print("{0:016X} {1:016X} {2:016X} {3:016X} {4:s}".format(dtime, pid, err, res, name[4:length]))
    else:
        print("{0:016X} {1:016X} {2:016X} {3:016X} sys_exit {4:016X}".format(dtime, pid, err, res, id))

###############################################################################
# process_log_entry - process next log entry
###############################################################################

def process_log_entry(i, etype, bdata, sized, sc_table):

    if (etype == 0):
        # kprobe entry handler
        process_log_kprobe_entry(i, etype, bdata, sized, sc_table)

    elif ((etype == 1) or (etype == 3)):
        # kprobe exit handler or raw tracepoint sys_exit
        process_log_exit(i, etype, bdata, sized, sc_table)

    else:
        print("Error: unknown even type", file=stderr)
        raise NotImplementedError

    return

###############################################################################
# convert_bin2txt - convert binary log to text
###############################################################################

def convert_bin2txt(path_to_trace_log, sc_table):

    global BUF_SIZE

    sizei = struct.calcsize('i')
    sizeQ = struct.calcsize('Q')

    fh = open_file(path_to_trace_log, 'rb')

# read and init global BUF_SIZE
    BUF_SIZE, = read_data(fh, sizei, 'i')

# read header = command line
    data_size, = read_data(fh, sizei, 'i')
    argc, = read_data(fh, sizei, 'i')
    data_size -= sizei
    bdata = fh.read(data_size)
    argv = str(bdata.decode(errors="ignore"))
    argv = argv.replace('\0', ' ')
    print("Command line:", argv)

# read data
    i = 1
    while True:
        try:
            # read size of data
            sized, = read_data(fh, sizei, 'i')

            # read type of log entry
            etype, = read_data(fh, sizeQ, 'Q')
            sized -= sizeQ

            # read and process rest of data
            bentry = read_log_entry(fh, sized)
            process_log_entry(i, etype, bentry, sized, sc_table)
            i += 1

        except EndOfFile as err:
            if (err.val > 0):
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
    parser.add_argument("-b", "--binlog",   required=True, help="input file - tracing log in binary format")
    parser.add_argument("-t", "--txtlog",   required=False, help="output file - tracing log in text format")
    args = parser.parse_args()

    sc_table = read_syscalls_table(args.table)

    convert_bin2txt(args.binlog, sc_table)

if __name__ == "__main__":
        main()
