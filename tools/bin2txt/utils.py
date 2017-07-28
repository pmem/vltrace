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

import struct
import inspect

from sys import stderr
from exceptions import *


########################################################################################################################
# assert_msg -- custom assert function
########################################################################################################################
def assert_msg(cond, message):
    if cond:
        return

    frame_record = inspect.stack()[1]
    frame = frame_record[0]
    info = inspect.getframeinfo(frame)
    print("CRITICAL:{0:s}:{1:d}:{2:s}(): {3:s}".format(info.filename, info.lineno, info.function, message), file=stderr)

    raise CriticalError(message)


####################################################################################################################
# open_file -- open file with error handling
####################################################################################################################
def open_file(path, flags):
    try:
        fh = open(path, flags)
    except FileNotFoundError:
        print("ERROR: file not found: {0:s}".format(path), file=stderr)
        exit(-1)
    except:
        print("ERROR: unexpected error", file=stderr)
        raise
    # noinspection PyUnboundLocalVariable
    return fh


####################################################################################################################
# read_bdata - read binary data from file
####################################################################################################################
def read_bdata(fh, size):
    assert_msg(size >= 0, "attempt to read data of negative size, input file can be corrupted")
    bdata = fh.read(size)
    length = len(bdata)
    if length == 0:
        raise EndOfFile()
    assert_msg(length == size, "input file is truncated")
    return bdata


####################################################################################################################
# read_fmt_data -- read formatted data from file fh
####################################################################################################################
def read_fmt_data(fh, fmt):
    size = struct.calcsize(fmt)
    bdata = read_bdata(fh, size)
    return struct.unpack(fmt, bdata)
