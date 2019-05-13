'''Winny Connection.
'''
#
# Copyright (c) 2006 Pyny Project.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $Id: node.py 3 2006-03-06 01:03:41Z fuktommy $
#

import random
from time import time

from . import rc4
from . import nycommand

__all__ = ['Connection']
__version__ = '$Revision: 15 $'

buffer_size = 0x100000
block_max = 0x90000
speed_sec = 30
retry_max = 3


class Register:
    tail = 0
    command_offset = 0
    packlen = 0
    recvlen = 0
    phase = 0       # 0, 1, 2

    def save(self,
             tail = None,
             command_offset = None,
             packlen = None,
             recvlen = None,
             phase = None):
        if tail is not None:
            self.tail = tail
        if command_offset is not None:
            self.command_offset = command_offset
        if packlen is not None:
            self.packlen = packlen
        if recvlen is not None:
            self.recvlen = recvlen
        if phase is not None:
            self.phase = phase

    def load(self):
        return self.tail, self.connand_offset, \
               self.packlen, self.recvlen, self.phase

    def clear(self):
        self.tail = 0
        self.command_offset = 0
        self.packlen = 0
        self.recvlen = 0
        self.phase = 0

# End of Register


class Connection:
    '''Winny Connection.
    '''

    def __init__(self):
        self.register = Register()
        self.socket = None

        self.last_recv_time = 0
        self.last_send_time = 0
        self.recv_size_sec = 0
        self.send_size_sec = 0
        self.start_time = 0

    def clear(self):
        if self.socket:
            self.socket.close()

    def get_speed(self):
        '''Speed (bps).
        '''
        now = int(time())
        recv_diff = now - self.last_recv_time
        send_diff = now - self.last_send_time
        if recv_diff and send_diff:
            return self.send_size_sec / send_diff + \
                   self.recv_size_sec / recv_diff
        elif recv_diff:
            return self.recv_size_sec / recv_diff
        elif send_diff:
            return self.send_size_sec / send_diff
        else:
            return 0

    def ctl(self):
        '''Connection time length. (seconds).
        '''
        return int(time()) - self.start_time

    def authorize(self):
        self.init_block = random_data(6)
        self.rc4key = rc4.RC4(self.init_block[2:6])
        header = nycommand.NyProtocolHeader()
        header.major = nycommand.major_version
        header.minor = nycommand.minor_version

    def send(self, command):
        packet = command.pack()


# End of Connection


def random_data(size):
    '''Make random packet.
    '''
    buf = []
    for i in range(size):
        buf.append(chr(random.randint(0, 255)))
    return ''.join(buf)

def _test():
    import doctest
    from pyny import node
    return doctest.testmod(node)

if __name__ == '__main__':
    _test()
