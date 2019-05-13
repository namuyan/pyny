'''Winny Key.

See also Isamu Kaneko: The Technology of Winny.
http:/www.amazon.co.jp/exec/obidos/ASIN/4756145485

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
# $Id: $
#

import re
from StringIO import StringIO

import rc4
from conv import *
from checksum import sum16
from nyexcept import *

__version__ = '$Revision: $'
__all__ = ['NyKeyInformation']

address_size = 4
short_size = 2
int_size = 4

class NyKeyInformation:
    '''Query Kye Information.

    Records: <IP Address><Port><BBS Server's IP Address><BBS Server's Port>
             <File Size><File Hash>
             <File Name Length><Check Sum><File Name><Signature>
             <BBS Signature Size><BBS Signature>
             <Timer to Live><Refered Block Size><Modified Time>
             <Ignore Flag><Version>
    Version: 4, 5, or 6
    Sample:
    >>> com = NyKeyInformation()
    >>> com.sharing_address = '192.168.1.1'
    >>> com.sharing_port = 4000
    >>> com.bbs_address = '192.168.1.2'
    >>> com.bbs_port = 4001
    >>> com.file_name = 'abc'
    >>> com.file_size = 1000
    >>> com.hash = 'fcc3b22beb4c242c'
    >>> com.sharing_sign = 'xyz'
    >>> com.bbs_sign = 'XYZ'
    >>> com.timer = 100
    >>> com.block_size = 120
    >>> com.modified_time = 1146886153
    >>> com.ignore = False
    >>> com.version = 6
    >>> data = com.pack()
    >>> hexstr(data)
    'c0a80101a00fc0a80102a10fe8030000666363336232326265623463323432630326018f7b1e78797a00000000000000000358595a64007800000009185c440006'
    >>> com = NyKeyInformation(data)
    >>> com.sharing_address, com.sharing_port, com.bbs_address, com.bbs_port
    ('192.168.1.1', 4000, '192.168.1.2', 4001)
    >>> com.file_name, com.file_size, com.hash, com.sharing_sign, com.bbs_sign
    ('abc', 1000, 'fcc3b22beb4c242c', 'xyz', 'XYZ')
    >>> com.timer, com.block_size, com.modified_time, com.ignore, com.version
    (100, 120, 1146886153, False, 6)
    '''
    sharing_address = ''
    sharing_port = 0
    bbs_address = ''
    bbs_port = 0
    file_size = 0
    file_hash = ''
    file_name = ''
    checksum = ''
    sharing_sign = ''
    bbs_sign = ''
    timer = 0
    block_size = 0
    modified_time = 0
    ignore = False
    version = 6
    hash_length = 16
    checksum_length = 2
    sign_length = 11

    def __init__(self, data=''):
        if data:
            self.unpack(data)

    def pack(self):
        data = address_to_packet(self.sharing_address)
        data += int_to_packet(self.sharing_port)[:short_size]
        data += address_to_packet(self.bbs_address)
        data += int_to_packet(self.bbs_port)[:short_size]
        data += int_to_packet(self.file_size)
        data += self.hash[:self.hash_length] + \
                chr(0)*(self.hash_length-len(self.hash))
        data += int_to_packet(len(self.file_name))[:1]
        checksum = sum16(self.file_name)
        sum = chr(checksum & 0xFF) + chr((checksum & 0xFF00) >> 8)
        data += sum
        data += rc4.crypt(sum[0], self.file_name)
        data += self.sharing_sign + \
                chr(0)*(self.sign_length-len(self.sharing_sign))
        data += int_to_packet(len(self.bbs_sign))[:1]
        data += self.bbs_sign
        data += int_to_packet(self.timer)[:short_size]
        data += int_to_packet(self.block_size)
        data += int_to_packet(self.modified_time)
        data += chr(int(self.ignore))
        data += chr(self.version)
        return data

    def unpack(self, data):
        header_length = (address_size+short_size)*2 + \
                        int_size + self.hash_length + 1
        if len(data) < header_length:
            raise CommandError("Query: Key Header Size")
        packet = StringIO(data)
        self.sharing_address = packet_to_address(packet.read(address_size))
        self.sharing_port = packet_to_int(packet.read(short_size))
        self.bbs_address = packet_to_address(packet.read(address_size))
        self.bbs_port = packet_to_int(packet.read(short_size))
        self.file_size = packet_to_int(packet.read(int_size))
        self.hash = re.sub(r'\0.*', '', packet.read(self.hash_length))
        file_name_length = packet_to_int(packet.read(1))
        checksum = packet.read(self.checksum_length)
        file_name = packet.read(file_name_length)
        self.file_name = rc4.crypt(checksum[0], file_name)
        self.sharing_sign = re.sub(r'\0.*', '', packet.read(self.sign_length))
        bbs_sign_length = packet_to_int(packet.read(1))
        self.bbs_sign = packet.read(bbs_sign_length)
        self.timer = packet_to_int(packet.read(short_size))
        self.block_size = packet_to_int(packet.read(int_size))
        self.modified_time = packet_to_int(packet.read(int_size))
        self.ignore = bool(packet_to_int(packet.read(1)))
        self.version = packet_to_int(packet.read(1))
        return str(packet)

def _test():
    import doctest, nykey
    return doctest.testmod(nykey)

if __name__ == '__main__':
    _test()
