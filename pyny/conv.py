'''Conversion Utilities.
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
# $Id: conv.py 15 2006-12-10 06:23:36Z fuktommy $
#

from .nyexcept import *

__version__ = '$Revision: 15 $'
__all__ = [
    'hexstr',
    'binary',
    'get_cstring',
    'int_to_packet',
    'packet_to_int',
    'packet_to_address',
    'address_to_packet',
]


def hexstr(binarydata):
    '''Make hex string from binary data.

    0x0a11 -> '0a11'

    Sample:
    >>> hexstr('Aa')
    '4161'
    '''
    return ''.join(['%02x' % ord(c) for c in binarydata])


def binary(hexstring):
    '''Make binary data from hex string.

    '0a11' -> 0x0a11

    Sample:
    >>> binary('4161')
    'Aa'
    '''
    buf = []
    for i in range(0, len(hexstring), 2):
        buf.append(chr(int(hexstring[i:i + 2], 16)))
    return ''.join(buf)


def get_cstring(s):
    '''Parse string and get C string.

    C string ends with 0x00.
    '''
    length = s.find(chr(0))
    if length >= 0:
        return s[:length]
    else:
        return s


def int_to_packet(n):
    '''Make int packet form.

    Winny packet is little endian.

    Sample:
    >>> from pyny.conv import hexstr
    >>> hexstr(int_to_packet(123456789))
    '15cd5b07'
    '''
    array = [''] * 4
    array[3] = chr((n & 0xff000000) >> 24)
    array[2] = chr((n & 0x00ff0000) >> 16)
    array[1] = chr((n & 0x0000ff00) >> 8)
    array[0] = chr((n & 0x000000ff))
    return ''.join(array)


def packet_to_int(data):
    '''Make packet int.

    Winny packet is little endian.

    Sample:
    >>> packet_to_int('\\x15\\xCD\\x5B\\x07')
    123456789
    '''
    n = 0
    for i in range(len(data) - 1, -1, -1):
        n = n*256 + ord(data[i])
    return n


def packet_to_address(data):
    '''Convert 4 bite binary to IP address.

    Sample:
    >>> packet_to_address('\\xC0\\xA8\\x01\\x0A')
    '192.168.1.10'
    '''
    address = []
    for i in range(4):
        address.append(str(ord(data[i])))
    return '.'.join(address)


def address_to_packet(address):
    '''Convert IP address to 4 bite binary.

    Sample:
    >>> from pyny.conv import hexstr
    >>> hexstr(address_to_packet('192.168.1.10'))
    'c0a8010a'
    '''
    bin = []
    octet = address.split('.')
    if len(octet) != 4:
        raise CommandError('NyCommand: Bad address format')
    for i in octet:
        i = int(i)
        if i > 0xFF:
            raise CommandError('NyCommand: Bad address format')
        bin.append(chr(i))
    return ''.join(bin)


def _test():
    import doctest
    from pyny import conv
    return doctest.testmod(conv)


if __name__ == '__main__':
    _test()
