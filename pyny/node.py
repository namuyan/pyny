'''Winny Node.
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
# $Id: node.py 15 2006-12-10 06:23:36Z fuktommy $
#

from . import rc4
from . import config
from . import nyconnection
from .nyexcept import *
from .conv import hexstr, binary

__all__ = ['Node']
__version__ = '$Revision: 15 $'

level = {'Hi': 16, 'Middle': 4, 'Low': 1}


class Node:
    '''Winny Node.

    Variables:
    - isknown
    - priority          (0<=priority<=0xFF)
    - correlation       (it is not priority, 0<=correction<=0xFF)
    - major             Application name
    - minor             Version
    - addr              IPv4 address
    - port              Port number
    - reported_address  IPv4 address node reporting
    - clustering        Clustering keywords (len(clustering)<=3)
    - nodetype          Raw, NAT, DDNS, or Port0
    - speed
    - sortkey
    '''

    def __init__(self):
        self.isknown = False
        self.priority = 128
        self.addr = '0.0.0.0'
        self.port = 0

    def __str__(self):
        return '%s:%d' % (self.addr, self.port)

    def update_sortkey(self):
        self.sortkey = ((self.priority & 0xFF) << 24) | \
                       ((self.correlation & 0xff) << 16) | \
                       (self.speed & 0xffff)
        self.isknown = True

    def __cmp__(self, y):
        return y.sortkey - self.sortkey

    def setvalue(self,
                 correction=-1,
                 priority=-1,
                 speed=-1,
                 address='',
                 port=0,
                 header=None,
                 nodetype='',
                 nodeinfo=None):
        if correction > 0xFF:
            self.correction = 0xFF
        elif correction >= 0:
            self.correction = correction
        if priority > 0xFF:
            self.priority = 0xFF
        elif priority >= 0:
            self.priority = priority
        if speed >= 0:
            self.speed = speed
        self.update_sortkey()

        if header:
            self.major = header.major
            self.miner = header.minor
        if nodeinfo:
            self.clustering = nodeinfo.clustering
            self.correlation = 0  # XXX
            # XXX
            # It may not work when DDNS.
            self.addr = nodeinfo.addr
            self.port = nodeinfo.port
            self.reported_address = nodeinfo.addr

        # XXX
        # It may not work when DDNS.
        if nodetype and (nodetype == 'Port0'):
            self.type = 'Port0'
        elif nodeinfo and (self.addr == self.reported_address):
            self.type = 'Raw'
        else:
            self.type = 'NAT'

    def can_upstream(self, speed):
        '''Check this node can be upstream node.

        Argument speed is self-node's.
        The constant 4.3 may not work.
        '''
        return (speed * 0.8 <= self.speed) and (self.speed <= speed * 4.3)

    def can_downstream(self, speed):
        '''Check this node can be upstream node.

        Argument speed is self-node's.
        The constant 4.3 may not work.
        '''
        return not self.can_upstream(speed)

    def isself(self):
        selfnode = '%s:%d' % (config.addr, config.port)
        if (str(self) == selfnode):
            return True
        elif hasattr(self, 'reported_address') and \
             self.reported_address == config.addr:
            return True
        else:
            return False

    def connect(self):
        return nyconnection.Connection(self)


# End of Node


def strnode(s):
    '''Make node from string.

    Sample:
    >>> node = strnode('123.1.2.3:1234')
    >>> str(node)
    '123.1.2.3:1234'
    >>> node = strnode('@ba9582a383c7d6e79cd5d8c71f7347')
    >>> str(node)
    '123.1.2.3:1234'
    '''
    if s.startswith('@'):
        s = unpack_hash(s)
    addr, port = s.split(':')
    node = Node()
    node.addr, node.port = addr, int(port)
    return node


def RC4Key(checksum):
    '''RC4 key virtual class.
    '''
    magic = '\x6f\x70\x69\x65\x77\x66\x36\x61\x73\x63\x78\x6c\x76'
    return chr(checksum) + magic[1:]


def pack_hash(inetaddrss):
    '''Pack internet address.

    n.n.n.n:s -> @xxxx....

    sample:
    >>> pack_hash('123.1.2.3:1234')
    '@ba9582a383c7d6e79cd5d8c71f7347'
    '''
    checksum = 0
    for i in inetaddrss:
        checksum = (checksum + ord(i)) & 0xFF
    rc4key = RC4Key(checksum)
    hash = '@' + hexstr(chr(checksum) + rc4.crypt(rc4key, inetaddrss))
    return hash


def unpack_hash(hash):
    '''Unpack winny node format.

    @xxxx.... -> n.n.n.n:s

    sample:
    >>> unpack_hash('@ba9582a383c7d6e79cd5d8c71f7347')
    '123.1.2.3:1234'
    '''
    if len(hash) < 20:  # len('@^') + len('0.0.0.0:0') * 2 = 20
        raise NodeFormatError('Specified hash-string is too small')
    elif not hash.startswith('@'):
        raise NodeFormatError('Specified hash-string is not hash-string of NodeAddress')

    sum = binary(hash[1:3])
    encoded = binary(hash[3:])
    rc4key = RC4Key(ord(sum))
    unpackedstr = rc4.crypt(rc4key, encoded)

    checksum = 0
    for i in unpackedstr:
        checksum += ord(i)
    if (checksum & 0xFF) != ord(sum):
        raise NodeFormatError('sum check error')
    return unpackedstr


def _test():
    import doctest
    from pyny import node
    return doctest.testmod(node)


if __name__ == '__main__':
    _test()
