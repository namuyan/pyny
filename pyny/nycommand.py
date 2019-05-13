'''Winny Commands.

See also Isamu Kaneko: The Technology of Winny.
http:/www.amazon.co.jp/exec/obidos/ASIN/4756145485

Command code table (copied from Poeny):
    PROTOCOL_HEADER                 =  0,
    SPEED                           =  1,
    CONNECTION_TYPE                 =  2,
    NODE_DETAILS                    =  3,
    ANOTHER_NODE                    =  4,
    BBS_PORT                        =  5,
    DIFFUSION_REQUEST               = 10,
    FILE_REQUEST                    = 11,
    CONDITIONAL_DIFFUSION_REQUEST   = 12,
    QUERY                           = 13,
    FILE_RESPONSE                   = 21,
    CLOSE                           = 31,
    CONNECTED_LIMITATION            = 32,
    WRONG_LISTENING_PORT            = 33,
    REJECT                          = 34,
    SLOW_RATE                       = 35,
    LIAR                            = 36,
    LOW_VERSION                     = 97,
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
# $Id: nycommand.py 15 2006-12-10 06:23:36Z fuktommy $
#

import re
import struct
from io import StringIO

from . import rc4
from .conv import *
from .nykey import NyKeyInformation
from .nyexcept import *

__version__ = '$Revision: 15 $'
__all__ = [
    'NyProtocolHeader',
    'NySpeed',
    'NyConnectionType',
    'NyNodeDetails',
    'NyAnotherNode',
    'NyBBSPort',
    'NyDiffusionRequest',
    'NyFileRequest',
    'NyConditionalDiffusionRequest',
    'ViaNode',
    'NyQuery',
    'NyFileResponse',
    'CloseConnection',
    'NyClose',
    'NyConnectedLimitation',
    'NyWrongListeningPort',
    'NyReject',
    'NySlow',
    'NyLiar',
    'NyLowVersion',
]

int_size = 4  # bytes
short_size = 2  # bytes
float_size = 4  # bytes
address_size = int_size
port_size = short_size
node_size = address_size + port_size
command_length_size = 4  # bytes
code_size = 1  # bytes
header_length = command_length_size + code_size
major_version = 'Winny Ver2.0b1 (poeny)'
minor_version = 12710
sign_length = 11


def make_step2key(step1key):
    '''What is this?
    '''
    step2key = []
    for c in step1key:
        step2key.append(chr(ord(c) ^ 0x39))
    return ''.join(step2key)


class NyCommand:
    '''Winny Command.
    '''
    length = 0
    code = -1
    data = None
    header_length = 0

    def __len__(self):
        return self.length

    def unpack(self, command_block, unpack_all=True):
        '''Unpack packet style command.

        Packet is string (byte array).
        If unpack_all is False, unpack header only.
        '''
        if len(command_block) < header_length:
            raise CommandError('NyCommand: command is too small')
        self.length = len(command_block)
        if self.length == 0:
            raise CommandError('NyCommand: command code is nothing')
        self.gotcode = command_block[command_length_size]
        if len(command_block) < header_length + self.length - 1:
            #raise CommandError('NyCommand: length is too small')
            #XXX
            pass
        if not unpack_all:
            self.data = None
            if self.length == 1:
                return None
            else:
                return command_block[header_length:]
        if self.length > header_size:
            self.data = command_block[header_length:]
        else:
            self.data = None
        return self.data

    def assign(self, command):
        self.length = command.length
        self.code = command.code
        self.data = command.data

    def pack(self):
        '''Make packet, byte stream.
        '''
        packet = []
        packet.extend(int_to_packet(code_size + len(self.data)))
        packet.append(chr(self.code))
        packet.extend(self.data)
        self.data = None
        return ''.join(packet)

    def next_index(self):
        '''Next command index of packet steram.
        '''
        return header_size + self.length - 1

    def __str__(self):
        return 'CommandCode(%d) Length(%d)' % (self.code, self.length)


# End of NyCommand


class NyRawCommand(NyCommand):

    def __init__(self, command_block):
        self.unpack(command_block)

    def unpack(self, command):
        if isinstance(command, NyRawCommand):
            self.assign(command)
        else:
            self.data = NyCommand.unpack(self, command)


# End of NyRawCommand


class UnpackMixIn:
    '''Unpack common method.
    '''

    def __init__(self, raw_command=None):
        if raw_command is not None:
            self.unpack(raw_command)

    def unpack(self, command):
        if isinstance(command, NyRawCommand):
            self.assign(command)
            self._unpack(command.data)
        else:
            data = NyCommand.unpack(self, command, False)
            self._unpack(data)


# End of UnpackMixIn


class NyProtocolHeader(UnpackMixIn, NyCommand):
    '''Command00 - Winny Protocol Header.

    Records: <00><version><password>.

    Sample:
    >>> h = NyProtocolHeader()
    >>> h.major, h.minor = 'Winny Ver2.0b1 (poeny)', 12710
    >>> str(h)
    'Winny Ver2.0b1 (poeny)(12710)'
    >>> data = h.pack()
    >>> hexstr(data)
    '1b000000005f9c51446217f43658711c5eb7332084e7bb9b559276f3d9c77f'
    >>> h = NyProtocolHeader(data)
    >>> str(h)
    'Winny Ver2.0b1 (poeny)(12710)'
    '''
    code = 0
    cert_key = '\x39\x38\x37\x38\x39\x61\x73\x6A'
    major = ''
    minor = 0

    def cert_crypt(self, data):
        return rc4.crypt(self.cert_key, data)

    def _unpack(self, data):
        if self.length < int_size:
            raise CommandError('Command is too small')
        cert = self.cert_crypt(data)
        # minor is 32bit little endian
        self.minor = packet_to_int(cert[:int_size])
        self.major = cert[int_size:]
        self.data = None

    def __str__(self):
        return '%s(%d)' % (self.major, self.minor)

    def pack(self):
        data = int_to_packet(self.minor) + self.major
        self.data = self.cert_crypt(data)
        return NyCommand.pack(self)


# End of NyProtocolHeader


class NySpeed(UnpackMixIn, NyCommand):
    '''Command01 - Report Line Speed.

    Records: <01><speed (KB/s)>.

    Sample:
    >>> com = NySpeed()
    >>> com.speed = 120
    >>> data = com.pack()
    >>> hexstr(data)
    '05000000010000f042'
    >>> com = NySpeed(data)
    >>> com.speed
    120.0
    '''
    code = 1
    speed = 0

    def _unpack(self, data):
        if len(data) < float_size:
            raise CommandError('Speed: length is too small')
        self.speed = struct.unpack('f', data)[0]
        self.data = None

    def pack(self):
        self.data = struct.pack('f', self.speed)
        return NyCommand.pack(self)


# End of NySpeed


class NyConnectionType(UnpackMixIn, NyCommand):
    '''Command02 - Connection Type.

    Recods: <02><port0 flag><badport0 flag><bbslink flag>.

    Sample:
    >>> com = NyConnectionType()
    >>> com.setvalues(linktypestr='Transfer')
    >>> com.isport0, com.isbadport0, com.isbbslink = True, False, True
    >>> data = com.pack()
    >>> hexstr(data)
    '050000000201010001'
    >>> com = NyConnectionType(data)
    >>> com.linktypestr, com.isport0, com.isbadport0, com.isbbslink
    ('Transfer', True, False, True)
    '''
    code = 2
    linktypes = {'Search': 0, 'Transfer': 1, 'BbsSearch': 2}
    linktype = -1
    linktypestr = ''
    isport0 = False
    isbadport0 = False
    isbbslink = False

    def _unpack(self, data):
        if len(data) < 4:  #XXX 4 flags
            raise CommandError('ConnectionType: length is too small')
        linktype = ord(data[0])
        for k in self.linktypes:
            if self.linktypes[k] == linktype:
                self.linktypestr = k
                break
        else:
            raise CommandError('ConnectionType: unknown LinkType "%d"' % linktype)
        self.isport0 = (data[1] != chr(0))
        self.isbadport0 = (data[2] != chr(0))
        self.isbbslink = (data[3] != chr(0))
        self.data = None

    def setvalues(self, linktypestr=''):
        if linktypestr:
            self.linktypestr = linktypestr
            self.linktype = self.linktypes[linktypestr]

    def pack(self):
        self.data = [chr(self.linktype), chr(self.isport0), chr(self.isbadport0), chr(self.isbbslink)]
        return NyCommand.pack(self)


# End of NyConnectionType


class NyNodeDetails(UnpackMixIn, NyCommand):
    '''Command 03 - Report Node Information.

    Records: <03><IPaddress><Port><DDNS name length>
            <Clustering words length><FQDN Host Name>
            <Clustering word1><Clustering word2><Clustering word3>
    Sample:
    >>> com = NyNodeDetails()
    >>> com.address = '192.168.1.10'
    >>> com.port = 8000
    >>> com.host = 'pyny.sf.net'
    >>> com.words = ['a', 'bb', 'ccc']
    >>> data = com.pack()
    >>> hexstr(data)
    '1e00000003c0a8010a401f00000b01020370796e792e73662e6e6574616262636363'
    >>> com = NyNodeDetails(data)
    >>> com.address, com.port, com.host, com.words
    ('192.168.1.10', 8000, 'pyny.sf.net', ['a', 'bb', 'ccc'])
    '''
    code = 3
    wordsize = 3
    address = ''
    port = ''
    host = ''
    words = [''] * wordsize

    def _unpack(self, data):
        headsize = 2*int_size + 1 + self.wordsize * 1
        if len(data) < headsize:
            raise CommandError('NodeDetails: length is too small')
        self.address = packet_to_address(data[0:4])
        self.port = packet_to_int(data[4:8])
        hostlen = ord(data[8])
        wordslen = []
        for i in range(self.wordsize):
            wordslen.append(ord(data[9 + i]))

        if len(data) != headsize + hostlen + \
                        wordslen[0] + wordslen[1] + wordslen[2]:
            raise CommandError('NodeDetails: illegal length')
        self.host = data[headsize:headsize + hostlen]
        offset = headsize + hostlen
        for i in range(self.wordsize):
            self.words[i] = data[offset:offset + wordslen[i]]
            offset += wordslen[i]
        self.data = None

    def pack(self):
        self.data = ''
        for c in self.address.split('.'):
            self.data += chr(int(c))
        self.data += int_to_packet(self.port)
        self.data += chr(len(self.host))
        for i in range(len(self.words)):
            self.data += chr(len(self.words[i]))
        self.data += self.host
        for i in range(len(self.words)):
            self.data += self.words[i]
        return NyCommand.pack(self)


# End of NyNodeDetails


class NyAnotherNode(UnpackMixIn, NyCommand):
    '''Command 04 - Report Anoter Node Information.

    Records: <04><IP Address><Port for File Sharing><Port for BBS>
             <BBS Node Flag><Speed><Clustering words length>
             <Clustering word1><Clustering word2><Clustering word3>
    Sample:
    >>> com = NyAnotherNode()
    >>> com.address = '192.168.1.10'
    >>> com.sharing_port = 8000
    >>> com.bbs_port = 8001
    >>> com.is_bbs_node = True
    >>> com.speed = 120
    >>> com.words = ['a', 'bb', 'ccc']
    >>> data = com.pack()
    >>> hexstr(data)
    '1b00000004c0a8010a401f0000411f00000178000000010203616262636363'
    >>> com = NyAnotherNode(data)
    >>> com.address, com.sharing_port, com.bbs_port, com.is_bbs_node
    ('192.168.1.10', 8000, 8001, True)
    >>> com.speed, com.words
    (120, ['a', 'bb', 'ccc'])
    '''
    code = 4
    wordsize = 3
    address = ''
    sharing_port = 0
    bbs_port = 0
    is_bbs_node = False
    speed = 0
    words = [''] * wordsize

    def _unpack(self, data):
        headsize = 3*int_size + 1 + int_size + self.wordsize * 1
        if len(data) < headsize:
            raise CommandError('NyAnotherNode: command is too small')
        self.address = packet_to_address(data[0:4])
        self.sharing_port = packet_to_int(data[4:8])
        self.bbs_port = packet_to_int(data[8:12])
        self.is_bbs_node = (data[12] == chr(1))
        self.speed = packet_to_int(data[13:17])
        wordslen = []
        for i in range(self.wordsize):
            wordslen.append(ord(data[17 + i]))
        offset = headsize
        for i in range(self.wordsize):
            self.words[i] = data[offset:offset + wordslen[i]]
            offset += wordslen[i]
        self.data = None

    def pack(self):
        self.data = ''
        for c in self.address.split('.'):
            self.data += chr(int(c))
        self.data += int_to_packet(self.sharing_port)
        self.data += int_to_packet(self.bbs_port)
        self.data += chr(self.is_bbs_node)
        self.data += int_to_packet(self.speed)
        for i in range(len(self.words)):
            self.data += chr(len(self.words[i]))
        for i in range(len(self.words)):
            self.data += self.words[i]
        return NyCommand.pack(self)


# End of NyAnotherNode


class NyBBSPort(UnpackMixIn, NyCommand):
    '''Command 05 - Report BBS Port Number.

    Records: <04><Port for BBS>
    Sample:
    >>> com = NyBBSPort()
    >>> com.bbs_port = 8000
    >>> data = com.pack()
    >>> hexstr(data)
    '0500000005401f0000'
    >>> com = NyBBSPort(data)
    >>> com.bbs_port
    8000
    '''
    code = 5
    bbs_port = 0

    def _unpack(self, data):
        if len(data) < int_size:
            raise CommandError('NyBBSPort: command is too small')
        self.bbs_port = packet_to_int(data)
        self.data = None

    def pack(self):
        self.data = int_to_packet(self.bbs_port)
        return NyCommand.pack(self)


# End of NyBBSPort


class NyDiffusionRequest(UnpackMixIn, NyCommand):
    '''Command 10 - Request for Diffusion Query.

    Records: <10>
    Sample:
    >>> com = NyDiffusionRequest()
    >>> data = com.pack()
    >>> hexstr(data)
    '010000000a'
    >>> com = NyDiffusionRequest(data)
    '''
    code = 10
    data = ''

    def _unpack(self, data):
        self.data = None


# End of NyDiffusionRequest


class NyFileRequest(UnpackMixIn, NyCommand):
    '''Command 11 - Request File.

    Records: <11><Task ID><Block No.><Block Size><Hash><File Size>
    Sample:
    >>> com = NyFileRequest()
    >>> com.task_id = 300
    >>> com.block_begin = 1000
    >>> com.block_size = 500
    >>> com.setvalues(hash='fcc3b22beb4c242c')
    >>> com.file_size = 2000
    >>> data = com.pack()
    >>> hexstr(data)
    '210000000b2c010000e8030000f401000066636333623232626562346332343263d0070000'
    >>> com = NyFileRequest(data)
    >>> (com.task_id, com.block_begin, com.block_size, com.hash, com.file_size)
    (300, 1000, 500, 'fcc3b22beb4c242c', 2000)
    '''
    code = 11
    task_id = 0
    block_begin = 0
    block_size = 0
    hash = chr(0) * 16
    file_size = 0
    packetsize = 3*int_size + 16 + int_size

    def _unpack(self, data):
        if len(data) < self.packetsize:
            raise CommandError('NyFileRequest: command is too small')
        self.task_id = packet_to_int(data[0:4])
        self.block_begin = packet_to_int(data[4:8])
        self.block_size = packet_to_int(data[8:12])
        self.hash = data[12:28]
        self.file_size = packet_to_int(data[28:32])
        self.data = None

    def pack(self):
        self.data = int_to_packet(self.task_id) + \
                    int_to_packet(self.block_begin) + \
                    int_to_packet(self.block_size) + \
                    self.hash + \
                    int_to_packet(self.file_size)
        return NyCommand.pack(self)

    def setvalues(self, hash=None):
        if hash is not None:
            self.hash = hash[:16]
            if len(self.hash) < 16:
                self.hash += chr(0) * (16 - len(self.hash))


# End of NyFileRequest


class NyConditionalDiffusionRequest(UnpackMixIn, NyCommand):
    '''Command 12 - Request for Conditional Diffusion Query.

    Records: <12><Task ID><Block No.><Block Length><Hash><File Size>
    Sample:
    >>> com = NyConditionalDiffusionRequest()
    >>> com.keyword = 'Abc'
    >>> com.sign = 'Xyz'
    >>> com.query_id = 20
    >>> data = com.pack()
    >>> hexstr(data)
    '150100000c41626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000058797a000000000000000000000000000014000000'
    >>> com = NyConditionalDiffusionRequest(data)
    >>> com.keyword, com.sign, com.query_id
    ('Abc', 'Xyz', 20)
    '''
    code = 12
    keyword = ''
    sign = ''
    query_id = 0
    keywordsize = 255
    signsize = 17
    packetsize = keywordsize + signsize + int_size

    def _unpack(self, data):
        if len(data) != self.packetsize:
            raise CommandError('NyConditionalDiffusionRequest: ' + 'command is too small or too long')
        self.keyword = data[0:self.keywordsize]
        self.keyword = self.keyword.replace(chr(0), '')
        self.sign = data[self.keywordsize:self.keywordsize + self.signsize]
        self.sign = self.sign.replace(chr(0), '')
        self.query_id = packet_to_int(data[self.keywordsize + self.signsize:])
        self.data = None

    def pack(self):
        self.keyword = self.keyword[:self.keywordsize - 1]
        self.sign = self.sign[:self.signsize - 1]
        self.data = self.keyword + chr(0) * (self.keywordsize - len(self.keyword))
        self.data += self.sign + chr(0) * (self.signsize - len(self.sign))
        self.data += int_to_packet(self.query_id)
        return NyCommand.pack(self)


# End of NyConditionalDiffusionRequest


class ViaNode:
    '''Part of Command 13 - Node on query path.

    Records: <IP Address><Port>

    Sample:
    >>> vianode = ViaNode('192.168.1.1', 4000)
    >>> data = vianode.pack()
    >>> hexstr(data)
    'c0a80101a00f'
    >>> vianode.unpack(data)
    >>> str(vianode)
    '192.168.1.1:4000'
    '''

    def __init__(self, address='', port=0):
        self.address = address
        self.port = port

    def __str__(self):
        return '%s:%d' % (self.address, self.port)

    def pack(self):
        return address_to_packet(self.address) + \
               int_to_packet(self.port)[:2]

    def unpack(self, data):
        self.address = packet_to_address(data[:address_size])
        self.port = packet_to_int(data[address_size:])


# End of ViaNode


class NyQuery(UnpackMixIn, NyCommand):
    '''Command 13 - Query.

    Records: <13><Response Flag><Diffusion Flag><Direction Flag><BBS Flag>
             <Query ID><Keyword Length><Keyword><Signature>
             <ViaNode Size><ViaNode>...
             <Key Size><NyKeyInformation>...
    Sample:
    >>> keyinfo = NyKeyInformation()
    >>> keyinfo.sharing_address = '192.168.1.1'
    >>> keyinfo.sharing_port = 4000
    >>> keyinfo.bbs_address = '192.168.1.2'
    >>> keyinfo.bbs_port = 4001
    >>> keyinfo.file_name = 'abc'
    >>> keyinfo.file_size = 1000
    >>> keyinfo.hash = 'fcc3b22beb4c242c'
    >>> keyinfo.sharing_sign = 'xyz'
    >>> keyinfo.bbs_sign = 'XYZ'
    >>> keyinfo.timer = 100
    >>> keyinfo.block_size = 120
    >>> keyinfo.modified_time = 1146886153
    >>> keyinfo.ignore = False
    >>> keyinfo.version = 6
    >>> com = NyQuery()
    >>> com.is_response = False
    >>> com.is_diffusion_query = True
    >>> com.is_downstream_query = False
    >>> com.is_bbs_query = False
    >>> com.query_id = 300
    >>> com.keyword = 'abc'
    >>> com.sign = 'xyz'
    >>> com.vianode = [ViaNode('192.168.1.1', 4000)]
    >>> com.keyinfo = [keyinfo]
    >>> data = com.pack()
    >>> hexstr(data)
    '620000000d000100002c0100000361626378797a000000000000000001c0a80101a00f0100c0a80101a00fc0a80102a10fe8030000666363336232326265623463323432630326018f7b1e78797a00000000000000000358595a64007800000009185c440006'
    >>> com = NyQuery(data)
    >>> com.is_response, com.is_diffusion_query, com.is_downstream_query
    (False, True, False)
    >>> com.is_bbs_query, com.keyword, com.sign, str(com.vianode[0])
    (False, 'abc', 'xyz', '192.168.1.1:4000')
    >>> keyinfo = com.keyinfo[0]
    >>> keyinfo.sharing_address, keyinfo.sharing_port
    ('192.168.1.1', 4000)
    >>> keyinfo.bbs_address, keyinfo.bbs_port
    ('192.168.1.2', 4001)
    >>> keyinfo.file_name, keyinfo.file_size, keyinfo.hash,
    ('abc', 1000, 'fcc3b22beb4c242c')
    >>> keyinfo.sharing_sign, keyinfo.bbs_sign
    ('xyz', 'XYZ')
    >>> keyinfo.timer, keyinfo.block_size, keyinfo.modified_time
    (100, 120, 1146886153)
    >>> keyinfo.ignore, keyinfo.version
    (False, 6)
    '''
    code = 13
    is_response = None
    is_diffusion_query = None
    is_downstream_query = None
    is_bbs_query = None
    query_id = 0
    keyword = ''
    sign = ''
    vianode = []
    keyinfo = []
    header_length = 4 + int_size + 1

    def _unpack(self, data):
        if len(data) < self.header_length:
            raise CommandError('NyQuery: command is too small')
        packet = StringIO(data)
        self.is_response = bool(ord(packet.read(1)))
        self.is_diffusion_query = bool(ord(packet.read(1)))
        self.is_downstream_query = bool(ord(packet.read(1)))
        self.is_bbs_query = bool(ord(packet.read(1)))
        self.query_id = packet_to_int(packet.read(int_size))
        keyword_length = ord(packet.read(1))
        if len(data) < self.header_length + \
                       keyword_length + sign_length + 1:
            raise CommandError('NyQuery: command is too small')
        self.keyword = packet.read(keyword_length)
        self.sign = re.sub('\0.*', '', packet.read(sign_length))
        vianode_size = ord(packet.read(1))
        for i in range(vianode_size):
            vianode = ViaNode()
            vianode.unpack(packet.read(node_size))
            self.vianode.append(vianode)
        keyinfo_size = packet_to_int(packet.read(short_size))
        pack = packet.read()
        for i in range(keyinfo_size):
            keyinfo = NyKeyInformation()
            pack = keyinfo.unpack(pack)
            self.keyinfo.append(keyinfo)
        self.data = None

    def pack(self):
        self.data = chr(self.is_response) + \
                    chr(self.is_diffusion_query) + \
                    chr(self.is_downstream_query) + \
                    chr(self.is_bbs_query) + \
                    int_to_packet(self.query_id) + \
                    int_to_packet(len(self.keyword))[:1] + \
                    self.keyword + \
                    self.sign + chr(0)*(sign_length-len(self.sign)) + \
                    int_to_packet(len(self.vianode))[:1]
        for i in self.vianode:
            self.data += i.pack()
        self.data += int_to_packet(len(self.keyinfo))[:2]
        for i in self.keyinfo:
            self.data += i.pack()
        return NyCommand.pack(self)


# End of NyQuery


class NyFileResponse(UnpackMixIn, NyCommand):
    '''Command 21 - Response for Request.

    Records: <21><Task ID><Block No.><Block Data>
    Sample:
    >>> com = NyFileResponse()
    >>> com.task_id = 300
    >>> com.block_begin = 1000
    >>> com.setvalues(hash='fcc3b22beb4c242c')
    >>> com.setvalues(file_data='0123456789abcdef')
    >>> data = com.pack()
    >>> hexstr(data)
    '29000000152c010000e80300006663633362323262656234633234326330313233343536373839616263646566'
    >>> com = NyFileResponse(data)
    >>> (com.task_id, com.block_begin, com.hash, com.file_data)
    (300, 1000, 'fcc3b22beb4c242c', '0123456789abcdef')
    '''
    code = 21
    task_id = 0
    block_begin = 0
    hash = chr(0) * 16
    file_data = ''
    data_limit = 0x10000
    header_size = 2*int_size + 16

    def _unpack(self, data):
        if len(data) < self.header_size:
            raise CommandError('NyFileResponse: command is too small')
        self.task_id = packet_to_int(data[0:4])
        self.block_begin = packet_to_int(data[4:8])
        self.hash = data[8:24]
        self.file_data = data[24:24 + self.data_limit]
        self.data = None

    def pack(self):
        self.data = int_to_packet(self.task_id) + \
                    int_to_packet(self.block_begin) + \
                    self.hash + self.file_data
        return NyCommand.pack(self)

    def setvalues(self, hash=None, file_data=None):
        if hash is not None:
            self.hash = hash[:16]
            if len(self.hash) < 16:
                self.hash += chr(0) * (16 - len(self.hash))
        if file_data is not None:
            self.file_data = file_data[:self.data_limit]

    def cache_block(self):
        return int_to_packet(self.task_id) + \
               int_to_packet(self.block_begin) + \
               self.hash + \
               self.file_data + chr(0)*(self.data_limit-len(self.file_data))


# End of NyFileResponse


class CloseConnection(UnpackMixIn, NyCommand):
    '''Command 3X - Close Connection.

    Records: <3X>
    '''
    code = 0
    data = ''

    def _unpack(self, data):
        self.data = None


# End of CloseConnection


class NyClose(CloseConnection):
    code = 31


class NyConnectedLimitation(CloseConnection):
    code = 32


class NyWrongListeningPort(CloseConnection):
    code = 33


class NyReject(CloseConnection):
    code = 34


class NySlow(CloseConnection):
    code = 35


class NyLiar(CloseConnection):
    code = 36


class NyLowVersion(CloseConnection):
    code = 97


def _test():
    import doctest
    from pyny import nycommand
    return doctest.testmod(nycommand)


if __name__ == '__main__':
    _test()
