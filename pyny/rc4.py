'''RC4 Crypt for Obfuscation.
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
# $Id: rc4.py 15 2006-12-10 06:23:36Z fuktommy $
#

__version__ = '$Revision: 15 $'
__all__ = ['crypt']

class RC4:
    '''RC4 for Winny.
    '''

    def __init__(self, key=''):
        self.m_state = []
        self.m_x = 0
        self.m_y = 0
        if key:
            self.setkey(key)

    def setkey(self, key):
        '''Set key string.

        Key string ends with 0x00.
        '''
        length = key.find(chr(0))
        if length == 0:
            key = key[0]
        elif length > 0:
            key = key[:length]
        self.m_x = 0
        self.m_y = 0
        self.m_state = range(256)
        if len(key) == 0:
            return
        ki = 0
        si = 0
        for i in range(len(self.m_state)):
            si = (si + ord(key[ki]) + self.m_state[i]) & 0xFF;
            self.m_state[si], self.m_state[i] = \
                self.m_state[i], self.m_state[si]
            ki += 1
            if ki >= len(key):
                ki = 0

    def crypt(self, src):
        dest = []
        for c in src:
            x = (self.m_x + 1) & 0xFF
            sx = self.m_state[x]
            y = (sx + self.m_y) & 0xFF
            sy = self.m_state[y]
            self.m_x = x
            self.m_y = y
            self.m_state[y] = sx
            self.m_state[x] = sy
            dest.append(chr(ord(c) ^ self.m_state[(sx+sy)&0xFF]))
        return ''.join(dest)

def crypt(key, src):
    '''RC4 crypt for Winny.

    sample:
    >>> from conv import hexstr
    >>> key = '\\xD2\\x46\\xAD\\x10'
    >>> src = '\\xDC\\x9A\\x1E\\xF9\\x71\\xAE\\xC3\\x4C' + \\
    ...       '\\x8A\\xFD\\x8B\\xE9\\x88\\x7A\\x7B\\x21' + \\
    ...       '\\x23\\xBD\\xAA\\x76\\x9E\\x8A\\x63\\xDB\\x01\\x5D'
    >>> hexstr(crypt(key, src))
    '010000006115000000005f9c51446217f43658711c5eb7332084'

    >>> key = '\\x39\\x38\\x37\\x38\\x39\\x61\\x73\\x6a'
    >>> src = '\\x5F\\x9C\\x51\\x44\\x62\\x17\\xF4\\x36\\x58\\x71' + \\
    ...       '\\x1C\\x5E\\xB7\\x33\\x20\\x84'
    >>> hexstr(crypt(key, src))
    'a631000057696e6e7920566572322e30'
    '''
    return RC4(key).crypt(src)

def _test():
    import doctest, rc4
    return doctest.testmod(rc4)

if __name__ == '__main__':
    _test()
