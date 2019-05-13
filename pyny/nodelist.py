'''Node List and Manager.
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
# $Id: nodelist.py 15 2006-12-10 06:23:36Z fuktommy $
#

from threading import Thread

import config
from node import Node

__all__ = ['NodeManager']
__version__ = '$Revision: 15 $'


class NodeList(list):
    pass

# End of NodeList


class NodeManager(Thread):
    '''Node Manager.

    System has ONE instance of this class.

    NodeManager has 4 lists:
    - upstream: upstream find connection list.
    - downstream: downstream find connection list.
    - forward: data forwading connection list.
    - all: all nodes list.
    '''
    upstream = None
    downstream = None
    forward = None
    all = None

    def run(self):
        self.upstream = NodeList()
        self.downstream = NodeList()
        self.forward = NodeList()
        self.all = NodeList()

# End of NodeManager


def _test():
    import doctest, nodelist
    return doctest.testmod(nodelist)

if __name__ == '__main__':
    _test()
