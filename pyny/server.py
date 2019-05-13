'''Server.
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
# $Id: nodelist.py 3 2006-03-06 01:03:41Z fuktommy $
#

from threading import Thread
from socketserver import ThreadingTCPServer, StreamRequestHandler

from . import config

__all__ = ['start']
__version__ = '$Revision: 3 $'

_server = None


class NyServer(ThreadingTCPServer, Thread):

    def __init__(self, port):
        Thread.__init__(self)
        address = ('', port)
        ThreadingTCPServer.__init__(self, address, NyRequestHandler)

    def run(self):
        self.serve_forever()

    def busy(self):
        '''I am busy.

        Requests are ommited.
        '''
        return False


# End of NyServer


class NyRequestHandler(StreamRequestHandler):

    def handle(self):
        '''Server main loop.
        '''
        self.close_connection = True
        self.handle_one_request()
        while not self.close_connection:
            self.handle_one_request()

    def handle_one_request(self):
        '''Now it is ECHO server.
        '''
        if _server.busy():
            return
        while True:
            buf = self.rfile.readline()
            if not buf:
                break
            self.wfile.write(buf)


# End of NyRequestHandler


def start():
    global _server
    _server = NyServer(config.port)
    _server.start()
    return _server


def _test():
    #import doctest, nodelist
    #return doctest.testmod(nodelist)
    start()


if __name__ == '__main__':
    _test()
