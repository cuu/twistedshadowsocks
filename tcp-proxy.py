#!/usr/bin/env python
# coding: utf-8
# http://musta.sh/2012-03-04/twisted-tcp-proxy.html

import sys
import os

from twisted.internet import defer
from twisted.internet import protocol
from twisted.internet import reactor
from twisted.python import log

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
from shadowsocks import encrypt ,common
from shadowsocks.common import parse_header


STAGE_INIT = 0 
STAGE_ADDR = 1 
STAGE_UDP_ASSOC = 2 
STAGE_DNS = 3 
STAGE_CONNECTING = 4 
STAGE_STREAM = 5 
STAGE_DESTROYED = -1

STAGE_STR={0:"init",1:"addr",2:"udpassoc",3:"dns",4:"connecting",5:"stream",-1:"destroyed"}

# for each handler, we have 2 stream directions:
#    upstream:    from client to server direction
#                 read local and write to remote
#    downstream:  from server to client direction
#                 read remote and write to local

STREAM_UP = 0  ## client to server
STREAM_DOWN = 1   ## server to client

# for each stream, it's waiting for reading, or writing, or both
WAIT_STATUS_INIT = 0 
WAIT_STATUS_READING = 1 
WAIT_STATUS_WRITING = 2 
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING

BUF_SIZE = 32 * 1024

## Connector->Server->Client->Peer

class ProxyClientProtocol(protocol.Protocol):
    def connectionMade(self):
        log.msg("Client: connected to peer")
        self.cli_queue = self.factory.cli_queue ## cli_queue == client queue
        self.cli_queue.get().addCallback(self.serverDataReceived)

    def serverDataReceived(self, chunk):
        if chunk is False:
            self.cli_queue = None
            log.msg("Client: disconnecting from peer")
            self.factory.continueTrying = False
            self.transport.loseConnection()
        elif self.cli_queue:
            log.msg("Client: writing %d bytes to peer" % len(chunk))
            self.transport.write(chunk)
            self.cli_queue.get().addCallback(self.serverDataReceived)
        else:
            self.factory.cli_queue.put(chunk)

    def dataReceived(self, chunk):
        log.msg("Client: %d bytes received from peer" % len(chunk))
        self.factory.srv_queue.put(chunk)

    def connectionLost(self, why):
        if self.cli_queue:
            self.cli_queue = None
            log.msg("Client: peer disconnected unexpectedly")


class ProxyClientFactory(protocol.ReconnectingClientFactory):
    maxDelay = 10
    continueTrying = True
    protocol = ProxyClientProtocol

    def __init__(self, srv_queue, cli_queue):
        self.srv_queue = srv_queue
        self.cli_queue = cli_queue

class ProxyServer(protocol.Protocol): ##代理服务器
    def __init__(self):
        self.stage = STAGE_INIT
        self.client_address = None
        self.remote_address = None
        self.encryptor = encrypt.Encryptor("fuckyou","aes-256-cfb")
        self.header_result = None
    def connectionMade(self):

        self.srv_queue = defer.DeferredQueue()
        self.cli_queue = defer.DeferredQueue()
        self.srv_queue.get().addCallback(self.clientDataReceived) ## 使用队列与回调函数共同工作,
        self.client_address = (self.transport.getPeer().host,self.transport.getPeer().port)
        self.stage = STAGE_INIT
        print("connection Made: ",self.client_address," ### ", self.stage)

    def clientDataReceived(self, chunk):
        data = self.encryptor.encrypt(chunk)
        log.msg("Server: writing %d bytes to original client" % len(chunk))
        self.transport.write(data)
        self.srv_queue.get().addCallback(self.clientDataReceived)

    def dataReceived(self, chunk):
        data = self.encryptor.decrypt(chunk)
        print(data.encode('hex_codec'), " ### ", self.stage )
        if self.stage == STAGE_INIT:
            self.header_result = parse_header(data)
            if self.header_result is None:
                raise Exception('can not parse header')
      
            print("after parse_header\n")
            addrtype, remote_addr, remote_port, header_length = self.header_result
            print('connecting %s:%d from %s:%d' % (common.to_str(remote_addr), remote_port, self.client_address[0], self.client_address[1]))
            self.remote_address = (common.to_str(remote_addr), remote_addr, remote_port)
            self.stage = STAGE_CONNECTING
            factory = ProxyClientFactory(self.srv_queue, self.cli_queue)
            reactor.connectTCP(self.remote_address[0], self.remote_address[2], factory) 
            log.msg("Server: %d bytes received" % len(chunk))
            self.cli_queue.put(data[header_length:])
        else:
            self.cli_queue.put(data)

    def connectionLost(self, why):
        print("cut off")
        self.header_result = None
        self.cli_queue.put(False)



if __name__ == "__main__":
    log.startLogging(sys.stdout)
    factory = protocol.Factory()
    factory.protocol = ProxyServer
    reactor.listenTCP(1234, factory, interface="0.0.0.0")
    reactor.run()
