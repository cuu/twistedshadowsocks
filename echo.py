#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2012-2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import sys 
import os
import logging
import signal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))

from twisted.names import client
from twisted.internet import protocol, reactor, endpoints

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


class Echo(protocol.Protocol):
  def __init__(self):
    self._encryptor = encrypt.Encryptor("fuckyou","aes-256-cfb")
    self._stage = STAGE_INIT
    self._client_address = []
    self._remote_address = None
    self.dns_resolver =  client.createResolver(servers=[('8.8.8.8', 53), ('8.8.4.4', 53)], hosts='/etc/hosts')
    self.clients = {}

  #def makeConnection(self, transport): 
  #  self._client_address = transport.get_extra_info("peername")[:2]
  #  self.transport = transport
  def make_peer_id(host,port):
    self.clients [host+"_"+str(port)] = {}

  def connectionMade(self):
    print( "Connection from", self.transport.getPeer(), " ", self.transport.getHost())
    self._client_address.insert(0, self.transport.getPeer().host)
    self._client_address.insert(1, self.transport.getPeer().port)
    
    self.clients[self.transport.getPeer().host +"_"+ str(self.transport.getPeer().port)] = {}
    

  def connectionLost(self, reason):
    self.clients.pop( self._client_address[0]+"_"+self._client_address[1])
  
  def _handle_dns_resolved(self, address, hostname):
    if address:
      sys.stdout.write(address + '\n')
      self._stage = STAGE_CONNECTING
      self.handle_stage()
    else:
      sys.stderr.write(
        'ERROR: No IP addresses found for name %r\n' % (hostname,))
  
  def handle_stage(self):
    print("in stage: ",STAGE_STR[self._stage])
    if self._stage == STAGE_DNS:
      self._dns_resolver.getHostByName( self._remote_address[0] )
      self._dns_resolver.addCallback(self._handle_dns_resolved)
    if self._stage == STAGE_CONNECTING:
      
  def dataReceived(self, data):
    data = self._encryptor.decrypt(data)
    print(data.encode('hex_codec') )
    
    if self._stage == STAGE_INIT:
      header_result = parse_header(data)
      if header_result is None:
        raise Exception('can not parse header')
      
      print("after parse_header\n")
      addrtype, remote_addr, remote_port, header_length = header_result

      print('connecting %s:%d from %s:%d' % (common.to_str(remote_addr), remote_port, self._client_address[0], self._client_address[1]))
      self._remote_address = (common.to_str(remote_addr), remote_addr, remote_port)
      # pause reading
      self._stage = STAGE_DNS
      self.handle_stage()

class EchoFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return Echo()

endpoints.serverFromString(reactor, "tcp:1234").listen(EchoFactory())
reactor.run()
