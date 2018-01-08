#!/usr/bin/env python
#-*- coding: utf-8 -*-
import socket
import struct

class IPHelp(object):
    def __init__(self):
        pass

    @classmethod
    def IntToString(cls, net_ip):
        return socket.inet_ntoa(struct.pack('I', net_ip))

    @classmethod
    def StringToInt(cls, str_ip):
        return struct.unpack('I', socket.inet_aton(str_ip))[0]