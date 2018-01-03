#!/usr/bin/env python
#-*- coding: utf-8 -*-
import struct
import logging

''' 
为与已有项目c++通信(已有项目使用的是小端)，故而使用小端
'''

#序列化数据
class Serialize(object):
    def __init__(self, data=None):
        self.data = b''
        self.dataLength = 0
        self.pos = 0

        if data != None:
            self.data = data
            self.dataLength = len(data)

    def writeInt(self, intValue):
        self.data += struct.pack("<i", intValue)
        self.dataLength += 4
        #\print data

    def writeUInt(self, uintValue):
        self.data += struct.pack("<I", uintValue)
        self.dataLength += 2

    def writeByte(self, byteValue):
        self.data += struct.pack("<B", byteValue)
        self.dataLength += 1

    def writeUShort(self, ushortValue):
        self.data += struct.pack("<H", ushortValue)
        self.dataLength += 2

    def writeInt64(self, int64Value):
        self.data += struct.pack("<q", int64Value)
        self.dataLength += 8

    def writeString(self, strValue):
        strLen = len(strValue)
        format = "<%ds" % strLen
        self.data += struct.pack(format, strValue)
        self.dataLength += strLen

    def getData(self):
        return (self.data, self.dataLength)

    def readInt(self):
        if self.pos + 4 > self.dataLength:
            return None
        value = struct.unpack("<i", self.data[self.pos:self.pos+4])[0]
        self.pos += 4
        return value

    def readUInt(self):
        if self.pos + 4 > self.dataLength:
            return None
        value = struct.unpack("<I", self.data[self.pos:self.pos+4])[0]
        self.pos += 4
        return  value

    def readByte(self):
        if self.pos + 1 > self.dataLength:
            return None
        value = struct.unpack("<B", self.data[self.pos:self.pos+1])[0]
        self.pos += 1
        return value

    def readUShort(self):
        if self.pos + 2 > self.dataLength:
            return None
        value = struct.unpack("<H", self.data[self.pos:self.pos+2])[0]
        self.pos += 2
        return value

    def readInt64(self):
        if self.pos + 8 > self.dataLength:
            return None
        value = struct.unpack("<q", self.data[self.pos:self.pos+8])[0]
        self.pos += 8
        return value

    def readString(self, length):
        if self.pos + length > self.dataLength:
            return b''
        format = "<%ds" % length
        strValue = struct.unpack(format, self.data[self.pos:self.pos+length])[0]
        self.pos += length
        return strValue

#网络字节流封侦解侦
'''
包格式:包头('\x03\x02')+版本(1个字节)+包头长(1个字节unsigned char)+包长(2个字节unsigned short)+包体+效验(2个字节)+包尾('\x05\x04')
'''
class NetFrame(object):
    def __init__(self):
        self.data = []
        self.pos = 0
        self.header = b'\x03\x02'
        self.tail = b'\x05\x04'
        self.ver = b'\x01'
        self.headerLength = 6
        self.tailLength = 4

    def removeByte(self, buf):
        if buf is None:
            return None
        if len(buf) < 1:
            return b''

        buf = buf[1:]
        self.pos = 0
        return buf

    def pack(self, data):
        #数据长度
        dataLength = len(data)

        #包头
        fmt = '<%ds' % len(self.header)
        buf = struct.pack(fmt, self.header)

        #版本
        buf += struct.pack("<s", self.ver)

        #包头长
        buf += struct.pack("<B", self.headerLength)

        #包长
        buf += struct.pack("<H", dataLength)

        #包体
        fmt = "<%ds" % dataLength
        buf += struct.pack(fmt, data)

        #效验
        buf += struct.pack("<H", self.headerLength+self.tailLength+dataLength)

        #包尾
        fmt = '<%ds' % len(self.tail)
        buf += struct.pack('<BB', 0x5, 0x4)

        return buf

    def appendData(self, data):
        self.data.append(data)

    def unpack(self):
        result = False
        packData = b''
        self.pos = 0
        buf = b''.join(self.data)
        if not buf:
            result = False
            return packData, result
        del self.data[:]
        logging.debug('unpack:len=%d' % len(buf))
        while True:
            #包头
            if self.pos + len(self.header) > len(buf):
                break
            fmt = '<%ds' % len(self.header)
            header = struct.unpack(fmt, buf[self.pos:self.pos+len(self.header)])[0]
            if header != self.header:
                buf = self.removeByte(buf)
                continue
            self.pos += len(self.header)

            #版本
            if self.pos + len(self.ver) > len(buf):
                break
            ver = struct.unpack("<s", buf[self.pos:self.pos + len(self.ver)])[0]
            if ver != self.ver:
                buf = self.removeByte(buf)
                continue
            self.pos += 1

            #包头长
            if self.pos + 1 > len(buf):
                break
            headLen = struct.unpack("<B", buf[self.pos:self.pos + 1])[0]
            if headLen != self.headerLength:
                buf = self.removeByte(buf)
                continue
            self.pos += 1

            #包长
            if self.pos + 2 > len(buf):
                break
            packLen = struct.unpack("<H", buf[self.pos:self.pos + 2])[0]
            if self.pos + packLen > len(buf):
                buf = self.removeByte(buf)
                continue
            self.pos += 2

            #包体
            fmt = '<%ds' % packLen
            logging.debug('fmt=%s, buflen=%d' % (fmt, len(buf)))
            packData = struct.unpack(fmt, buf[self.pos:self.pos + packLen])[0]
            self.pos += packLen

            if self.pos + 2 > len(buf):
                break
            checkCode = struct.unpack("<H", buf[self.pos:self.pos + 2])[0]
            if checkCode != self.headerLength + self.tailLength + packLen:
                buf = self.removeByte(buf)
                continue
            self.pos += 2

            #包尾
            if self.pos + len(self.tail) > len(buf):
                break
            fmt = '<%ds' % len(self.tail)
            tail = struct.unpack(fmt, buf[self.pos:self.pos + len(self.tail)])[0]
            if tail != self.tail:
                buf = self.removeByte(buf)
                continue
            self.pos += len(self.tail)

            result = True
            buf = buf[self.pos:]
            break

        self.data.append(buf)
        logging.debug('unpack end len=%d' % len(buf))
        return packData, result

 #最小包长
MIN_NET_FRAME_LEN = 10
#最大包长
MAX_NET_FRAME_LEN = 1560
'''
包格式:'('+包头长(4个字节整数)+包体长(4个字节整数)+包头+包体+')'
'''
class PBNetFrame(object):
    def __init__(self):
        self.data = []
        self.pos = 0

    def removeByte(self, buf):
        if buf is None:
            return None
        if len(buf) < 1:
            return b''

        buf = buf[1:]
        self.pos = 0
        return buf

    def pack(self, head, body):
        if head is None:
            return None
        if body is None:
            return None

        strHead = head.SerializeToString()
        strBody = body.SerializeToString()
        buf = struct.pack('!c', '(')
        buf += struct.pack('!I', len(strHead))
        buf += struct.pack('!I', len(strBody))
        fmt = '!%ds' % len(strHead)
        buf += struct.pack(fmt, strHead)
        fmt = '!%ds' % len(strBody)
        buf += struct.pack(fmt, strBody)
        buf += struct.pack('!c', ')')
        return buf

    def appendData(self, data):
        self.data.append(data)

    def unpack(self):
        result = False
        if not self.data:
            return result, None, None

        buf = b''.join(self.data)
        if len(buf) < MIN_NET_FRAME_LEN:
            return result, None, None

        del self.data[:]
        while True:
            #包头分割符
            if len(buf) < self.pos+1:
                continue
            hSpan = struct.unpack('!c', buf[self.pos:self.pos+1])[0]
            if hSpan != '(':
                buf = self.removeByte(buf)
                continue
            self.pos += 1

            #包头长度
            if len(buf) < self.pos+4:
                continue
            headSize = struct.unpack('!I', buf[self.pos:self.pos+4])[0]
            self.pos += 4

            #包体长度
            if len(buf) < self.pos+4:
                continue
            bodySize = struct.unpack('!I', buf[self.pos:self.pos+4])[0]
            self.pos += 4

            #包头
            if len(buf) < self.pos+headSize:
                continue
            fmt = '!%ds' % headSize
            head = struct.unpack(fmt, buf[self.pos:self.pos+headSize])[0]
            self.pos += headSize

            #包体
            if len(buf) < self.pos+bodySize:
                continue
            fmt = '!%ds' % bodySize
            body = struct.unpack(fmt, buf[self.pos:self.pos+bodySize])[0]
            self.pos += bodySize

            #包尾分割符
            if len(buf) <self.pos+1:
                continue
            tSpan = struct.unpack('!c', buf[self.pos:self.pos+1])[0]
            self.pos += 1
            buf = buf[self.pos:]
            result = True
            break

        self.data.append(buf)
        return result, head, body


def test():
    serialize = Serialize()
    serialize.writeUShort(1403)

if __name__ == '__main__':
    test()
else:
    print('module: %s' % __name__)

