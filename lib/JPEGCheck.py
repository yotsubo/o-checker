#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2014-2026 Yuhei Otsubo
Released under the MIT license
http://opensource.org/licenses/mit-license.php
"""

import struct

#JPEGの形式が正式なものかチェック
def JPEGCheck(data):
    pos = 0
    ret = bytearray()
    l = len(data)
    while pos < l:
        tok = struct.unpack('>H',data[pos:pos+2])[0]
        pos += 2
        if tok == 0xFFD8:
            #SOI:Start of Image
            ret += b'%08X:SOI\n' % (pos-2)
            continue
        elif tok == 0xFFC0:
            #SOF0 標準DCT圧縮
            ret += b'%08X:SOF0\n' % (pos-2)
            tok2 = struct.unpack('>H',data[pos:pos+2])[0]
            pos += tok2
        elif tok == 0xFFC1:
            #SOF0 DCT圧縮(adobe original?)
            ret += b'%08X:SOF0(adobe)\n' % (pos-2)
            tok2 = struct.unpack('>H',data[pos:pos+2])[0]
            pos += tok2
        elif tok == 0xFFC2:
            #SOF0 DCT圧縮(????)暫定
            ret += b'%08X:SOF0(???)\n' % (pos-2)
            tok2 = struct.unpack('>H',data[pos:pos+2])[0]
            pos += tok2
        elif tok == 0xFFC4:
            #DHT
            ret += b'%08X:DHT\n' % (pos-2)
            tok2 = struct.unpack('>H',data[pos:pos+2])[0]
            pos += tok2
        elif tok >= 0xFFD0 and tok <= 0xFFD7:
            #SOS?
            ret += b'%08X:SOS?\n' % (pos-2)
            while pos < l:
                tok2 = struct.unpack('B',data[pos:pos+1])[0]
                pos += 1
                if tok2 != 0xFF:
                    continue
                else:
                    tok3 = struct.unpack('B',data[pos:pos+1])[0]
                    if tok3 == 0:
                        pos += 1
                    else:
                        pos -= 1
                        break
        elif tok == 0xFFD9:
            #EOI:End of Image
            ret += b'%08X:EOI\n' % (pos-2)
            break
            
        elif tok == 0xFFDA:
            #SOS Start of Scan
            ret += b'%08X:SOS\n' % (pos-2)
            while pos < l:
                tok2 = struct.unpack('B',data[pos:pos+1])[0]
                pos += 1
                if tok2 != 0xFF:
                    continue
                else:
                    tok3 = struct.unpack('B',data[pos:pos+1])[0]
                    if tok3 == 0:
                        pos += 1
                    else:
                        pos -= 1
                        break
        elif tok == 0xFFDB:
            #DQT 量子化テーブル定義
            ret += b'%08X:DQT\n' % (pos-2)
            tok2 = struct.unpack('>H',data[pos:pos+2])[0]
            pos += tok2
        elif tok == 0xFFDD:
            #DRI
            ret += b'%08X:DRI\n' % (pos-2)
            tok2 = struct.unpack('>H',data[pos:pos+2])[0]
            pos += tok2
            continue
        elif tok >= 0xFFE0 and tok <= 0xFFED:
            #APP0
            ret += b'%08X:APPx\n' % (pos-2)
            tok2 = struct.unpack('>H',data[pos:pos+2])[0]
            pos += tok2
        elif tok == 0xFFEE:
            #Adobe形式？
            ret += b'%08X:Adobex\n' % (pos-2)
            tok2 = struct.unpack('>H',data[pos:pos+2])[0]
            pos += tok2
        elif tok == 0xFFFE:
            #Adobe形式？
            ret += b'%08X:Adobex\n' % (pos-2)
            tok2 = struct.unpack('>H',data[pos:pos+2])[0]
            pos += tok2
        elif tok == 0xFFFF:
            #0xFFFFの時の処理（暫定）
            pos -= 1
        else:
            #error
            ret += b'%08X:Unknown Marker' % (pos-2) +(b'%04X\n' % tok)
            break

    if pos <= l and pos >= l-48:
        ret += b'Normal JPEG\n'
    else:
        null_flag = True
        for i in range(pos,l):
            if ord(data[i:i+1]) != 0:
                null_flag = False
        ret += b'%08X-'%pos + b'%08X:'%l
        if null_flag:
            ret += b'Null\n'
        else:
            ret += b'Malicious JPEG\n'


    return ret
            
            
