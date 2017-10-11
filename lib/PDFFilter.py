#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2014-2017 Yuhei Otsubo
Released under the MIT license
http://opensource.org/licenses/mit-license.php
"""

import PDFObj
import re
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
import zlib
import JPEGCheck

def decompress(data):
    try:
        decompressor = zlib.decompressobj()
        decompressed = decompressor.decompress(data)

        l = len(decompressor.unused_data)
        if l >= 32:#復号の際に付くゴミのサイズ以上があれば警告
            decompressed += '__UnusedData__%d__'%l + decompressor.unused_data

        return decompressed
    except Exception as e:
        return "zlib decompress error\n"+str(e)+"aaa"+data
    
def compress(data):
    return zlib.compress(data)

def JBIG2Decode(data, decodeParams=None):
    #終端を示すマーカーFF ACを検索
    l = len(data)
    eof = False

    pos = 0
    eof_pos = 0
    while pos < l-1:
        tok = ord(data[pos])
        if tok == 0xFF:
            if ord(data[pos+1]) == 0xAC:
                eof_pos = pos
        pos += 1
    if l-eof_pos < 512+2:
        return "JBIG2"
    else:
        return "JBIG2 Error"
    
def FlateDecode(data, decodeParams=None):
    #一時的にDecodeParmsの処理を削除
    decodeParams=None

    data = decompress(data)
    predictor = 1
    p = re.compile('zlib decompress error')
    m = p.match(data)
    if decodeParams:
        predictor = decodeParams['/Predictor']
    if predictor != 1 and not m:
        columns = decodeParams['/Columns']
        # PNG prediction:
        if predictor >= 10 and predictor <= 15:
            output = StringIO()
            # PNG prediction can vary from row to row
            rowlength = columns + 1
            assert len(data) % rowlength == 0
            prev_rowdata = (0,) * rowlength
            for row in xrange(len(data) / rowlength):
                rowdata = [ord(x) for x in data[(row*rowlength):((row+1)*rowlength)]]
                filterByte = rowdata[0]
                if filterByte == 0:
                    pass
                elif filterByte == 1:
                    for i in range(2, rowlength):
                        rowdata[i] = (rowdata[i] + rowdata[i-1]) % 256
                elif filterByte == 2:
                    for i in range(1, rowlength):
                        rowdata[i] = (rowdata[i] + prev_rowdata[i]) % 256
                else:
                    # unsupported PNG filter
                    print "Unsupported PNG filter %r" % filterByte
                prev_rowdata = rowdata
                output.write(''.join([chr(x) for x in rowdata[1:]]))
            data = output.getvalue()
        else:
            # unsupported predictor
            print "Unsupported flatedecode predictor %r" % predictor
    return data
        

def ASCIIHexDecode(data, decodeParms=None):
    p = re.compile("[0-9a-fA-F\s]+>")
    m = p.match(data)
    if not m:
        p = re.compile("[0-9a-fA-F\s]+")
        m = p.match(data)
        if m:
            data = data[:m.end()]+">"
        else:
            return "ASCIIHexDecode error\n"+data
    retval = ""
    char = ""
    x = 0
    while True:
        c = data[x]
        if c == ">":
            break
        elif c.isspace():
            x += 1
            continue
        char += c
        if len(char) == 2:
            retval += chr(int(char, base=16))
            char = ""
        x += 1
    #assert char == ""
    return retval

def ASCII85Decode(data, decodeParms=None):
    retval = ""
    group = []
    x = 0
    hitEod = False
    # remove all whitespace from data
    data = [y for y in data if not (y in ' \n\r\t')]
    while not hitEod:
        c = data[x]
        if len(retval) == 0 and c == "<" and data[x+1] == "~":
            x += 2
            continue
        elif c == 'z':
            assert len(group) == 0
            retval += '\x00\x00\x00\x00'
            x += 1
            continue
        elif c == "~" and data[x+1] == ">":
            if len(group) != 0:
                # cannot have a final group of just 1 char
                assert len(group) > 1
                cnt = len(group) - 1
                group += [ 85, 85, 85 ]
                hitEod = cnt
            else:
                break
        else:
            c = ord(c) - 33
            if c < 0 and c > 85:
                return 'ASCII85Decode error'
            group += [ c ]
        if len(group) >= 5:
            b = group[0] * (85**4) + \
                group[1] * (85**3) + \
                group[2] * (85**2) + \
                group[3] * 85 + \
                group[4]
            assert b < (2**32)
            c4 = chr((b >> 0) % 256)
            c3 = chr((b >> 8) % 256)
            c2 = chr((b >> 16) % 256)
            c1 = chr(b >> 24)
            retval += (c1 + c2 + c3 + c4)
            if hitEod:
                retval = retval[:-4+hitEod]
            group = []
        x += 1
        if x >= len(data):
            #print "End of stream"
            break
    return retval

#streamdataのデコード
def DecodeStream(obj):
    #print "%08X"%obj.start_pos
    if obj.has_key('/Filter'):
        if isinstance(obj['/Filter'], PDFObj.ArrayObject):
            #Filterがリスト型の場合
            #print "/Filter:",obj['/Filter']
            for i in range(0,len(obj['/Filter'])):
                if obj['/Filter'][i] == '/FlateDecode':
                    #FlateDecode
                    if obj.has_key('/DecodeParms'):
                        obj[PDFObj.NameObject('__streamdata__')] = PDFObj.StringObject(FlateDecode(obj['__streamdata__'],obj['/DecodeParms']))
                    else:
                        obj[PDFObj.NameObject('__streamdata__')] = PDFObj.StringObject(FlateDecode(obj['__streamdata__']))
                        
                if obj['/Filter'][i] == '/ASCIIHexDecode':
                    #ASCIIHexDecode
                    obj[PDFObj.NameObject('__streamdata__')] = PDFObj.StringObject(ASCIIHexDecode(obj['__streamdata__']))
                if obj['/Filter'][i] == '/ASCII85Decode':
                    #ASCII85Decode
                    obj[PDFObj.NameObject('__streamdata__')] = PDFObj.StringObject(ASCII85Decode(obj['__streamdata__']))
                if obj['/Filter'][i] == '/DCTDecode':
                    #DCTDecode
                    obj[PDFObj.NameObject('__streamdata__')] = PDFObj.StringObject(JPEGCheck.JPEGCheck(obj['__streamdata__']))
                if obj['/Filter'][i] == '/JBIG2Decode':
                    #JBIG2Decode
                    obj[PDFObj.NameObject('__streamdata__')] = PDFObj.StringObject(JBIG2Decode(obj['__streamdata__']))
                
        elif isinstance(obj['/Filter'], PDFObj.NameObject):
            #Filterが名前型の場合
            #print "/Filter:",obj['/Filter']
            if obj['/Filter'] == '/FlateDecode':
                #FlateDecode
                if obj.has_key('/DecodeParms'):
                    obj[PDFObj.NameObject('__streamdata__')] = PDFObj.StringObject(FlateDecode(obj['__streamdata__'],obj['/DecodeParms']))
                else:
                    obj[PDFObj.NameObject('__streamdata__')] = PDFObj.StringObject(FlateDecode(obj['__streamdata__']))
            if obj['/Filter'] == '/ASCIIHexDecode':
                #ASCIIHexDecode
                obj[PDFObj.NameObject('__streamdata__')] = PDFObj.StringObject(ASCIIHexDecode(obj['__streamdata__']))
            if obj['/Filter'] == '/ASCII85Decode':
                #ASCII85Decode
                obj[PDFObj.NameObject('__streamdata__')] = PDFObj.StringObject(ASCII85Decode(obj['__streamdata__']))
            if obj['/Filter'] == '/DCTDecode':
                #DCTDecode
                obj[PDFObj.NameObject('__streamdata__')] = PDFObj.StringObject(JPEGCheck.JPEGCheck(obj['__streamdata__']))
            if obj['/Filter'] == '/JBIG2Decode':
                #JBIG2Decode
                obj[PDFObj.NameObject('__streamdata__')] = PDFObj.StringObject(JBIG2Decode(obj['__streamdata__']))
    return obj
