#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2014-2017 Yuhei Otsubo
Released under the MIT license
http://opensource.org/licenses/mit-license.php
"""


import re
import decimal

class PdfObject(object):
    idnum = -1
    generation = -1
    start_pos = -1
    end_pos = -1
    fOBJ = False
    fFreeOBJ = False
    fOldOBJ = False
    fTrailer = False
    fComment = False
    fXref = False
    fStartXref = False
    fObjStm = False
    fXrefStm = False
    fEtc = False
    fLinearPDF = False
    fHintStream = False
    fXMLmetadata = False
    ObjStm = None
    xref = None
    fEOF = False

    def getLength(self):
        return self.end_pos - self.start_pos
    
    def getID(self):
        return int(self.idnum)

    def getGeneration(self):
        return int(self.generation)

    def setID(self,idnum):
        self.idnum = int(idnum)

    def setGeneration(self,generation):
        self.generation = int(generation)

    def getObject(self):
        return self

#小数型
class FloatObject(decimal.Decimal,PdfObject):
    def __new__(cls, value='0', context=None):
        return decimal.Decimal.__new__(cls, str(value), context)
    
#数値型
class NumberObject(int,PdfObject):
    def __init__(self, value):
        int.__init__(value)
    def ReadFromStream(self,stream):
        pos = stream.get_pos()
        start_pos = stream.get_pos()
        phrase = stream.read_phrase_u()
        end_pos = stream.get_pos()
        p = re.compile("([-+]?([0-9]+(\.[0-9]*)?|\.[0-9]+)?)")
        m = p.match(phrase)
        if m:
            if m.groups()[0].find('.') != -1:
                ret = FloatObject(m.groups()[0])
                ret.start_pos = start_pos
                ret.end_pos = end_pos
                return ret
            else:
                ret = NumberObject(m.groups()[0])
                ret.start_pos = start_pos
                ret.end_pos = end_pos
                return ret
        else:
            stream.set_pos(pos)
            return NullObject()

 
#文字列型
class StringObject(str,PdfObject):
        
    def __init__(self,value):
        str.__init__(value)
    def ReadFromStreamHex(self,stream):
        pos = stream.get_pos()
        start_pos = stream.get_pos()
        tok = stream.get_u()
        if tok != '<':
            stream.set_pos(pos)
            return NullObject
        x = ''
        txt = ''
        while True:
            stream.skip_blank()
            tok = stream.get()
            if tok == '>':
                break
            x += tok
            if len(x) == 2:
                txt += chr(int(x, base=16))
                x = ''
        if len(x) == 1:
            x += '0'
        if len(x) == 2:
            txt += chr(int(x, base=16))
        end_pos = stream.get_pos()
        ret = StringObject(txt)
        ret.start_pos = start_pos
        ret.end_pos = end_pos
        return ret
    def ReadFromStream(self,stream):
        pos = stream.get_pos()
        start_pos = stream.get_pos()
        tok = stream.get_u()
        if tok != '(':
            stream.set_pos(pos)
            return NullObject()
        parens = 1
        txt = ''
        while True:
            tok = stream.get()
            if tok == 'EOF':
                break
            elif tok == '(':
                parens += 1
            elif tok == ')':
                parens -= 1
                if parens == 0:
                    break
            elif tok == '\\':
                tok = stream.get()
                if tok == 'n':
                    tok = '\n'
                elif tok == 'r':
                    tok = '\r'
                elif tok == 't':
                    tok = '\t'
                elif tok == 'b':
                    tok = '\b'
                elif tok == 'f':
                    tok = '\f'
                elif tok == '(':
                    tok = '('
                elif tok == ')':
                    tok = ')'
                elif tok == '\\':
                    tok = '\\'
                elif tok.isdigit():
                    # "The number ddd may consist of one, two, or three
                    # octal digits; high-order overflow shall be ignored.
                    # Three octal digits shall be used, with leading zeros
                    # as needed, if the next character of the string is also
                    # a digit." (PDF reference 7.3.4.2, p 16)
                    for i in range(2):
                        ntok = stream.get()
                        stream.bak_pos()
                        if ntok.isdigit():
                            tok += ntok
                            stream.get()
                        else:
                            break
                    try:
                        tok = chr(int(tok, base=8))
                    except:
                        #変換に失敗した場合はそのまま
                        tok = tok
            elif tok in '\n\r':
                # This case is  hit when a backslash followed by a line
                # break occurs.  If it's a multi-char EOL, consume the
                # second character:
                pos = stream.get_pos()
                tok = stream.get()
                if not tok in "\n\r":
                    stream.set_pos(pos)
                else:
                    break
                # Then don't add anything to the actual string, since this
                # line break was escaped:
                tok = ''
            #else:#読み込みエラー
                
            txt += tok
        end_pos = stream.get_pos()
        ret = StringObject(txt)
        ret.start_pos = start_pos
        ret.end_pos = end_pos
        return ret
                
#名前型
class NameObject(str,PdfObject):

    def __init__(self, value):
        str.__init__(value)
    def ReadFromStream(self,stream):
        start_pos = stream.get_pos()
        pos = stream.get_pos()
        tok = stream.get_u()
        if tok != '/':
            stream.set_pos(pos)
            return NullObject()
        phrase = tok + stream.read_phrase_u()
        p = re.compile("//")
        m = p.match(phrase)
        if m:
            stream.set_pos(start_pos)
            stream.get_u()
            ret = NameObject("")
            ret.start_pos = start_pos
            ret.end_pos = start_pos
            return ret

        p = re.compile("(/[^\s\(\)\<\>\[\]\{\}/\%]*)")
        m = p.match(phrase)
        end_pos = stream.get_pos()
        if m:
            ret = NameObject(m.groups()[0])
            ret.start_pos = start_pos
            ret.end_pos = end_pos
            return ret

#Boolean型
class BooleanObject(PdfObject):
    def __init__(self, value):
        self.value = value
    def __repr__(self):
        if self.value:
            return "true"
        else:
            return "false"
    def ReadFromStream(self,stream):
        start_pos = stream.get_pos()
        pos = stream.get_pos()
        phrase = stream.read_phrase_u()
        end_pos = stream.get_pos()
        p = re.compile("true")
        m = p.match(phrase)
        if m:
            ret = BooleanObject(True)
            ret.start_pos = start_pos
            ret.end_pos = end_pos
            return ret
        p = re.compile("false")
        m = p.match(phrase)
        if m:
            ret = BooleanObject(False)
            ret.start_pos = start_pos
            ret.end_pos = end_pos
            return ret
        stream.set_pos(pos+1)
        return NullObject()
        
        

#null object
class NullObject(PdfObject):
    def ReadFromStream(self,stream):
        start_pos = stream.get_pos()
        pos = stream.get_pos()
        phrase = stream.read_phrase_u()
        end_pos = stream.get_pos()
        p = re.compile("null")
        m = p.match(phrase)
        if m:
            ret = NullObject()
            ret.start_pos = start_pos
            ret.end_pos = end_pos
            return ret
        stream.set_pos(pos+1)
        return NullObject()

#list object
class ArrayObject(list,PdfObject):
    def ReadFromStream(self,stream):
        start_pos = stream.get_pos()
        arr = ArrayObject()
        pos = stream.get_pos()
        tok = stream.get_u()
        if tok != '[':
            stream.set_pos(pos)
            return NullObject()
        while True:
            # skip leading whitespace
            stream.skip_blank()

            tok = stream.get_u()
            stream.bak_pos()
            # check for array ending
            if tok == ']' or tok == 'EOF':
                stream.get_u()
                break
            # read and append obj
            obj = ReadObject(stream)
            arr.append(obj)
        end_pos = stream.get_pos()
        arr.start_pos = start_pos
        arr.end_pos = end_pos
        return arr

#Dictionary Object
class DictionaryObject(dict, PdfObject):
    def __init__(self, *args, **kwargs):
        if len(args) == 0:
            self.update(kwargs)
        elif len(args) == 1:
            arr = args[0]
            # If we're passed a list/tuple, make a dict out of it
            if not hasattr(arr, "iteritems"):
                newarr = {}
                for k, v in arr:
                    newarr[k] = v
                arr = newarr
            self.update(arr)
        else:
            raise TypeError("dict expected at most 1 argument, got 3")

    def update(self, arr):
        # note, a ValueError halfway through copying values
        # will leave half the values in this dict.
        for k, v in arr.iteritems():
            self.__setitem__(k, v)

    def raw_get(self, key):
        return dict.__getitem__(self, key)

    def __setitem__(self, key, value):
        if not isinstance(key, PdfObject):
            raise ValueError("key must be PdfObject")
        if not isinstance(value, PdfObject):
            raise ValueError("value must be PdfObject")
        return dict.__setitem__(self, key, value)

    def setdefault(self, key, value=None):
        if not isinstance(key, PdfObject):
            raise ValueError("key must be PdfObject")
        if not isinstance(value, PdfObject):
            raise ValueError("value must be PdfObject")
        return dict.setdefault(self, key, value)

    def __getitem__(self, key):
        return dict.__getitem__(self, key).getObject()

    def ReadFromStream(self, stream):
        start_pos = stream.get_pos()
        pos = stream.get_pos()
        tok = stream.get_u() + stream.get_u()
        data = {}
        if tok != '<<':
            stream.set_pos(pos)
            return NullObject()

        while True:
            # skip leading whitespace
            stream.skip_blank()

            tok = stream.get_u()
            stream.bak_pos()
            # check for array ending
            if tok == '>' or tok == 'EOF':
                tok = stream.get_u()
                tok = stream.get_u()
                if tok != '>':
                    stream.bak_pos()
                break
            # read and append obj
            key = ReadObject(stream)
            # skip leading whitespace
            stream.skip_blank()

            tok = stream.get_u()
            stream.bak_pos()
            if tok == '>':
                #valueが定義されていない場合はnullとして扱う
                value = NullObject()
            else:
                value = ReadObject(stream)
            #print key,value
            if data.has_key(key):
                #multiple difinitions of key not mermitted
                print "同じキーが複数あります"
            data[key] = value
        end_pos = stream.get_pos()
        ret = DictionaryObject()
        ret.update(data)
        ret.start_pos = start_pos
        ret.end_pos = end_pos
        return ret
            
            
        

#間接参照
class IndirectObject(PdfObject):
    def __init__(self, idnum, generation):
        self.idnum = int(idnum)
        self.generation = int(generation)

    def __repr__(self):
        return "(%r %r R)" % (self.idnum, self.generation)

    def ReadFromStream(self,stream):
        start_pos = stream.get_pos()
        pos = stream.get_pos()
        phrase = stream.read_phrase_u()
        phrase += ' ' + stream.read_phrase_u()
        phrase += ' ' + stream.read_phrase_u()
        end_pos = stream.get_pos()
        p = re.compile("(\d+)\s+(\d+)\s+R")
        m = p.match(phrase)
        if m:
            ret = IndirectObject(int(m.groups()[0]),int(m.groups()[1]))
            ret.start_pos = start_pos
            ret.end_pos = end_pos
            return ret
        stream.set_pos(pos)
        return NullObject()


def ReadObject(stream):
    stream.skip_blank()
    pos = stream.get_pos()
    tok = stream.get_u()
    #print "%08X"%pos,tok
    stream.bak_pos()
    if tok=='t' or tok=='f':
        #boolean
        ret = BooleanObject(True)
        return ret.ReadFromStream(stream)
    elif tok == '(':
        #string
        ret = StringObject('')
        return ret.ReadFromStream(stream)
    elif tok == '/':
        #name
        ret = NameObject('')
        return ret.ReadFromStream(stream)
    elif tok == '[':
        #list
        ret = ArrayObject()
        return ret.ReadFromStream(stream)
    elif tok == 'n':
        #null
        ret = NullObject()
        return ret.ReadFromStream(stream)
    elif tok == '<':
        peek = stream.get_u() + stream.get_u()
        stream.set_pos(pos)
        if peek == '<<':
            #dictionary
            ret = DictionaryObject()
            return ret.ReadFromStream(stream)
        else:
            #文字列(16進数表記)
            ret = StringObject("")
            return ret.ReadFromStreamHex(stream)
    elif tok == '%':
        #coment
        stream.read_line()
        return ReadObject(stream)
    elif tok == 'e':
        peek = stream.read_phrase_u()
        if peek =='endobj':
            #endobjの場合とりあえずnullにする
            #stream.set_pos(pos)
            ret = NullObject()
            return ret
        else:
            #errorとりあえずnullにする
            ret = NullObject()
            return ret
    else:
        #number or indirect reference
        if tok == '+' or tok == '-':
            #number
            ret = NumberObject(0)
            return ret.ReadFromStream(stream)
        phrase = stream.read_phrase_u()
        phrase += ' ' + stream.read_phrase_u()
        phrase += ' ' + stream.read_phrase_u()
        stream.set_pos(pos)
        p = re.compile("(\d+)\s+(\d+)\s+R")
        m = p.match(phrase)
        if m:
            #indirect reference
            ret = IndirectObject(0,0)
            return ret.ReadFromStream(stream)
        else:
            if tok in '0123456789.':
                #number
                ret = NumberObject(0)
                return ret.ReadFromStream(stream)
            else:
                #null
                stream.get_u()
                ret = NullObject()
                return ret
    
