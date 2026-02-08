#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2014-2026 Yuhei Otsubo
Released under the MIT license
http://opensource.org/licenses/mit-license.php
"""

class Stream:
    def __init__(self):
        self.lines = bytearray()
        self.analysis = {}
        self.pos = 0
        
    def ReadFile(self,filename):
        input1 = open(filename,"rb")
        self.lines = input1.read();
        input1.close()
        self.pos = 0

    def SetStream(self,stream):
        self.lines = stream
        self.pos = 0

    def isEOF(self):
        return self.pos >= len(self.lines)
    
    def get_pos(self):
        return self.pos

    def set_pos(self,pos):
        self.pos = pos

    def add_pos(self,add):
        self.pos += add
        
    #get without unescape
    def get(self):
        self.pos_ = self.get_pos()
        if self.isEOF():
            self.pos += 1
            return b"EOF"
        else:
            ret = self.lines[self.pos:self.pos+1]
            self.pos += 1
            return ret

    #get with unescape
    def get_u(self):
        pos = self.get_pos()
        tok = self.get()
        if tok == b"EOF":
            return b"EOF"
        elif tok == b'#':
            # '#xx' to charCode
            tok2 = self.get()+self.get()
            if tok2 == b'20' or tok2 == b'2F' or tok2== b'2f' or tok2 == b'28' or tok2 == b'29' or tok2 == b'25' or tok2 == b'5b' or tok2 == b'5B' or tok2 == b'5d' or tok2 == b'5D':
                #空白,\()%の場合は変換しない
                ret = tok
                self.add_pos(-2)
            else:
                try:
                    ret = bytearray(int(tok2, base=16))
                except ValueError:
                    ret = tok
                    self.add_pos(-2)
        else:
            ret = tok

        self.pos_ = pos
        return ret

    #posを直前のget/get_u実行前に戻す
    def bak_pos(self):
        self.set_pos(self.pos_)

    def skip_blank(self):
        pos = self.get_pos()
        tok = self.get_u()
        while tok in (b'\x00',b'\r',b'\n',b'\t',b'\f',b' '):
            pos = self.get_pos()
            tok = self.get_u()
        self.set_pos(pos)
                

    def read_line(self):
        ret = bytearray()
        tok = self.get()
        while tok != b"EOF":
            if tok == b'\r':
                ret += tok
                tok2 = self.get()
                if tok2 == b'\n':
                    ret += tok2
                else:
                    self.add_pos(-1)
                break
            elif tok == b'\n':
                ret += tok
                tok2 = self.get()
                if tok2 == b'\r':
                    ret += tok2
                else:
                    self.add_pos(-1)
                break
            else:
                ret += tok
            tok = self.get()
        return ret

    def read_line_u(self):
        ret = bytearray()
        tok = self.get_u()
        while tok != b"EOF":
            if tok == b'\r':
                ret += tok
                pos = self.get_pos()
                tok2 = self.get_u()
                if tok2 == b'\n':
                    ret += tok2
                else:
                    self.set_pos(pos)
                break
            elif tok == b'\n':
                ret += tok
                pos = self.get_pos()
                tok2 = self.get_u()
                if tok2 == b'\r':
                    ret += tok2
                else:
                    self.set_pos(pos)
                break
            else:
                ret += tok
            tok = self.get_u()
        return ret
    def read_phrase_u(self):
        max_phrase_length = 128
        l = max_phrase_length
        ret = bytearray()
        #self.skip_blank()
        tok = self.get_u()
        if tok in (b'(',b')',b'<',b'>',b'[',b']',b'/',b'%'):
            ret = tok
        else:
            pos = self.get_pos()
            while not tok in (b'\x00',b'\r',b'\n',b'\t',b'\f',b' ',b'EOF',b'(',b')',b'<',b'>',b'[',b']',b'/',b'%'):
                ret += tok
                pos = self.get_pos()
                tok = self.get_u()
                l = l - 1
                if l <= 1:
                    break
            self.set_pos(pos)
        self.skip_blank()
        return ret
    
        
            
            
