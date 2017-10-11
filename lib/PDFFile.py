#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2014-2017 Yuhei Otsubo
Released under the MIT license
http://opensource.org/licenses/mit-license.php
"""

import Stream
import re
import PDFObj
import PDFCrypto
import PDFFilter
import time
import StringIO

__DEBUG__ = False

#オブジェクト中から間接参照を検索してリスト型で返す
def SearchIndirectObject(obj):
    ret = []
    if isinstance(obj, PDFObj.IndirectObject):
        ret.append(obj)
    elif isinstance(obj, PDFObj.DictionaryObject):
        for key in obj:
            if isinstance(obj[key], PDFObj.IndirectObject):
                ret.append(obj[key])
            elif isinstance(obj[key], PDFObj.DictionaryObject):
                ret += SearchIndirectObject(obj[key])
            elif isinstance(obj[key], PDFObj.ArrayObject):
                ret += SearchIndirectObject(obj[key])
    elif isinstance(obj, PDFObj.ArrayObject):
        for i in range(0,len(obj)):
            if isinstance(obj[i], PDFObj.IndirectObject):
                ret.append(obj[i])
            elif isinstance(obj[i], PDFObj.DictionaryObject):
                ret += SearchIndirectObject(obj[i])
            elif isinstance(obj[i], PDFObj.ArrayObject):
                ret += SearchIndirectObject(obj[i])
    return ret

class PDFFile:
    def __init__(self):
        self.stream = Stream.Stream()
        self.obj = []
        self.ObjList = {}
        self.Trailer = {}
        self.encrypt = None
        self.encryption_key = None

    def isObj(self,idnum,generation):
        if idnum == 0:
            return False
        
        for obj in self.obj:
            if obj.fOBJ:
                if obj.getID()==idnum and obj.getGeneration()==generation:
                    return True
        return False

    def GetObj(self,idnum,generation):
        if idnum == 0:
            return PDFObj.NullObject()

        for obj in self.obj:
            if obj.fOBJ:
                if obj.getID()==idnum and obj.getGeneration()==generation:
                    return obj
        return PDFObj.NullObject()

    #高速サーチ用
    def PrepareObjList(self):
        self.ObjList = {}

        for i in range(len(self.obj)):
            self.ObjList[self.obj[i].getID()] = i

    def isObj2(self,idnum):
        return self.ObjList.has_key(idnum)

    def GetObj2(self,idnum):
        return self.obj[self.ObjList[idnum]]
        

    def PrintObjectList(self):
        output = StringIO.StringIO()
        unfinish = True
        eof = 0
        for obj in self.obj:
            if obj.fOldOBJ:
                unfinish = True
                print >> output,"%08X-%08X:obj"%(obj.start_pos,obj.end_pos-1),obj.getID(),obj.getGeneration(), "old(not used)"
            elif obj.fOBJ:
                if obj.start_pos != 0xFFFFFFFF:
                    unfinish = True
                if obj.fLinearPDF:
                    print >> output,"%08X-%08X:obj"%(obj.start_pos,obj.end_pos-1),obj.getID(),obj.getGeneration(), "Linearized parameter Dictionary"
#                elif obj.fFreeOBJ:
#                    print >> output,"%08X-%08X:obj"%(obj.start_pos,obj.end_pos-1),obj.getID(),obj.getGeneration(), "Free Object"
                elif obj.fHintStream:
                    print >> output,"%08X-%08X:obj"%(obj.start_pos,obj.end_pos-1),obj.getID(),obj.getGeneration(), "Hint Stream"
                elif obj.fXMLmetadata:
                    print >> output,"%08X-%08X:obj"%(obj.start_pos,obj.end_pos-1),obj.getID(),obj.getGeneration(), "XML metadata"
                elif obj.fTrailer:
                    print >> output,"%08X-%08X:obj"%(obj.start_pos,obj.end_pos-1),obj.getID(),obj.getGeneration(), "trailer"
                elif obj.fXrefStm:
                    print >> output,"%08X-%08X:obj"%(obj.start_pos,obj.end_pos-1),obj.getID(),obj.getGeneration(), "XrefStm"
                elif obj.fObjStm:
                    print >> output,"%08X-%08X:obj"%(obj.start_pos,obj.end_pos-1),obj.getID(),obj.getGeneration(), "ObjStm",obj.ObjStm
                else:
                    if obj.xref == None and obj.end_pos-obj.start_pos > 512:
                        #Suspicious
                        print >> output,"%08X-%08X:obj"%(obj.start_pos,obj.end_pos-1),obj.getID(),obj.getGeneration(), "xref from",obj.xref,"Suspicious"
                    else:
                        print >> output,"%08X-%08X:obj"%(obj.start_pos,obj.end_pos-1),obj.getID(),obj.getGeneration(), "xref from",obj.xref
            elif obj.fTrailer:
                unfinish = True
                print >> output,"%08X-%08X:trailer"%(obj.start_pos,obj.end_pos-1)
            elif obj.fXref:
                unfinish = True
                print >> output,"%08X-%08X:xref"%(obj.start_pos,obj.end_pos-1)
            elif obj.fStartXref:
                unfinish = True
                print >> output,"%08X-%08X:startxref %08X"%(obj.start_pos,obj.end_pos-1,obj)
            elif obj.fComment:
                if obj.fEOF:
                    print >> output,"%08X-%08X:EOF,"%(obj.start_pos,obj.end_pos-1)#,obj
                    eof += 1
                    unfinish = False
                else:
                    print >> output,"%08X-%08X:comment,"%(obj.start_pos,obj.end_pos-1)#,obj
            elif obj.fEtc:
                if obj.end_pos-obj.start_pos+1 > 512:
                    print >> output,"%08X-%08X:unknown(malicious)"%(obj.start_pos,obj.end_pos-1)
                else:
                    print >> output,"%08X-%08X:unknown(suspicious)"%(obj.start_pos,obj.end_pos-1)
            else:
                if obj.end_pos-obj.start_pos+1 > 512:
                    print >> output,"%08X-%08X:unknown(malicious)"%(obj.start_pos,obj.end_pos-1)
                else:
                    print >> output,"%08X-%08X:unknown(suspicious)"%(obj.start_pos,obj.end_pos-1)

        if unfinish:
            print >> output,"unfinished PDF file"
        ret = output.getvalue()
        print ret

        return ret
            
    def ReadFile(self,filename,password=''):
        t = []
        t_ = []
        t.append(time.time())
        t_.append('Read File')
        
        self.__init__()
        self.stream.ReadFile(filename)

        t.append(time.time())
        t_.append('Read Object')
        
        trailer = {}
        t_encrypt = None
        not_use_obj = {}


        p1 = re.compile("([-+]?\d+)[\s\0]+([-+]?\d+)[\s\0]+obj",re.I)
        p1_ = re.compile("obj",re.I)
        p2 = re.compile("trailer",re.I)
        p3 = re.compile("%",re.I)
        p4 = re.compile("xref",re.I)
        p5 = re.compile("startxref",re.I)
        p1_1 = re.compile("endobj",re.I)
        p1_2 = re.compile("stream",re.I)
        p1_3 = re.compile("endstream",re.I)
        while not self.stream.isEOF():
            start_pos = self.stream.get_pos()
            self.stream.skip_blank()
            pos = self.stream.get_pos()
            #print "%08X"%pos
            line =  self.stream.read_line_u()
            #search object
            m1 = p1.match(line)
            m1_ = p1_.match(line)
            m2 = p2.match(line)
            m3 = p3.match(line)
            m4 = p4.match(line)
            m5 = p5.match(line)
            if m1 or m1_:
                self.stream.set_pos(start_pos)
                if m1:
                    self.stream.read_phrase_u()
                    self.stream.read_phrase_u()
                self.stream.read_phrase_u()
                self.stream.skip_blank()
                if m1:
                    idnum = int(m1.groups()[0])
                    generation = int(m1.groups()[1])
                else:
                    idnum = 0
                    generation = 0
                tok = self.stream.get_u()
                self.stream.bak_pos()
                if tok == '%':
                    #途中にコメントある場合の暫定処理
                    pos = self.stream.get_pos()
                    line =  self.stream.read_line()
                    l = len(line)
                    for i in range(len(line)):
                        if line[i] == '\x00':
                            l = i+1
                            break
                    self.stream.set_pos(pos+l)
                    self.stream.skip_blank()
                    tok = self.stream.get_u()
                    self.stream.bak_pos()
                    
                if tok in '<[(0123456789+-/netf':
                    try:
                        obj = PDFObj.ReadObject(self.stream)
                    except:
                        #オブジェクトの読み込み時にエラーが発生した場合はNullオブジェクトとする
                        obj = PDFObj.NullObject()
                else :
                    obj = PDFObj.NullObject()
                pos = self.stream.get_pos()
                self.stream.skip_blank()
                phrase = self.stream.read_phrase_u()
                self.stream.set_pos(pos)
                if p1_1.match(phrase):  #'endobj'
                    self.stream.skip_blank()
                    self.stream.read_phrase_u()
                    self.stream.skip_blank()
                elif p1_2.match(phrase):    #'stream'
                    self.stream.skip_blank()
                    tok = self.stream.get_u()#s
                    tok = self.stream.get_u()#t
                    tok = self.stream.get_u()#r
                    tok = self.stream.get_u()#e
                    tok = self.stream.get_u()#a
                    tok = self.stream.get_u()#m
                    tok = self.stream.get_u()
                    l=0
                    if tok == '\n':
                        l += 1
                    elif tok == '\r':
                        tok = self.stream.get_u()
                        l += 1
                        if tok == '\n':
                            l += 1
                        else:
                            self.stream.bak_pos()
                    else:
                        self.stream.bak_pos()
#                    while tok in '\r\n':
#                        tok = self.stream.get_u()
#                        l += 1
#                        if l == 2:
#                            self.stream.bak_pos()
#                            break
#                        
#                    else:
#                        self.stream.bak_pos()
                    #self.stream.skip_blank()
                    txt = ''
                    l = 0
                    if isinstance(obj, PDFObj.DictionaryObject):
                        if obj.has_key('/Length'):
                            l = obj['/Length']
                    if isinstance(l, PDFObj.IndirectObject):
                        if self.isObj2(l.getID()):
                            l = self.GetObj2(l.getID())
                            if not isinstance(l, PDFObj.NumberObject):
                                l = 0
                        else:
                            l = 0
                    pos = self.stream.get_pos()
                    
                    tmp_l = l+2
                    while tmp_l > 0:
                        self.stream.set_pos(pos+tmp_l)
                        tok = self.stream.get_u()
                        if tok == 'e' or tok == 'E':
                            self.stream.bak_pos()
                            phrase = self.stream.read_phrase_u()
                            if p1_3.match(phrase):  #'endstream'
                                break
                        tmp_l -= 1
                    l = tmp_l
                    self.stream.set_pos(pos)
                        
                    for i in range(l):
                        txt += self.stream.get()
                    tok = self.stream.get_u()
                    self.stream.bak_pos()
                    while tok != 'EOF':
                        if tok == 'e' or tok == 'E':
                            pos = self.stream.get_pos()
                            phrase = self.stream.read_phrase_u()
                            self.stream.set_pos(pos)
                            if p1_3.match(phrase):  #'endstream'
                                self.stream.read_phrase_u()
                                #pos = self.stream.get_pos()
                                #phrase = self.stream.read_phrase_u()
                                #endobjで終わっているか
                                #if p1_1.match(phrase):
                                #    self.stream.skip_blank()
                                #else:
                                #    self.stream.set_pos(pos)
                                break
                        txt += self.stream.get()
                        tok = self.stream.get_u()
                        self.stream.bak_pos()
                    if l!=0 and len(txt)>l and len(txt)>2 and txt[-1] in ('\r','\n'):
                        if len(txt)>l+1 and len(txt)>3 and txt[-2] in ('\r','\n'):
                            txt = txt[:-2]
                        else:
                            txt = txt[:-1]
                    if isinstance(obj, PDFObj.DictionaryObject):
                        #暫定処置
                        obj[PDFObj.NameObject('__streamdata__')] = PDFObj.StringObject(txt)

                    self.stream.skip_blank()
                    pos = self.stream.get_pos()
                    phrase = self.stream.read_phrase_u()
                    if p1_1.match(phrase):  #'endobj'
                        self.stream.skip_blank()
                    else:
                        self.stream.set_pos(pos)
                end_pos = self.stream.get_pos()
                obj.setID(idnum)
                obj.setGeneration(generation)
                obj.start_pos = start_pos
                obj.end_pos = end_pos
                obj.fOBJ = True
                #オブジェクトのダブリを処理
                if self.isObj2(idnum):
                    oldobj = self.GetObj2(idnum)
                    oldobj.fOBJ = False
                    oldobj.fOldOBJ = True
                self.obj.append(obj)
                self.ObjList[idnum]=len(self.obj)-1
            elif m2:
                #search trailer
                
                self.stream.set_pos(start_pos)
                self.stream.read_phrase_u()
                self.stream.skip_blank()
                try:
                    trailer = PDFObj.ReadObject(self.stream)#dict(trailer,**PDFObj.ReadObject(self.stream))
                except:
                    #オブジェクトの読み込み時にエラーが発生した場合は空の辞書オブジェクトとする
                    obj = PDFObj.DictionaryObject()
                    
                self.Trailer.update(trailer)
                #analysis trailer
                if trailer.has_key('/Size'):
                    t_size = trailer['/Size']
                else:
                    t_size = 0
                if trailer.has_key('/Root'):
                    t_root = trailer['/Root']
                if trailer.has_key('/Info'):
                    t_info = trailer['/Info']
                if trailer.has_key('/ID'):
                    t_id = trailer['/ID']
                if trailer.has_key('/Prev'):
                    t_prev = trailer['/Prev']
                else:
                    t_prev = ()
                if trailer.has_key('/Encrypt'):
                    t_encrypt = trailer['/Encrypt']
                self.stream.skip_blank()
                end_pos = self.stream.get_pos()
                trailer.start_pos = start_pos
                trailer.end_pos = end_pos
                trailer.fTrailer = True
                self.obj.append(trailer)
            elif m3:
                #comment
                p = re.compile('%%EOF')
                m = p.match(line)
                if m:
                    #'%%EOF'の時は以降のコメントは無視
                    self.stream.set_pos(start_pos+5)
                    self.stream.skip_blank()
                    line = '%%EOF'
                    fEOF = True
                else:
                    fEOF = False
                #コメント中にnullがあればそこで終了
                l = len(line)
                for i in range(len(line)):
                    if line[i] == '\x00':
                        l = i+1
                        break
                self.stream.set_pos(start_pos+l)
                end_pos = self.stream.get_pos()
                if line[-1] in ('\r','\n'):
                    if line[-2] in ('\r','\n'):
                        line = line[:-2]
                    else:
                        line = line[:-1]
                obj = PDFObj.StringObject(line)
                obj.start_pos = start_pos
                obj.end_pos = end_pos
                obj.fComment = True
                obj.fEOF = fEOF
                self.obj.append(obj)
            elif m4:
                #xref
                self.stream.set_pos(start_pos)
                self.stream.read_phrase_u()
                self.stream.skip_blank()
                lines = ''
                while True:
                    pos = self.stream.get_pos()
                    line = self.stream.read_line_u()
                    self.stream.set_pos(pos)
                    p = re.compile('(\d+)\s+(\d+)[\r\n\s]')
                    m = p.match(line)
                    if m:
                        lines += line
                        start_num = int(m.groups()[0])
                        obj_start = int(self.stream.read_phrase_u())
                        obj_num = int(self.stream.read_phrase_u())
                        p = re.compile('(\d+)\s+(\d+)\s+([fn])',re.I)
                        while True:
                            pos = self.stream.get_pos()
                            line = self.stream.read_line_u()
                            m = p.match(line)
                            if m:
                                if m.groups()[2] == 'f':
                                    not_use_obj[start_num] = True
                                start_num += 1
                                lines += line
                            else:
                                self.stream.set_pos(pos)
                                break
                    else:
                        break
                    
                    
                
                end_pos = self.stream.get_pos()
                obj = PDFObj.StringObject(lines)
                obj.start_pos = start_pos
                obj.end_pos = end_pos
                obj.fXref = True
                self.obj.append(obj)
            elif m5:
                #startxref
                self.stream.set_pos(start_pos)
                self.stream.read_phrase_u()
                self.stream.skip_blank()
                xref_start = int(self.stream.read_phrase_u())
                end_pos = self.stream.get_pos()
                obj = PDFObj.NumberObject(xref_start)
                obj.start_pos = start_pos
                obj.end_pos = end_pos
                obj.fStartXref = True
                self.obj.append(obj)
            else:
                #etc
                end_pos = self.stream.get_pos()
                if len(self.obj) > 0 and self.obj[-1].fEtc:
                    self.obj[-1].end_pos = end_pos
                else:
                    obj = PDFObj.NullObject()
                    obj.start_pos = start_pos
                    obj.end_pos = end_pos
                    obj.fEtc = True
                    self.obj.append(obj)
                    
                if line[-1] in ('\r','\n'):
                    if line[-2] in ('\r','\n'):
                        line = line[:-2]
                    else:
                        line = line[:-1]
                
            self.stream.skip_blank()
                

        if self.Trailer == {}:
            #トレーラーが見つからなかった場合は%%EOFの直前のオブジェクトをトレーラーとみなす
            for i in range(len(self.obj)):
                if self.obj[i].fComment:
                    if self.obj[i] == '%%EOF':
                        last_obj = ''
                        for j in range(i):
                            if self.obj[i-j].fOBJ or self.obj[i-j].fOldOBJ:
                                last_obj = self.obj[i-j]
                                break
                        trailer = last_obj
                        trailer.fTrailer = True
                        self.Trailer = trailer
                        #トレーラーを分析
                        if trailer.has_key('/Size'):
                            t_size = trailer['/Size']
                        else:
                            t_size = PDFObj.NumberObject(0)
                        if trailer.has_key('/Root'):
                            t_root = trailer['/Root']
                        if trailer.has_key('/Info'):
                            t_info = trailer['/Info']
                        if trailer.has_key('/ID'):
                            t_id = trailer['/ID']
                        if trailer.has_key('/Prev'):
                            t_prev = trailer['/Prev']
                        else:
                            t_prev = ()
                        if trailer.has_key('/Encrypt'):
                            t_encrypt = trailer['/Encrypt']
        #PDF読み込み終了

        t.append(time.time())
        t_.append('Analysis Encryption Dictionary')
        
        #暗号化辞書の分析～ここから
        if t_encrypt:
            encrypt = self.GetObj(t_encrypt.getID(),t_encrypt.getGeneration())
            if not encrypt.has_key('/EncryptMetadata'):
                #/EncryptMetadataのデフォルト値はtrue
                encrypt[PDFObj.NameObject('/EncryptMetadata')] = PDFObj.BooleanObject(True)
            if not encrypt.has_key('/Length'):
                #/Lengthのデフォルト値は40
                encrypt[PDFObj.NameObject('/Length')] = PDFObj.NumberObject(40)
            self.encrypt = encrypt
            encryption_key = PDFCrypto.get_encryption_key(self.encrypt,self.Trailer,password)
            self.encryption_key = encryption_key
        #暗号化辞書の分析～ここまで

        t.append(time.time())
        t_.append('Decryption')
        
        #暗号の復号化～ここから
        if t_encrypt:
            for obj in self.obj:
                if obj.fOBJ or obj.fOldOBJ:
                    fXref = False
                    if isinstance(obj,PDFObj.DictionaryObject):
                        if obj.has_key('/Type'):
                            if obj['/Type'] == '/XRef':
                                fXref = True
                                #トレーラー上にある相互参照ストリームのときは通常は暗号化されていない
                                #トレーラー上にない相互参照ストリームはトレイラーに'/XRefStm'が定義されていると暗号化されない
                                #それ以外は暗号化される
                                if not obj.fTrailer:
                                    if self.Trailer.has_key('/XRefStm'):
                                        if obj.start_pos != int(self.Trailer['/XRefStm']):
                                            fXref = False
                                    else:
                                        fXref = False
                                    
                    if (obj.getID() != encrypt.getID() or obj.getGeneration != encrypt.getGeneration()) and not fXref:
                        PDFCrypto.DecryptObject(encrypt,encryption_key, obj, obj.getID(), obj.getGeneration())
        #暗号の復号化～ここまで

        t.append(time.time())
        t_.append('Decode Streamdata')
        
        #ストリームデータのデコード～ここから
        for obj in self.obj:
            if obj.fOBJ or obj.fOldOBJ:
                if isinstance(obj,PDFObj.DictionaryObject):
                    if obj.has_key('__streamdata__'):
                        PDFFilter.DecodeStream(obj)
        #ストリームデータのデコード～ここまで

        t.append(time.time())
        t_.append('Expand ObjStm')

        #オブジェクトストリームの展開～ここから
        for obj in self.obj:
            if obj.fOBJ or obj.fOldOBJ:
                if isinstance(obj,PDFObj.DictionaryObject):
                    if obj.has_key('/Type'):
                        if obj['/Type'] == '/XRef':
                            #相互参照ストリーム
                            obj.fXrefStm = True
                        elif obj['/Type'] == '/Metadata':
                            if obj.has_key('/Subtype'):
                                if obj['/Subtype'] == '/XML':
                                    #XML metadata
                                    obj.fXMLmetadata = True
                        elif obj['/Type'] == '/ObjStm':
                            obj.fObjStm = True
                            stream = Stream.Stream()
                            stream.SetStream(obj['__streamdata__'])
                            ids = []
                            tok = ''
                            while tok != 'EOF':
                                stream.skip_blank()
                                tok = stream.get_u()
                                stream.bak_pos()
                                if tok in ('0','1','2','3','4','5','6','7','8','9'):
                                    #id
                                    ids.append(int(stream.read_phrase_u()))
                                    #offset
                                    stream.read_phrase_u()
                                else:
                                    break
                            obj.ObjStm = ids
                            for var in ids:
                                obj2 = PDFObj.ReadObject(stream)
                                obj2.start_pos = 0xFFFFFFFF
                                obj2.end_pos = 0x100000000
                                obj2.fOBJ = True
                                obj2.setID(var)
                                obj2.setGeneration(0)
                                self.obj.append(obj2)
                                    
        #オブジェクトストリームの展開～ここまで

        self.PrepareObjList()
        t.append(time.time())
        t_.append('etc...')

        #Linear PDFの判定～ここから
        for obj in self.obj:
            if obj.fOBJ:
                if isinstance(obj, PDFObj.DictionaryObject) and obj.has_key('/Linearized'):
                    if obj['/Linearized'] == 1:
                        #Linear PDF
                        obj.fLinearPDF = True
                        if obj.has_key('/H'):
                            #primary hint stream
                            primary_hint_stream_pos = obj['/H'][0]
                            for obj2 in self.obj:
                                if obj2.start_pos == primary_hint_stream_pos:
                                    obj2.fHintStream = True
                            if len(obj['/H'])==4:
                                #overflow hint stream
                                overflow_hint_stream_pos = obj['/H'][3]
                                for obj2 in self.obj:
                                    if obj2.start_pos == overflow_hint_stream_pos:
                                        obj2.fHintStream = True
                break
                        
        #Linear PDFの判定～ここまで

        #xrefで未使用となっているオブジェクトの処理～ここから
        for var in not_use_obj:
            if self.isObj2(var):
                obj = self.GetObj2(var)
                #obj.fOBJ = False
                obj.fFreeOBJ = True
        
        #xrefで未使用となっているオブジェクトの処理～ここまで

        t.append(time.time())
        t_.append('Analysis Object Correlation')

        #オブジェクトの相関関係分析～ここから
        for obj in self.obj:
            if obj.fOBJ or obj.fOldOBJ:
                xref = SearchIndirectObject(obj)
                for var in xref:
                    if self.isObj2(var.getID()):
                        obj2 = self.GetObj2(var.getID())
                        if not obj2.xref:
                            obj2.xref = []
                        obj2.xref.append(PDFObj.IndirectObject(obj.getID(),obj.getGeneration()))
            elif obj.fTrailer:
                xref = SearchIndirectObject(obj)
                for var in xref:
                    if self.isObj2(var.getID()):
                        obj2 = self.GetObj2(var.getID())
                        if not obj2.xref:
                            obj2.xref = []
                        obj2.xref.append(PDFObj.IndirectObject(-1,-1))
        #オブジェクトの相関関係分析～ここまで

        t.append(time.time())

        if __DEBUG__:
            for i in range(len(t)-1):
                print t_[i],t[i+1]-t[i],'sec'
    def OutputObject(self,no):
        if no == 0:
            print self.obj
        elif no == -1:
            return
        else:
            for obj in self.obj:
                if obj.getID() == no:
                    print obj
    def OutputStream(self,no):
        if no == 0:
            print self.obj
        elif no == -1:
            return
        else:
            for obj in self.obj:
                if obj.getID() == no:
                    if obj.has_key('__streamdata__'):
                        print obj['__streamdata__']
