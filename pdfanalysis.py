#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2014-2017 Yuhei Otsubo
Released under the MIT license
http://opensource.org/licenses/mit-license.php
"""

import sys
#コマンドラインオプション解析用
import argparse
#正規表現を使用
import re
import time
import lib.PDFFile
import lib.PDFObj

#コマンドラインオプション
parser = argparse.ArgumentParser(description='PDF File Analysis Tool')
parser.add_argument('FileName', metavar='FileName', type=str,
                   help='PDF FileName')
parser.add_argument('-cc','--cryptcheck', action="store_true", default=False,dest='ccheck',
                    help='only judge whether it is encrypt or not')
parser.add_argument('-d','--debug', action="store_true", default=False,dest='debug',help='DebugMode')
parser.add_argument('-j','--judge', action="store_true", default=False,dest='judge',
                    help='only judge whether it is malicious or not')
parser.add_argument('-m', dest='mode', metavar='Mode', type=int, default=0,
                   help='Analysis Mode 0:Normal Mode,1:Force Mode1,2:Force Mode2(default: 0)')
parser.add_argument('-o', dest='object', metavar='ObjectNo.', type=int, default=0,
                   help='output Object No.(-1:Suspicious only 0:all) (default: 0)')
parser.add_argument('-s', dest='stream', metavar='ObjectNo.', type=int, default=0,
                   help='output Stream\'s Object No.(-1:Suspicious only 0:all) (default: 0)')
parser.add_argument('-O', dest='outputfile', metavar='FileName', type=str, default="a.out",
                   help='Output File Name (default: "a.out")')
parser.add_argument('-p', dest='password', metavar='Password', type=str, default="",
                   help='Password for encrypted PDF (default: null)')

args = parser.parse_args()

t1 = time.time()

#pdfファイルを読み込み
filename = args.FileName
pdffile = lib.PDFFile.PDFFile()
pdffile.ReadFile(filename,args.password)

if args.object:
    pdffile.OutputObject(args.object)
elif args.stream:
    pdffile.OutputStream(args.stream)
else:

    output = pdffile.PrintObjectList()
    judge = False

    #オブジェクトの属性を分析
    fDecrypt = True
    if pdffile.encrypt and pdffile.encryption_key == '':
        #暗号化PDFの暗号化キーの取り出しが失敗している場合
        fDecrypt = False
    for obj in pdffile.obj:
        if (obj.fOBJ or obj.fOldOBJ) and isinstance(obj, lib.PDFObj.DictionaryObject):
            if obj.has_key('__streamdata__'):
                #malicious JBIG2
                p = re.compile('JBIG2 Error')
                m = p.search(obj['__streamdata__'])
                if m and fDecrypt:
                    print 'obj',obj.getID(),obj.getGeneration(),'malicious JBIG2'
                    print obj['__streamdata__']
                    judge = True
                #malicious jpeg
                p = re.compile('Malicious JPEG')
                m = p.search(obj['__streamdata__'])
                if m and fDecrypt:
                    print 'obj',obj.getID(),obj.getGeneration(),'malicious jpeg'
                    print obj['__streamdata__']
                    judge = True
                #zlib decompress error
                p = re.compile('zlib decompress error')
                m = p.match(obj['__streamdata__'])
                if m and fDecrypt:
                    print 'obj',obj.getID(),obj.getGeneration(),'zlib decompress error'
                    judge = True
                #zlib decompress unused data
                p = re.compile('__UnusedData__(\d+)__')
                m = p.search(obj['__streamdata__'])
                if m:
                    if (int)(m.groups()[0]) > 48:
                        print 'obj',obj.getID(),obj.getGeneration(),'zlib decompress unused data:',m.groups()[0]
                        judge = True
                #xml form
                p = re.compile('(<\?xml)|(xmlns)')
                m = p.search(obj['__streamdata__'])
                if m:
                    print 'obj',obj.getID(),obj.getGeneration(),'xml form'
                #SWF File
                p = re.compile('[CF]WS')
                m = p.match(obj['__streamdata__'])
                if m:
                    print 'obj',obj.getID(),obj.getGeneration(),'SWF File'
            if obj.has_key('/JS'):
                print 'obj',obj.getID(),obj.getGeneration(),'Javascript'
        elif obj.fComment:
            p = re.compile('%PDF-')
            m = p.match(obj)
            if m:
                if obj.start_pos != 0:
                    print 'Suspicious PDF Header'


    if not fDecrypt:
        print "Decryption fail"
    if output.find("ObjStm") != -1 or output.find("XrefStm") != -1:
        fObjStm = True
        print "ObjStm or XrefStm"
    else:
        fObjStm = False
        
    #ジャッジモード～ここから
    sus = False
    if args.judge:
        if output.find("unfinished PDF file") != -1:
            sus = True
        else:
            if output.find("xref from None Suspicious") != -1:
                if fDecrypt or not fObjStm:
                    judge = True
            if output.find("unknown(malicious)") != -1:
                judge = True
            if output.find("unknown(suspicious)") != -1:
                sus = True
        if judge:
            print 'Malicious!'
        elif sus:
            print 'Suspicious!'
        else:
            print 'None!'

    #暗号化PDFか否かチェック
    if args.ccheck:
        if pdffile.encrypt:
            print "Encrypted PDF"
                    
    #ジャッジモード～ここまで
     
    t2 = time.time()
    print 'run time:', t2 - t1, 'sec'

sys.exit()
