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
import os
import struct
import time

flag_win32 = False
try:
    os.uname()
except AttributeError:
    flag_win32 = True

#コマンドラインオプション
parser = argparse.ArgumentParser(description='MS File Analysis Tool')
parser.add_argument('FileName', metavar='FileName', type=str,
                   help='MS FileName')
parser.add_argument('-d','--debug', action="store_true", default=False,dest='debug',help='DebugMode')
parser.add_argument('-j','--judge', action="store_true", default=False,dest='judge',
                    help='only judge whether it is malicious or not')

args = parser.parse_args()
t1 = time.time()

mal = False
sus = False

#MSファイルを読み込み
filename = args.FileName
input1 = open(filename,"rb")
lines = input1.read();
input1.close()

ppath = os.path.abspath(os.path.dirname(__file__))
os.chdir(ppath)

#ヘッダをチェック
if lines[:8] == '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
    print 'Compound File'
    SSZ = 2**struct.unpack("<h",lines[30:30+2])[0]
#    print 'Size of Sector:',SSZ
    SSSZ = 2**struct.unpack("<h",lines[32:32+2])[0]
#    print 'Size of Short Sector:',SSSZ
    SATnum = struct.unpack("<i",lines[44:44+4])[0]
#    print 'number of SAT',SATnum
    SSATnum = struct.unpack("<i",lines[64:64+4])[0]
#    print 'number of SSAT',SSATnum
    MSATnum = struct.unpack("<i",lines[72:72+4])[0]
#    print 'number of MSAT',MSATnum
    print (SATnum+MSATnum+1+SSATnum)*SSZ

    if flag_win32:
        cmd = "docfileparser.py " + '"' + filename + '"' + ""
    else:   
        cmd = "python "+"docfileparser.py " + '"' + filename + '"' + ""
    result = os.popen(cmd).read()
    print result

    p = re.compile("unknown data:\s+([+-]*\d+)")
    m = p.search(result)
    if m:
        size1 = int(m.groups()[0])
        p = re.compile("unused sector\s+(\d+)")
        m = p.search(result)
        size2 = int(m.groups()[0])
        if size1-size2 > 512:
            print 'Suspicious 2'
            mal = True
    else:
        #error
        print 'Suspicious 1'
        sus = True
        #mal = True
    if result.find("suspicious unused sector!") != -1:
        if result.find("file size error") != -1:
            mal = True
        else:
            sus = True
    else:
        if result.find("file size error") != -1:
            if size1 < 0:
                mal = True
            elif size1 - size2 <= 512:
                sus = True
            else:
                mal = True
        
    if result.find("suspicious file size!") != -1:
        mal = True
    

elif lines[:4] == '{\\rt':
    print 'Rich Text File'
    pos = 0
    tok = lines[pos]
    if tok != '{':
        print 'error'
    parens = 1
    pos += 1
    eof = len(lines)
    while True:
        if pos >= eof:
            break
        tok = lines[pos]
        pos += 1
        if tok == '{':
            parens += 1
        elif tok == '}':
            parens -= 1
            if parens == 0:
                break
        elif tok == '\\':
            pos += 1
    print 'unknown data size:',eof-pos
    if eof-pos > 512:
        print 'Suspicious 3'
        mal = True
    ascii = True
    for i in range(eof):
        tok = ord(lines[i])
        if tok >= 0x7f:
            ascii = False
            print '%08X' % i
            break
    if not ascii and False:
        print 'Suspicious 4'
        mal = True
else:
    print 'Error'

#ジャッジモード～ここから
if args.judge:
    if mal:
        print 'Malicious!'
    elif sus:
        print 'Suspicious!'
    else:
        print 'None!'
                
#ジャッジモード～ここまで
    
t2 = time.time()
print 'run time:', t2 - t1, 'sec'

sys.exit()
