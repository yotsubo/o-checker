#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2015-2017 Yuhei Otsubo
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
parser = argparse.ArgumentParser(description='Document File Analysis Tool')
parser.add_argument('FileName', metavar='FileName', type=str,
                   help='Document FileName')

args = parser.parse_args()
#ファイルを読み込み
filename = args.FileName
input1 = open(filename,"rb")
lines = input1.read(8);
input1.close()
filename = os.path.abspath(filename)

ppath = os.path.abspath(os.path.dirname(__file__))
os.chdir(ppath)
#ヘッダをチェック
if lines[:8] == '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
    if flag_win32:
        cmd = "msanalysis.py " + '"' + filename + '"' + " -j"
    else:   
        cmd = "python "+"msanalysis.py " + '"' + filename + '"' + " -j"
    result = os.popen(cmd).read()
    p = re.compile("Malicious!")
    m = p.search(result)
    if m:
        print "Malicious!"
    else:
        print 'None!'
elif lines[:4] == '{\\rt':
    if flag_win32:
        cmd = "msanalysis.py " + '"' + filename + '"' + " -j"
    else:   
        cmd = "python "+"msanalysis.py " + '"' + filename + '"' + " -j"
    result = os.popen(cmd).read()
    p = re.compile("Malicious!")
    m = p.search(result)
    if m:
        print "Malicious!"
    else:
        print 'None!'
else:
    if flag_win32:
        cmd ="pdfanalysis.py " + '"' + filename + '"' + " -j"
    else:   
        cmd = "python "+"pdfanalysis.py " + '"' + filename + '"' + " -j"
    result = os.popen(cmd).read()
    p = re.compile("Malicious!")
    m = p.search(result)
    if m:
        print "Malicious!"
    else:
        print 'None!'


sys.exit()
