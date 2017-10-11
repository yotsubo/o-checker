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

def chWord(line):
    ret = ord(line[0])+ord(line[1])*256
    return ret

def chDword(line):
    ret = ord(line[0])+(ord(line[1])<<8)+(ord(line[2])<<16)+(ord(line[3])<<24)
    return ret

def chInt(line):
    ret = ord(line[0])+(ord(line[1])<<8)+(ord(line[2])<<16)+(ord(line[3])<<24)
    if ret>0x80000000:
        ret -= 0x100000000
    return int(ret)

def sec_pos(SecID,sec_size):
    return 512+SecID*sec_size

def ssec_pos(SecID,sec_size):
    return SecID*sec_size

def readSAT(line,MSAT,sec_size):
    ret = []
    for SecID in MSAT:
        pos = sec_pos(SecID,sec_size)
        buf = line[pos:pos+sec_size]
        for i in range(sec_size/4):
            var = chInt(buf[i*4:i*4+4])
            ret.append(var)
    return ret

def SATtoStream(line,sat,sec_size):
    ret = []
    for ary in sat:
        txt = ""
        for var in ary:
            txt += line[sec_pos(var,sec_size):sec_pos(var,sec_size)+sec_size]
        ret.append(txt)
    return ret

def SSATtoStream(line,sat,sec_size):
    ret = []
    for ary in sat:
        txt = ""
        for var in ary:
            txt += line[ssec_pos(var,sec_size):ssec_pos(var,sec_size)+sec_size]
        ret.append(txt)
    return ret

def deUni(uniline):
    ret = ""
    for i in range(len(uniline)/2):
        ret += unichr(chWord(uniline[i*2:i*2+2]))
    try:
        return str(ret)
    except:
        return "encode error"

#コマンドラインオプション
parser = argparse.ArgumentParser(description='DocFile Perser')
parser.add_argument('FileName', metavar='FileName', type=str,
                   help='DocFile format FileName')
parser.add_argument('-d','--debug', action="store_true", default=False,dest='debug',
                   help='DebugMode')
parser.add_argument('-O', dest='outputfile', metavar='FileName', type=str, default="a.txt",
                   help='Output File Name (default: "a.txt")')

args = parser.parse_args()


#DocFile format ファイルを読み込み
filename = args.FileName
input1 = open(filename,"rb")
allLines = input1.read();
input1.close()

#output fileへの出力の準備
outLines = ""
if args.debug:
    outLines += "Debug Mode\n"

#DocFileのヘッダーチェック
if allLines[0:8] =="\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
    print "This is DocFile"
else:
    print "This file is not DocFile"
    sys.exit()

sec_size = 1<<chWord(allLines[30:32])
print "Size of a sector:", sec_size
ssec_size = 1<<chWord(allLines[32:34])
print "Size of a short-sector:", ssec_size
num_sec = chDword(allLines[44:48])
print "Total number of sectors:", num_sec
DictSecID = chInt(allLines[48:52])
print "SecID of first sector of the dictionary stream",DictSecID
mini_size = chDword(allLines[56:60])
print "Minimum size of standard stream",mini_size
print "SecID of first sector of ssat",chInt(allLines[60:64])
#ssat = readSAT(allLines,chInt(allLines[60:64]),sec_size)
#print ssat
num_ssec = chDword(allLines[64:68])
if chInt(allLines[60:64]) == 0:
    num_ssec = 0
print "Total number of short-sectors:",num_ssec

#ファイルが切れているかの簡易チェック
if len(allLines) < 512 + 512 * ( 512 / 4 ) * (num_sec -1 ):
    print "unfinished MS file"
    
#Master Sector Allocation Tableの分析
msat = []
next_sec = chInt(allLines[68:72])
for i in range(109):
    var = chInt(allLines[76+i*4:80+i*4])
    if var != -1:
        msat.append(var)
while next_sec >=0:#!= -2:
    for i in range((sec_size-4)/4):
        var = chInt(allLines[sec_pos(next_sec,sec_size)+i*4:sec_pos(next_sec,sec_size)+i*4+4])
        if var != -1:
            msat.append(var)
    print next_sec
    next_sec = chInt(allLines[sec_pos(next_sec,sec_size)+sec_size-4:sec_pos(next_sec,sec_size)+sec_size])
#print "MSAT:",msat
#Sector Allocation Tableの読み込み
sat = readSAT(allLines,msat,sec_size)
#print "SAT:",sat

#Short-Sector Allocation Tableの読み込み
ssat = []
next_sec = chInt(allLines[60:64])
while next_sec >0:#!= -2:
    for i in range(sec_size/4):
        var = chInt(allLines[sec_pos(next_sec,sec_size)+i*4:sec_pos(next_sec,sec_size)+i*4+4])
        ssat.append(var)
    next_sec = sat[next_sec]
#print "SSAT:",ssat

#Dictionary Streamの解析
DirID = 0
SSCS = ""
next_sec = DictSecID
DictSize = 0
total_c_size = 0
while next_sec >=0:#!= -2:
    DictSecPos = sec_pos(next_sec,sec_size)
    for i in range(4):
        print DirID,
        Dict = allLines[DictSecPos:DictSecPos+128]
        #print i,
        #Directry Name
        name = deUni(Dict[:chWord(Dict[64:66])])
        f_empty = False
        if Dict[66] == '\x01':
            f_empty = True
            name = 'D:' + name
        elif Dict[66] == '\x00':
            f_empty = True
            name = 'Empty'
        elif Dict[66] == '\x02':
            name = 'U:' + name
        print name,
        #Type of the entry:
        #print ord(Dict[66])
        f_id = chInt(Dict[116:120])
        print f_id,
        #print "SecID of first sector or short-sector:",f_id,
        f_size = chDword(Dict[120:124])
        if f_empty:
            f_size = 0
        print "stream size:", f_size,
        if f_size < mini_size:
            c_size = (f_size + ssec_size -1)/ssec_size*ssec_size
        else:
            c_size = (f_size + sec_size-1)/sec_size*sec_size
        if Dict[66] == '\x05':
            c_size = (f_size + sec_size-1)/sec_size*sec_size
        print "composed size:", c_size
        if f_size >= mini_size or Dict[66] == '\x05':#DirID != 0:
            #Root Entryの場合は足さない
            total_c_size += c_size

        DictSecPos += 128
        DirID += 1
    DictSize += 512
    if next_sec == sat[next_sec]:
        break
    next_sec = sat[next_sec]


#未使用セクタの表示
l = len(allLines)
if num_sec*sec_size*sec_size/4+512 < l:
    l = num_sec * sec_size*sec_size /4 + 512
    print "suspicious file size!"
num_unused_block = 0
for i in range(l/sec_size-1):
    if sat[i] == -1:
        print '%08X-%08X:unused' % ((i * sec_size+512),(i * sec_size+512+sec_size-1))
        num_unused_block += 1
if sat[l/sec_size-1-1] == -1:
    #最終セクタが未使用は怪しい
    print 'suspicious unused sector!'

#null blockの判定
l = len(allLines)/sec_size
num_null_block = 0
for i in range(l):
    f = True
    for j in range(sec_size):
        if allLines[i*sec_size+j] != '\x00':
            f = False
            break
    if f:
        num_null_block += 1
    


#判定
print "file size:",len(allLines)
if (len(allLines)-512)%sec_size != 0:
    print "file size error!"
    
print "header size:",(num_sec+num_ssec+1)*sec_size
print "total composed size:",total_c_size
print "Dictionary Stream size:", DictSize
print "unused sector",num_unused_block * sec_size
print "unknown data:",len(allLines)-(num_sec+num_ssec+1)*sec_size-total_c_size-DictSize
print "Null block size:", num_null_block*sec_size

sys.exit()
