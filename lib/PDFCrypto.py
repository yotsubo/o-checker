#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2014-2017 Yuhei Otsubo
Released under the MIT license
http://opensource.org/licenses/mit-license.php
"""

#SHA-256用
import hashlib
import binascii
#AES用
import Crypto.Cipher.AES
#MD5用
from sys import version_info
if version_info < ( 2, 5 ):
    from md5 import md5
else:
    from hashlib import md5
#BASE64用
import base64
import PDFObj

#RC4
def RC4_encrypt(key, plaintext):
    S = [i for i in range(256)]
    j = 0
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]
    i, j = 0, 0
    retval = ""
    for x in range(len(plaintext)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        t = S[(S[i] + S[j]) % 256]
        retval += chr(ord(plaintext[x]) ^ t)
    return retval

#暗号化キーの取得
def get_encryption_key(encrypt,trailer,password):
    #trailerに/IDが登録されていない場合は""とする
    if not trailer.has_key('/ID'):
        dmy = PDFObj.ArrayObject()
        dmy.append("")
        dmy.append("")        
        trailer[PDFObj.NameObject('/ID')] = dmy
    if encrypt['/V'] == 0:
        #古いバージョン
        #未実装
        return ()
    elif encrypt['/V'] <= 4:
        #V=1:Algorithm 3.1
        #V=2:(PDF1.4)Algorithm3.1
        #V=3:(PDF1.4)未発表Algorithm
        #V=4:(PDF1.5)A;gorithm 3.1 with a key length of 128 bits
        #パスワードのパッディング
        _encryption_padding = '\x28\xbf\x4e\x5e\x4e\x75\x8a\x41\x64\x00\x4e\x56\xff\xfa\x01\x08\x2e\x2e\x00\xb6\xd0\x68\x3e\x80\x2f\x0c\xa9\xfe\x64\x53\x69\x7a'
        password = (password + _encryption_padding)[0:32]
        #ハッシュ値の計算
        import struct
        m = md5(password)
        m.update(encrypt['/O'])
        p_entry = struct.pack('<i', encrypt['/P'])
        m.update(p_entry)
        m.update(trailer['/ID'][0])
        if encrypt['/R'] >= 4 and encrypt['/EncryptMetadata']=='false':
            m.update('\xff\xff\xff\xff')
        md5_hash = m.digest()
        if encrypt['/R'] >= 3:
            for i in range(50):
                md5_hash = md5(md5_hash[:encrypt['/Length']/8]).digest()
        encryption_key = md5_hash[:encrypt['/Length']/8]

        #正しいユーザーパスワードかチェック
        if encrypt['/R'] == 2:
            if encrypt['/U'] == RC4_encrypt(encryption_key, password):
                print "R=2:暗号化キー取り出し成功"
                #要検証
            else:
                print "R=2:暗号化キー取り出し失敗"
                return ''
                
        elif encrypt['/R'] >= 3:
            m = md5()
            m.update(_encryption_padding)
            m.update(trailer['/ID'][0])
            val = RC4_encrypt(encryption_key, m.digest()[:16])
            for i in range (1,20):
                new_key = ''
                for l in range(len(encryption_key)):
                    new_key += chr(ord(encryption_key[l]) ^ i)
                val = RC4_encrypt(new_key, val)
            val += '\x00' * 16
            if val[:16] == encrypt['/U'][:16]:
                print "R>=3:暗号化キー取り出し成功"

            else:
                print "R>=3:暗号化キー取り出し失敗"#,val,encrypt['/U']
                return ''
            
            return encryption_key
            
        return encryption_key
        
    elif encrypt['/V'] == 5:
        #(PDF1.7 ExtensionLevel 3) Algorithm 3.1a with a key length of 256 bits
        #256bitAES
        print "256bitAES"
        if isinstance(password, unicode):
            password.encode('utf-8')
            #print "変換",len(password)
        
        #パスワードがユーザーパスワードと一致するかチェック
        v_salt = encrypt['/U'][32:40]
        #print "Validation Salt:", v_salt
        seed = ""
        for i in range(0,len(password)):
            seed += chr(ord(password[i]))
        for i in range(0,8):
            seed += chr(ord(v_salt[i]))
        sha256 = hashlib.sha256(seed).digest()
        #print sha256
        #print encrypt['/O'][0:32]
        #print encrypt['/U'][0:32]
        if encrypt['/O'][0:32]==sha256:
            #バグあり
            print "オーナーパスワードは:",password
            
        elif encrypt['/U'][0:32]==sha256:
            #print "ユーザーパスワードは:",password
            #暗号化キーを取得
            key_salt = encrypt['/U'][40:48]
            seed = ""
            for i in range(0,len(password)):
                seed += chr(ord(password[i]))
            for i in range(0,8):
                seed += chr(ord(key_salt[i]))
            intermediate_user_key = hashlib.sha256(seed).digest()
            iv = chr(0)+chr(0)+chr(0)+chr(0)+chr(0)+chr(0)+chr(0)+chr(0)+chr(0)+chr(0)+chr(0)+chr(0)+chr(0)+chr(0)+chr(0)+chr(0)
            obj = Crypto.Cipher.AES.new(intermediate_user_key, Crypto.Cipher.AES.MODE_CBC,iv)
            encryption_key = obj.decrypt(encrypt['/UE'][0:32])
            #print "暗号化キー:",encryption_key
            #Permを復号->正しい暗号化キーなら9-11バイト目が'a','d','b'
            obj2 = Crypto.Cipher.AES.new(encryption_key, Crypto.Cipher.AES.MODE_ECB,iv)
            perms = obj2.decrypt(encrypt['/Perms'][0:16])
            #print "Perms:",encrypt['/Perms'][0:16],perms
            if perms[9:12] == "adb":
                print "暗号化キー取り出し成功"
                return encryption_key
            else:
                print "暗号化キー取り出し失敗"
                return ''
            
        else:
            print "ユーザーパスワードが一致しませんでした"
    return ()

#復号化
def decryptString(encrypt, encryption_key, line,no = 0,gen = 0):
    if encryption_key == '':
        return
    if encrypt['/V'] == 0:
        #古いバージョン(未対応)
        #未実装
        return ()
    elif encrypt['/V'] == 1:
        #Algorithm 3.1
        #40bitRC4に決めうち
        import struct
        pack1 = struct.pack('<i', no)[:3]
        pack2 = struct.pack('<i', gen)[:2]
        
        key = md5(encryption_key+pack1+pack2).digest()[:min(16,len(encryption_key)+5)]
        
        ret = RC4_encrypt(key,line)
        return ret
    elif encrypt['/V'] == 2:
        #(PDF1.4)Algorithm3.1
        #128bitRC4に決めうち
        import struct
        pack1 = struct.pack('<i', no)[:3]
        pack2 = struct.pack('<i', gen)[:2]
        
        key = md5(encryption_key+pack1+pack2).digest()[:min(16,len(encryption_key)+5)]
        
        ret = RC4_encrypt(key,line)
        return ret
    elif encrypt['/V'] == 3:
        #(PDF1.4)未発表Algorithm
        #未実装
        return ()
    elif encrypt['/V'] == 4:
        #(PDF1.5)A;gorithm 3.1 with a key length of 128 bits
        #128bitAES or 128bitRC4に決めうち
        if encrypt['/CF']['/StdCF']['/CFM'] == '/V2':
            #128bitRC4
            import struct
            pack1 = struct.pack('<i', no)[:3]
            pack2 = struct.pack('<i', gen)[:2]
            
            key = md5(encryption_key+pack1+pack2).digest()[:min(16,len(encryption_key)+5)]
            
            ret = RC4_encrypt(key,line)
            return ret
        else:
            #128bitAES
            iv = line[0:16]
            #鍵の拡張 'sAlT'を追加
            import struct
            encryption_key += struct.pack('<i', no)[:3]
            encryption_key += struct.pack('<i', gen)[:2]
            
            encryption_key += '\x73\x41\x6C\x54'
            m = md5(encryption_key)
            
            obj = Crypto.Cipher.AES.new(m.digest(), Crypto.Cipher.AES.MODE_CBC,iv)
            #16バイト単位に変換
            m = 16 - (len(line) % 16)
            for i in range(0,m):
                line += chr(m)
            ret = obj.decrypt(line[16:])
            return ret
    elif encrypt['/V'] == 5:
        #(PDF1.7 ExtensionLevel 3) Algorithm 3.1a with a key length of 256 bits
        #256bitAES
        iv = line[0:16]
        obj = Crypto.Cipher.AES.new(encryption_key, Crypto.Cipher.AES.MODE_CBC,iv)
        #16バイト単位に変換
        m = 16 - (len(line) % 16)
        for i in range(0,m):
            line += chr(m)
        ret = obj.decrypt(line[16:])
        return ret

#暗号化されたオブジェクトの復号化
def DecryptObject(encrypt, encryption_key, obj,no=0,gen=0):
    if isinstance(obj, PDFObj.DictionaryObject):
        for key in obj:
            if key == '__streamdata__':
                if not obj.has_key('/Type'):
                    obj[key] = PDFObj.StringObject(decryptString(encrypt, encryption_key, obj[key], no, gen))
                elif obj['/Type'] == '/Metadata':
                    if encrypt['/EncryptMetadata'] == 'true':
                        obj[key] = PDFObj.StringObject(decryptString(encrypt, encryption_key, obj[key], no, gen))
                else:
                    obj[key] = PDFObj.StringObject(decryptString(encrypt, encryption_key, obj[key], no, gen))
                        
            elif isinstance(obj[key], PDFObj.StringObject):
                obj[key] = PDFObj.StringObject(decryptString(encrypt, encryption_key, obj[key], no, gen))
            elif isinstance(obj[key], PDFObj.DictionaryObject):
                obj[key] = DecryptObject(encrypt, encryption_key, obj[key], no, gen)
            elif isinstance(obj[key], PDFObj.ArrayObject):
                obj[key] = DecryptObject(encrypt, encryption_key, obj[key], no, gen)
    elif isinstance(obj, PDFObj.ArrayObject):
        for i in range(0,len(obj)):
            if isinstance(obj[i], PDFObj.StringObject):
                obj[i] = PDFObj.StringObject(decryptString(encrypt, encryption_key, obj[i], no, gen))
            elif isinstance(obj[i], PDFObj.DictionaryObject):
                obj[i] = DecryptObject(encrypt, encryption_key, obj[i], no, gen)
            elif isinstance(obj[i], PDFObj.ArrayObject):
                obj[i] = DecryptObject(encrypt, encryption_key, obj[i], no, gen)
                
    return obj
