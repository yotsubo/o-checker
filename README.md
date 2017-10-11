o-checker
====

O-checker is a malware detection tool for document files.  
We published this tool at Black Hat USA 2016.  
The following is the abstract of the research paper at Black Hat USA 2016.
  
Documents containing executable files are often used in targeted email attacks. We examine various document formats (Rich Text Format, Compound File Binary and Portable Document Format) for files used in targeted attacks from 2009 to 2012 in Japan. Almost all the examined document files contain executable files that ignore the document file format specifications. Therefore, we focus on deviations from file format specifications and examine stealth techniques for hiding executable files. We classify eight anomalous structures and create a tool named o-checker to detect them. O-checker detects 96.1% of the malicious files used in targeted email attacks in 2013 and 2014. There are far fewer stealth techniques for hiding executable files than vulnerabilities of document processors. Additionally, document file formats are more stable than document processors themselves. Accordingly, we assert that o-checker can continue detecting malware with a high detection rate for long periods.  
  
Black Hat USA 2016: [Presentation](https://www.blackhat.com/docs/us-16/materials/us-16-Otsubo-O-checker-Detection-of-Malicious-Documents-through-Deviation-from-File-Format-Specifications.pdf), [White Paper](https://www.blackhat.com/docs/us-16/materials/us-16-Otsubo-O-checker-Detection-of-Malicious-Documents-through-Deviation-from-File-Format-Specifications-wp.pdf)

## Requirement

* An OS that can run Python 2.7.3 or later
* PyCrypto package for Python (for encrypted PDF files)

## Usage
#### Basic usage
In normal use, the path to a target file is the only parameter passed to `o-checker.py`.
The following shows an example of o-checker input and output.  
```
> python o-checker.py malware.doc  
Malicious!
```
In this case, we ran `o-checker.py` against a malicious Microsoft doc file, which results in the **Malicious!** output.
When the document file does not have any of the targeted anomalous structures, the output is **None!**.

#### Advanced usage
O-checker is not only a detection tool but also an analysis tool that can describe the detailed structure of CFB or PDF document files.
The details of usage are as follows.

##### Analyzing CFB files}
O-checker contains `msanalysis.py` for analyzing CFB files.
`msanalysis.py` scans a CFB file, and it outputs analysis logs describing the final determination of **Malicious!** or **None!**.
  
The following shows an example of output of `msanalysis.py` against a malicious doc file with the judgement option `-j`.
```
> python msanalysis.py -j malware.doc
Compound File
1536
This is DocFile
Size of a sector: 512
Size of a short-sector: 64
Total number of sectors: 1
SecID of first sector of the dictionary stream 17
Minimum size of standard stream 4096
SecID of first sector of ssat 19
Total number of short-sectors: 1
0 Root Entry 20 stream size: 8064 composed size: 8192
1 U:Data 8 stream size: 4096 composed size: 4096
2 U:WordDocument 0 stream size: 4096 composed size: 4096

18 Empty -2 stream size: 0 composed size: 0
19 U:CompObj 124 stream size: 121 composed size: 128
suspicious file size!
00008800-000089FF:unused
00008A00-00008BFF:unused

0000FE00-0000FFFF:unused
00010000-000101FF:unused
suspicious unused sector!
file size: 140218
file size error!
header size: 1536
total composed size: 28672
Dictionary Stream size: 2560
unused sector 31232
unknown data: 107450
Null block size: 15360

Suspicious 2
Malicious!
run time: 0.0584909915924 sec
```
The result of the check is shown as **Malicious!**.  
The following describes the tool output:
* This doc file contains 20 directory entries (Nos.0-19).
* There is data (at file offset 0x8800 to 0x101FF) not referred to in the FAT.
* `Suspicious unused sector` means the last sector is a free sector.
* The file size is 140,218 bytes. 140218 mod 512 = 442 (nonzero). `File size error!` means the file size is anomalous.
* 107,450 bytes of data is unaccounted for.

From the above, this doc file has deviations from file format specifications,
and an executable file may be present at file offset 0x8800. 

##### Analyzing PDF files
O-checker contains `pdfanalysis.py` for analyzing PDF files.
This tool scans a PDF file, and it outputs analysis logs describing the final determination of **Malicious!** or **None!**.
  
The following shows an example of output from `pdfanalysis.py`
against a malicious PDF file with the judgement option `-j`.
```
> python pdfanalysis.py -j malware.pdf
00000000-00000008:comment,
00000009-000006E2:obj 1 0 xref from [(8 0 R)]
000006E3-00000721:obj 2 0 xref from [(3 0 R), (8 0 R)]
00000722-0000075E:obj 3 0 xref from [(2 0 R), (4 0 R)]
0000075F-0000083F:obj 4 0 xref from [(3 0 R)]
00000840-000008D9:obj 5 0 xref from [(4 0 R), (6 0 R)]
000008DA-0000090E:obj 6 0 xref from [(5 0 R), (7 0 R)]
0000090F-0000098B:obj 7 0 xref from [(-1 -1 R)]
0000098C-000009DA:obj 8 0 xref from [(7 0 R)]
000009DB-00010E04:obj 17 0 xref from None Suspicious
00010E05-00010E09:xref
00010E0A-00010E28:trailer
00010E29-00010E38:startxref 000039AD
00010E39-00010E3D:EOF,

obj 1 0 xml form
obj 17 0 zlib decompress error
Malicious!
run time: 0.133231163025 sec
```
The result of the check is shown as **Malicious!**.
  
The following describes the tool output:
* This PDF file contains nine indirect objects (Nos.1-8 and 17).
* The indirect object references are listed (e.g., No.8 refers to No.1).
* No.17 is an unreferenced object.
* No.1 is an XML form. (Unrelated to determination)
* No.17 is a stream requiring the FlateDecode filter, but the decode process for No.17 fails.

This PDF file has deviations from file format specifications.
This suggests that object No.17 (located at offset 0x9DB) in this PDF file contains an executable file.

###### Analyzing encrypted PDF file
O-checker can handle four types of encryption methods, namely 40-bit RC4, 128-bit RC4, 128-bit AES, and 256-bit AES. 
When the specified PDF file is encrypted, o-checker usually tries to decrypt it using an empty password.
If the password is known, you can use the `-p` option to decrypt the PDF file using a specified password.

###### Exporting objects and streams
You can use the `-o` or `-s` options to export an indirect object from this PDF file for analyzing exploit code.
 * The `-o` option decodes the stream of the specified object, and outputs the object in JSON format.
 * The `-s` option decodes and outputs the stream of the specified object.

  
The following shows an example of the command and its output.
```
> python pdfanalysis.py -j malware.pdf -s 1
<?xml version="1.0" encoding="UTF-8" ?>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<config xmlns="http://www.xfa.org/schema/xci/1.0/">
<present>
<pdf>
<version>1.65</version>
<interactive>1</interactive>
<linearized>1</linearized>
</pdf>

<ImageField1 xfa:contentType="image/tif" href="">SUkqADggAACQ
kJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQ
kJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQ

FQAH/5CQkE0VAAcipwAHuxUAB////5BNFQAHMdcABy8RAAc=</ImageField1>
</topmostSubform>
</xfa:data>
</xfa:datasets>
```
In the above, we can find the exploit code in a tiff image.

## Licence
Released under the MIT license  
http://opensource.org/licenses/mit-license.php

## Author

[yotsubo](https://github.com/yotsubo)
