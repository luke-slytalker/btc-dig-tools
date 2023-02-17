import os, sys
import io
import struct

from struct import unpack
import json
import requests
from binascii import unhexlify, crc32

tx = sys.argv[1]    # list of transactions


def MagicScan(dataset):
    # scans data for magic number.
    s = dataset
    filesize = str(sys.getsizeof(dataset))
    response = ""                           # return response for the function

    gzip = s.find(b"\x1F\x8B\x08")              # gzip
    zipfile = s.find(b"\x50\x3b\x03\x04")       # zip archive
    rar = s.find(b"\x52\x61\x72\x21\x1a\x07")   # rar
    z7z = s.find(b"\x37\x7a\xbc\xaf\x27\x1c")   # 7zip header
    footer7z = s.find(b"\x00\x00\x00\x17\x06")  # 7zip footer
    lzip = s.find(b"\x4C\x5A\x49\x50")          # LZip archive
    pkzip = s.find(b"\x50\x4B\x03\x04")         # PKZip archive
    tar = s.find(b"\x75\x73\x74\x61\x72")       # TAR archive
    xzlz = s.find(b"\xFD\x37\x7A\x58\x5A\x00\x00")      # XZ compressed archive
    doc = s.find(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")   # MS Office file
    kgb = s.find(b"\x4B\x47\x42\x5F\x61\x72\x63\x68")   # KGB archive (don't ask...)
    lzh = s.find(b"\x2D\x6C\x68")               # LZip archive
    bzip2 = s.find(b"\x42\x5A\x68")             # bzip2 compressed archive

    png = s.find(b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", 2)    # png image
    jpg = s.find(b"\xff\xd8\xff\xe0", 2)                    # jpeg image
    gif = s.find(b"\x47\x49\x46\x38\x39\x61", 2)            # gif image

    sqlite = s.find(b"\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33\x00")  # SQLite database
    sqld = s.find(b"\x01\x0F\x00\x00")      # SQL Database
    telgd = s.find(b"\x54\x44\x46\x24")     # telegram desktop file
    telenc = s.find(b"\x54\x44\x45\x46")    # telegram encrypted file

    pdf = s.find(b"\x25\x50\x44\x46\x2d")   # pdf document
    utf8 = s.find(b"\xEF\xBB\xBF")          # UTF-8 encoded data
    txt = s.find(b"\x00\x00", 0, 5)  # ascii text

    pgpd = s.find(b"\x50\x47\x50\x64\x4D\x41\x49\x4E")  # PGP Disk image
    pgpk1 = s.find(b"\x95\x00")  # PGP Secret keyring 1
    pgpk2 = s.find(b"\x95\x01")  # PGP Secret keyring 2
    gpgkr = s.find(b"\x4b\x42\x58\x66")  # GPG Public Keyring (.KBX)
    gkrfoot = s.find(b"\x67\x70\x67\x00")  # GPG Keyring footer (.KBX)
    gpgcast = s.find(b"\x8c\x0d\x04\x03\x03\x02")  # GPG encrypted data CAST5 cipher header
    gpgcastx = s.find(b"\x60\xc9")  # also present at the last bit of the first byte
    gpgrsa = s.find(
        b"\x70\x72\x6f\x74\x65\x63\x74\x65\x64\x2d\x70\x72\x69\x76\x61\x74\x65\x2d\x6b\x65\x79\x28\x33\x3a\x72\x73\x61\x28")  # GPG Private Key RSA
    gpgdsa = s.find(
        b"\x70\x72\x6f\x74\x65\x63\x74\x65\x64\x2d\x70\x72\x69\x76\x61\x74\x65\x2d\x6b\x65\x79\x28\x33\x3a\x64\x73\x61\x28")  # GPG Private Key DSA
    gpgel = s.find(
        b"\x70\x72\x6f\x74\x65\x63\x74\x65\x64\x2d\x70\x72\x69\x76\x61\x74\x65\x2d\x6b\x65\x79\x28\x33\x3a\x65\x6c\x67\x28")  # GPG Private Key ELG
    pgpsub = s.find(b"\x97\xb5")  # PGP Secret Sub Key
    pkr = s.find(b"\x99\x01")  # PGP Public Keyring PKR file
    trustdb = s.find(b"\x01\x67\x70\x67")  # GPG Trust Database (.gpg file)
    tdbfoot = s.find(
        b"\x91\x9f\x10\xd7\xc2\x1d\xf0\x65\x0f\x4a\x95\xac\x94\x58")  # GPG Trust Database footer (.gpg file)

    ## ENCRYPTION

    if gpgrsa > -1:
        response += "GPG Private Key [RSA] (.key)  @ byte " + str(gpgrsa) + " of " + filesize + "<br>>"

    if gpgdsa > -1:
        response += "GPG Private Key [DSA] (.key)  @ byte " + str(gpgdsa) + " of " + filesize + "<br>"

    if gpgel > -1:
        response += "GPG Private Key [ELG] (.key)  @ byte " + str(gpgel) + " of " + filesize + "<br>"


    if gpgkr > -1 and gkrfoot > -1:
        response += "GPG Public Keyring (.kbx) @ byte " + str(gpgkr) + " to " + str(gkrfoot) + " of " + filesize + "<br>"

    if gpgkr > -1:
        response += "GPG Public Keyring Header (.kbx) @ byte " + str(gpgkr) + " of " + filesize + "<br>"

    if gkrfoot > -1:
        response += "GPG Public Keyring Footer (.kbx) @ byte " + str(gkrfoot) + " of " + filesize + "<br>"


    if trustdb > -1 and tdbfoot > -1:
        response += "GPG Trust Database (.gpg) @ byte " + str(trustdb) + " to " + str(tdbfoot) + " of " + filesize + "<br>"


    if trustdb > -1:
        response += "GPG Trust DB Header (.gpg) @ byte " + str(trustdb) + " of " + filesize + "<br>"


    if tdbfoot > -1:
        response += "GPG Trust DB Footer (.gpg) @ byte " + str(tdbfoot) + " of " + filesize + "<br>"


    if gpgcast > -1 and gpgcastx > -1:
        response += "GPG encrypted data [CAST5 cipher] @ byte " + str(gpgcast) + " of " + filesize + "<br>"

    if pgpk1 > -1:
        response += "PGP Secret Keyring 1 @ byte " + str(pgpk1) + " of " + filesize + "<br>"

    if pgpk2 > -1:
        response += "PGP Secret Keyring 2 @ byte " + str(pgpk2) + " of " + filesize + "<br>"

    if pkr > -1:
        response += "PGP Public Key Ring (PKR) @ byte " + str(pkr) + " of " + filesize + "<br>"

    if pgpsub > -1:
        response += "PGP Secret Sub Key @ byte " + str(pgpsub) + " of " + filesize + "<br>"

    if pgpd > -1:
        response += "PGP Disk Image @ byte " + str(pgpd) + " of " + filesize + "<br>"


    ## COMPRESSED ARCHIVES
    if kgb > -1:
        response += "KGB archive @ byte " + str(kgb) + " of " + filesize + "<br>"
    if bzip2 > -1:
        response += "bzip2 compressed archive @ byte " + str(bzip2) + " of " + filesize + "<br>"
    if lzh > -1:
        response += "LZH zip archive @ byte " + str(lzh) + " of " + filesize + "<br>"
    if gzip > -1:
        response += "GZip archive @ byte " + str(gzip) + " of " + filesize + "<br>"
    if xzlz > -1:
        response += "XZ compressed archive @ byte " + str(xzlz) + " of " + filesize + "<br>"
    if tar > -1:
        response += "TAR file @ byte " + str(tar) + " of " + filesize + "<br>"
    if pkzip > -1:
        response += "PKZip compressed archive @ byte " + str(pkzip) + " of " + filesize + "<br>"
    if lzip > -1:
        response += "LZIP compressed archive @ byte " + str(lzip) + " of " + filesize + "<br>"
    if z7z > -1:
        response += "7Zip compressed archive @ byte " + str(z7z) + " of " + filesize + "<br>"
    if footer7z > -1:
        response += "7Zip Footer @ byte " + str(footer7z) + " of " + filesize + "<br>"
    if zipfile > -1:
        response += "ZIP file @ byte " + str(zipfile) + " of " + filesize + "<br>"
    if rar > -1:
        response += "RAR compressed archive @ byte " + str(rar) + " of " + filesize + "<br>"

# IMAGES
    if jpg > -1:
        response += "JPG Image @ byte " + str(jpg) + " of " + filesize + "<br>"
    if png > -1:
        response += "PNG Image @ byte " + str(png) + " of " + filesize + "<br>"
    if gif > -1:
        response += "GIF Image @ byte " + str(gif) + " of " + filesize + "<br>"

# DOCUMENTS
    if doc > -1:
        response += "MS Office file " + str(doc) + " of " + filesize + "<br>"
    if pdf > -1:
        response += "PDF Document @ byte " + str(pdf) + " of " + filesize + "<br>"
    if utf8 > -1:
        response += "UTF-8 Encoded Text @ byte " + str(utf8) + " of " + filesize + "<br>"
    if txt > -1:
        response += "ASCII Text @ byte " + str(txt) + " of " + filesize + "<br>"

# TELEGRAM
    if telgd > -1:
        response += "MS Office file " + str(telgd) + " of " + filesize + "<br>"
    if telenc > -1:
        response += "PDF Document @ byte " + str(telenc) + " of " + filesize + "<br>"

# SQL
    if sqlite > -1:
        response += "UTF-8 Encoded Text @ byte " + str(sqlite) + " of " + filesize + "<br>"
    if sqld > -1:
        response += "ASCII Text @ byte " + str(sqld) + " of " + filesize + "<br>"


    return str(response)


print("Transaction list")
with open(tx, "r") as txlist:
    txs = txlist.readlines()

for trans in txs:
    print("TRANSACTION:  " + str(trans))
    try:
        dataout = b''
        data = requests.get("https://blockchain.info/rawtx/" + trans).json()

        for scrpt in data["out"]:
            dataout += unhexlify(scrpt["script"].encode('UTF8'))[3:-2]

        dat = dataout.replace(b'\n', b'               ')

        print(MagicScan(dat))
        print(dat)

    except:
        print("some error...")

    print("--------------------------------------------------------------------------------------------")


print("")
print("   ------- DONE -------")
