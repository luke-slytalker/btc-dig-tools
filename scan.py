import binascii
import os, sys
import io
import struct

from struct import unpack
import json
import requests
from binascii import unhexlify, crc32

tx = sys.argv[1]

try:
    dataout = b''
    data = requests.get("https://blockchain.info/rawtx/" + tx).json()

    for scrpt in data["out"]:
        dataout += unhexlify(scrpt["script"].encode('UTF8'))[3:-2]

    dat = dataout.replace(b'\n', b'               ')

    print(dat)

except:
    print("some error...")

# output as a file
#with open('test.file', 'wb') as zipfile:
#    zipfile.write(dataout)


print("")
print(" ---- ALL DONE ---- ")

