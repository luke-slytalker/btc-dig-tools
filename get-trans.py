import requests
from binascii import unhexlify, crc32
import os, sys, json

btcaddr = sys.argv[1]

#out_file = sys.argv[2]


data = requests.get("https://blockchain.info/rawaddr/" + btcaddr)
jdat = data.json()
spentyet = ""
txhash = ""
addrs = ""
returndata = ""

txs = list()

for line in jdat['txs']:
    for x in line['out']:
        try:
            if x['spent']:
                spentyet = x['spent']
            else:
                spentyet = "False"
            if x['addr']:
                addrs = x['addr']
            if line['hash']:
                txhash = line['hash']
            print(addrs + " - " + txhash + " spent: " + str(spentyet))
            txs.append(txhash)

            #returndata += "BTC Addr:  <b>" + addrs + "</b><br>hash: <b>" + txhash + "</b><br>Spent Yet: <b>" + str(spentyet) + "</b><br><br>"
            ## returndata += "BTC Addr:  <b>" + addrs + "</b><br>hash: <b>" + txhash + "</b><br>Spent Yet: <b>" + str(spentyet) + "</b><br><br>"
        except:
            pass

#print(returndata)
dupekill = list(set(txs))

for t in dupekill:
    print(t)


#with open("txlist.txt", "w") as txi:
#    for t in dupekill:
#        print(t)
#        txi.writelines(t + "\n")
