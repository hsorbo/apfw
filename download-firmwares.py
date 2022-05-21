#!/usr/bin/env python3
import json
import os
import requests

# not included
# https://support.apple.com/kb/DL521?locale=en_GB
# - https://download.info.apple.com/Mac_OS_X/061-1581.20041220.PtBSE/AirPortExtremeFW5.5.1.basebinary.zip
# https://support.apple.com/kb/DL522?locale=en_US
# - https://download.info.apple.com/Mac_OS_X/061-1597.20041220.APTBs/AirPortExpressFW6.1.1.basebinary.zip

prefix = "basebinaries"
xmlfile = os.path.join(prefix, 'version.xml')
jsonfile = os.path.join(prefix, 'version.json')

if not os.path.exists(xmlfile):
    raw = requests.get("https://apsu.apple.com/version.xml").text
    open(xmlfile, 'w').write(raw)

if not os.path.exists(jsonfile):
    os.system("plutil -convert json %s -o %s" % (xmlfile, jsonfile))

for x in json.loads(open(jsonfile, "r").read())['firmwareUpdates']:
    dir = os.path.join(prefix, x['productID'])
    if not os.path.exists(dir):
        os.mkdir(dir)
    url = x['location']
    filename = os.path.basename(url)
    fullname = os.path.join(dir, os.path.basename(url))
    if not os.path.exists(fullname):
        os.system("curl -o %s %s" % (fullname, url))
    print(fullname)