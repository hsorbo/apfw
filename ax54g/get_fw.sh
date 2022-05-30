#!/bin/sh
aria2c http://download.info.apple.com/Mac_OS_X/061-1574.20041122.ax60f/Express_6.0.basebinary
../bbtool.py --extract Express_6.0.basebinary --output 6.0.raw
binwalk --extract 6.0.raw
cp _6.0.raw.extracted/8681 6.0.firmware
rm -rf _6.* 6.0.raw Express_6.0.basebinary