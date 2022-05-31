#!/bin/sh
curl -L http://download.info.apple.com/Mac_OS_X/061-1574.20041122.ax60f/Express_6.0.basebinary -o 6.0.basebinary
curl -L http://apsu.apple.com/data/102/061-3062.20070321.omIpl/6.3.basebinary -o 6.3.basebinary

../bbtool.py --extract 6.0.basebinary --output 6.0.raw
binwalk --extract 6.0.raw
cp _6.0.raw.extracted/8681 6.0.vxworks

../bbtool.py --extract 6.3.basebinary --output 6.3.raw
binwalk --extract 6.3.raw
cp _6.3.raw.extracted/54C1 6.3.vxworks

rm -rf _6.*