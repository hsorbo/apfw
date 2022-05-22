#!/bin/sh
#curl http://apsu.apple.com/data/102/061-3062.20070321.omIpl/6.3.basebinary -s -o 6.3.basebinary
./bbtool.py --extract 6.3.basebinary --output 6.3.raw
binwalk --extract 6.3.raw
cp _6.3.raw.extracted/54C1 6.3.firmware