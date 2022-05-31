#!/usr/bin/env python3
from ast import dump
import os
import sys
import r2pipe


def qmu():
    # -nographic makes ctrl+c/z not work
    # -curses fills screen
    # -daemonize
    qemu = """
        qemu-system-mipsel\
        -device loader,file=6.0.vxworks,addr=0x80010000,cpu-num=0\
        -device loader,file=6.3.basebinary,addr=0x80600000,cpu-num=0\
        -device loader,addr=0x80010038,cpu-num=0\
        -s -S -nographic
    """
    print("attach with: r2 -a mips -D gdb gdb://127.0.0.1:1234")
    print("the run: . /Users/hsorbo/Projects/airport/2022/test.py")
    os.system(qemu.replace("\n", " "))


def setup_traps(r: r2pipe):
    r.cmd("db 0x801667e0")  # db hs_meh2
    r.cmd("db 0x80184310")  # henger i kjorer2
    r.cmd("db 0x80185170")  # TRAP
    r.cmd("db 0x80184944")  # #trappeditrapp
    r.cmd("db 0x802d2a58")  # deadlocking
    r.cmd("db 0x80000180")  # TRAP_COPY


def patch_logMsg(r: r2pipe):
    r.cmd("wa jr ra @0x802739d8")  # just return
    r.cmd("wa nop @0x802739dc")  # skru ju delay slot
    r.cmd("db 0x802739d8 ")
    r.cmd("dbte 0x802739d8 ")
    r.cmd("\"dbc 0x802739d8 echo logMsg; pf z @ a0\"")


def setup_update(r: r2pipe):
    r.cmd("dr a0=0x80600000")  # memory mapped airport-dumpfile
    r.cmd("dr a1=1572936")  # sizeof memory mapped airport-dumpfile
    r.cmd("dr pc=0x80011460")  # offset update


def dump_aes_meh(r: r2pipe):
    r.cmd("dcu 0x80171e2c")
    r.cmd("wtf bomba0 256 @0x803d6528")
    r.cmd("wtf bomba1 256 @0x803d6628")
    r.cmd("wtf bomba2 256 @0x803d6728")
    r.cmd("wtf bomba3 256 @0x803d6828")
    r.cmd("wtf bomba4 40  @0x803d6928")
    r.cmd("wtf bomba5 4096 @0x803d6950")
    r.cmd("wtf bomba6 4096 @0x803d7950")
    r.cmd("wtf bomba7 4096 @0x803d8950")
    r.cmd("wtf bomba8 4096 @0x803d9950")


def dump_firmware(r: r2pipe):
    setup_update(r)
    #r.cmd("dcu 0x80011744")
    #r.cmd("wtf fw.before 1572936 @0x80600000")
    r.cmd("dcu 0x80011748")
    r.cmd("wtf fw.after 1572936 @0x80600000")
    print("now you can run binwalk on output, there is a zlib secion with firmware")
    r.cmd("qyy")


def test_firmware(r: r2pipe):
    setup_update(r)
    r.cmd("dcu 0x8001171c")  # before key scramble
    #r.cmd("dcu 0x8016e308; echo start aes_expand_keys")
    #r.cmd("dcu 0x80171e40; echo after aes_expand_keys")

    #r.cmd("wtf fw.before 1572936 @0x80600000")

    # r.cmd("dcu 0x80171e3c")  # pre bmf4
    # 0x87fffa78  0400 0000 0601 ba1a 587a 44c2 9b91 eb2b  ........XzD....+
    # 0x87fffa88  0ba8 8dc9 c55c 6731 9d26 23f3 06b7 c8d8  .....\g1.&#.....
    # 0x87fffa98  0d1f 4511 0732 e5e6 9a14 c615 9ca3 0ecd  ..E..2..........
    # 0x87fffaa8  91bc 4bdc 6681 6367 fc95 a572 6036 abbf  ..K.f.cg...r`6..
    # 0x87fffab8  f18a e063 1060 98c6 ecf5 3db4 8cc3 960b  ...c.`....=.....
    # 0x87fffac8  7d49 7668 3b58 dd39 d7ad e08d 5b6e 7686  }Ivh;X.9....[nv.
    # 0x87fffad8  2627 00ee d73b f5ce 0096 1543 5bf8 63c5  &'...;.....C[.c.
    # 0x87fffae8  7ddf 632b 09c0 0431 0956 1172 52ae 72b7  }.c+...1.V.rR.r.
    # 0x87fffaf8  2f71 119c 2a42 da24 2314 cb56 71ba b9e1  /q..*B.$#..Vq...
    # 0x87fffb08  5ecb a87d 2e80 257c 0d94 ee2a 7c2e 57cb  ^..}..%|...*|.W.
    # 0x87fffb18  22e5 ffb6 c196 6bef cc02 85c5 b02c d20e  ".....k......,..
    # 0x87fffb28  92c9 2db8                                ..-.

    # aes.py
    # 0:	 06 01 ba 1a 58 7a 44 c2 9b 91 eb 2b 0b a8 8d c9
    # 10:	 c5 5c 67 31 9d 26 23 f3 06 b7 c8 d8 0d 1f 45 11
    # 20:	 07 32 e5 e6 9a 14 c6 15 9c a3 0e cd 91 bc 4b dc
    # 30:	 66 81 63 67 fc 95 a5 72 60 36 ab bf f1 8a e0 63
    # 40:	 10 60 98 c6 ec f5 3d b4 8c c3 96 0b 7d 49 76 68
    # 50:	 3b 58 dd 39 d7 ad e0 8d 5b 6e 76 86 26 27 00 ee
    # 60:	 d7 3b f5 ce 00 96 15 43 5b f8 63 c5 7d df 63 2b
    # 70:	 09 c0 04 31 09 56 11 72 52 ae 72 b7 2f 71 11 9c
    # 80:	 2a 42 da 24 23 14 cb 56 71 ba b9 e1 5e cb a8 7d
    # 90:	 2e 80 25 7c 0d 94 ee 2a 7c 2e 57 cb 22 e5 ff b6
    # a0:	 c1 96 6b ef cc 02 85 c5 b0 2c d2 0e 92 c9 2d b8
    # r.cmd("dcu 0x8016e324")  # key_size


def current_stuff(r: r2pipe):
    # break før/etter hs_fw_header_03 er kjørt
    r.cmd("db 0x80011744")
    r.cmd("db 0x80011748")
    # break før adler
    r.cmd("db 0x80011920")
    # break foer det feiler
    r.cmd("db 0x80011a64")


def dings(r: r2pipe):
    r.cmd("e dbg.bpinmaps=false")
    setup_traps(r)
    patch_logMsg(r)
    r.cmd("dc")  # run until init fails sets SP and other stuff
    test_firmware(r)
    # dump_aes_meh(r)
    # r.cmd("dc")


if __name__ == "__main__":
    if(len(sys.argv) > 1 and sys.argv[1] == "qemu"):
        qmu()
    else:
        dings(r2pipe.open())
