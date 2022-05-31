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
