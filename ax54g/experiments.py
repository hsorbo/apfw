#!/usr/bin/env python3
from ast import dump
import os
import sys
import r2pipe


def qmu(binary):
    # -nographic makes ctrl+c/z not work
    # -curses fills screen
    # -daemonize
    qemu = """
        qemu-system-mipsel\
        -device loader,file=%s,addr=0x80010000,cpu-num=0\
        -device loader,file=6.3.basebinary,addr=0x80600000,cpu-num=0\
        -device loader,addr=0x80010038,cpu-num=0\
        -s -S -nographic
    """ % binary
    print("attach with: r2 -a mips -D gdb gdb://127.0.0.1:1234")
    print("the run: . 6.0.experiments.py")
    os.system(qemu.replace("\n", " "))


def setup_traps(r: r2pipe):
    r.cmd("db 0x80000180")  # TRAP


def patch_logMsg_v60(r: r2pipe):
    r.cmd("wa jr ra @0x802739d8")  # just return
    r.cmd("wa nop @0x802739dc")  # skru ju delay slot
    r.cmd("db 0x802739d8 ")
    r.cmd("dbte 0x802739d8 ")
    r.cmd("\"dbc 0x802739d8 echo logMsg; pf z @ a0\"")


def patch_logMsg_v63(r: r2pipe):
    r.cmd("wa jr ra @0x8025683c")  # just return
    r.cmd("wa nop @08025683c")  # skru ju delay slot
    r.cmd("db 0x8025683c")
    r.cmd("dbte 0x8025683c")
    r.cmd("\"dbc 0x8025683c echo logMsg; pf z @ a0\"")


def setup_update_v60(r: r2pipe):
    r.cmd("dr a0=0x80600000")  # memory mapped airport-dumpfile
    r.cmd("dr a1=1572936")  # sizeof memory mapped airport-dumpfile
    r.cmd("dr pc=0x80011460")  # offset update


def setup_update_v63(r: r2pipe):
    r.cmd("dr a0=0x80600000")  # memory mapped airport-dumpfile
    r.cmd("dr a1=1572936")  # sizeof memory mapped airport-dumpfile
    r.cmd("dr pc=0x800110e0")  # offset update


def dump_firmware_v60(r: r2pipe):
    setup_update_v60(r)
    r.cmd("dcu 0x80011748")
    r.cmd("wtf fw.after 1572936 @0x80600000")
    print("now you can run binwalk on output, there is a zlib secion with firmware")
    r.cmd("qyy")


def dump_firmware_v63(r: r2pipe):
    setup_update_v63(r)
    r.cmd("dcu 0x80011360")
    r.cmd("wtf firmware.dump 1572936 @0x80600000")
    print("now you can run binwalk on output, there is a zlib secion with firmware")


def test_firmware_v60(r: r2pipe):
    setup_update_v60(r)
    r.cmd("dcu 0x8001171c")  # before key scramble


def current_stuff_v60(r: r2pipe):
    # break før/etter hs_fw_header_03 er kjørt
    r.cmd("db 0x80011744")
    r.cmd("db 0x80011748")
    # break før adler
    r.cmd("db 0x80011920")
    # break foer det feiler
    r.cmd("db 0x80011a64")


def run_v60(r: r2pipe):
    r.cmd("e dbg.bpinmaps=false")
    setup_traps(r)
    patch_logMsg_v60(r)
    r.cmd("dc")  # run until init fails sets SP and other stuff
    test_firmware_v60(r)


def run_v63(r: r2pipe):
    r.cmd("e dbg.bpinmaps=false")
    setup_traps(r)
    patch_logMsg_v63(r)
    r.cmd("dc")  # run until init fails sets SP and other stuff
    dump_firmware_v63(r)


if __name__ == "__main__":
    if(len(sys.argv) > 1 and sys.argv[1] == "qemu"):
        qmu("6.0.vxworks")
        # qmu("6.3.vxworks")
    else:
        run_v60(r2pipe.open())
        # run_v63(r2pipe.open())
