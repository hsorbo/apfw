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
        -device loader,file=6.3.firmware,addr=0x80010000,cpu-num=0\
        -device loader,file=6.3.basebinary,addr=0x80600000,cpu-num=0\
        -device loader,addr=0x8001001c,cpu-num=0\
        -s -S -nographic
    """
    print("attach with: r2 -a mips -D gdb gdb://127.0.0.1:1234")
    print("the run: . experiments.py")
    os.system(qemu.replace("\n", " "))


def setup_traps(r: r2pipe):
    r.cmd("db 0x80000180")  # TRAP


def patch_logMsg(r: r2pipe):
    r.cmd("wa jr ra @0x8025683c")  # just return
    r.cmd("wa nop @08025683c")  # skru ju delay slot
    r.cmd("db 0x8025683c")
    r.cmd("dbte 0x8025683c")
    r.cmd("\"dbc 0x8025683c echo logMsg; pf z @ a0\"")


def setup_update(r: r2pipe):
    r.cmd("dr a0=0x80600000")  # memory mapped airport-dumpfile
    r.cmd("dr a1=1572936")  # sizeof memory mapped airport-dumpfile
    r.cmd("dr pc=0x800110e0")  # offset update


def dump_firmware(r: r2pipe):
    setup_update(r)
    r.cmd("dcu 0x80011360")
    r.cmd("wtf firmware.dump 1572936 @0x80600000")
    print("now you can run binwalk on output, there is a zlib secion with firmware")


def run(r: r2pipe):
    r.cmd("e dbg.bpinmaps=false")
    setup_traps(r)
    patch_logMsg(r)
    r.cmd("dc")  # run until init fails sets SP and other stuff
    dump_firmware(r)


if __name__ == "__main__":
    if(len(sys.argv) > 1 and sys.argv[1] == "qemu"):
        qmu()
    else:
        run(r2pipe.open())
