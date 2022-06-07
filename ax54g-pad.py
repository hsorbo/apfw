#!/usr/bin/env python3
import argparse
import struct
import sys
import zlib
CKSUM_AX54G_FMT = struct.Struct(">I28x")

BOOTLOADER_SIZE = 0x80000-0x2000
KERNEL_SIZE = 0x180000


def copy_into(dst, src, start):
    for x in range(len(src)):
        dst[start+x] = src[x]


def main(args):
    data = open(args.input, 'rb').read()
    s = CKSUM_AX54G_FMT.size
    if args.action == 'check':
        exp = CKSUM_AX54G_FMT.unpack(data[-s:])[0]
        got = zlib.adler32(data[:-s])
        ok = "OK" if exp == got else "FAIL"
        print("Checksum: {} expected 0x{:08x} got 0x{:08x}".format(ok, exp, got))
    elif args.action == 'pad':
        if len(data) in [KERNEL_SIZE, BOOTLOADER_SIZE]:
            print("Already padded")
            return
        size = BOOTLOADER_SIZE if len(data) < BOOTLOADER_SIZE else KERNEL_SIZE
        print("Assuming size 0x{:0x}".format(size))
        out = bytearray([0]*size)
        copy_into(out, data, 0)
        cksum = zlib.adler32(bytes(out[:-s]))
        CKSUM_AX54G_FMT.pack_into(out, size-s, cksum)
        open(args.output, 'wb').write(out)

    elif args.action == 'unpad':
        if len(data) not in [KERNEL_SIZE, BOOTLOADER_SIZE]:
            print("Probably not padded")
        for x in range(len(data)-s-1, 0, -1):
            if data[x] != 0x00:
                print("{:08x}".format(x+1))
                open(args.output, 'wb').write(data[:x+1])
                break


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--input", required=True, help="input file")
    parser.add_argument(
        "-o", "--output", required="check" not in sys.argv, help="output file")
    parser.add_argument(
        "-a", "--action",
        choices=['pad', 'unpad', 'check'],
        required=True,
        help="output file")
    main(parser.parse_args())
