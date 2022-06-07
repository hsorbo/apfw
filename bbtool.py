#!/usr/bin/env python3
import struct
import zlib
import sys
from Crypto.Cipher import AES
import argparse

HDR_MAGIC = b'APPLE-FIRMWARE\x00'
HDR_FMT = struct.Struct(">15sB2I4BI")
CKSUM_FMT = struct.Struct(">I")
CKSUM_AX54G_FMT = struct.Struct(">I28x")

# names https://web.archive.org/web/20210612211745/http://www.sallonoroff.co.uk/blog/2015/07/apple-airport-firmware-updates/
# keys https://github.com/x56/airpyrt-tools / @hsorbo

KNOWN_MODELS = {
    3: ("AirPort Extreme 802.11g", None),
    102: ("AirPort Express 802.11g", "1f1ba10645645be2bab3c80f2e8eaae1"),
    104: ("AirPort Extreme 802.11n (1st Generation)", None),
    105: ("AirPort Extreme 802.11n (2nd Generation)", None),
    106: ("AirPort Time Capsule 802.11n (1st Generation)", None),
    107: ("AirPort Express 802.11n (1st Generation)", "5249c351028bf1fd2bd1849e28b23f24"),
    108: ("AirPort Extreme 802.11n (3rd Generation)", "bb7deb0970d8ee2e00fa46cb1c3c098e"),
    109: ("AirPort Time Capsule 802.11n (2nd Generation)", None),
    113: ("AirPort Time Capsule 802.11n (3rd Generation)", None),
    114: ("AirPort Extreme 802.11n (4th Generation)", None),
    115: ("AirPort Express 802.11n (2nd Generation)", "1075e806f4770cd4763bd285a64e9174"),
    116: ("AirPort Time Capsule 802.11n (4th Generation)", None),
    117: ("AirPort Extreme 802.11n (5th Generation)", None),
    119: ("AirPort Time Capsule 802.11ac", None),
    120: ("AirPort Extreme 802.11ac", "688cdd3b1b6bdda207b6cec2735292d2"),
}


def shuffle_key(key: bytes) -> bytes:
    # Apple does a shuffle of the decryption key stored in firmware
    return bytes([key[i] ^ (i + 0x19) for i in range(len(key))])


def encrypt_payload(key: bytes, iv: bytes, input: bytes, decrypt: bool) -> bytes:
    def chunkify(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i + n]
    output = bytearray()
    for chunk in chunkify(input, 0x8000):
        copy_size = len(chunk) % 0x10
        decrypt_size = len(chunk) - copy_size
        cipher = AES.new(key, AES.MODE_CBC, iv)
        f = cipher.decrypt if decrypt else cipher.encrypt
        output += f(chunk[0:decrypt_size]) + chunk[decrypt_size:]
    return bytes(output)


class BaseBinaryError(Exception):
    @staticmethod
    def checksum_failed(expected, got):
        return BaseBinaryError("checksum failed, expected %s, got %s" % (
            hex(expected), hex(got)))

    @staticmethod
    def checksum_assert(expected, got):
        if expected != got:
            raise BaseBinaryError.checksum_failed(
                expected, got)


class BaseBinaryHeader():
    def __init__(
            self,
            model: int,
            flags,
            version: int,
            iv,
            unknown1=0,
            unknown2=0,
            unknown3=0,
            unknown4=0) -> None:
        self.model = model
        self.flags = flags
        self.version = version
        self.IV = iv
        self.unknown1 = unknown1
        self.unknown2 = unknown2
        self.unknown3 = unknown3
        self.unknown4 = unknown4

    @ staticmethod
    def from_bytes(data: bytes):
        if len(data) < (HDR_FMT.size + 4):
            raise BaseBinaryError("Not enough data to parse")
        magic, iv, model, version, unknown1, unknown2, unknown3, flags, unknown4 = HDR_FMT.unpack(
            data[:HDR_FMT.size])
        if magic != HDR_MAGIC:
            raise BaseBinaryError("bad header magic")
        return BaseBinaryHeader(model, flags, version, iv, unknown1, unknown2, unknown3, unknown4)

    def to_bytes(self) -> bytes:
        return HDR_FMT.pack(
            HDR_MAGIC,
            self.IV,
            self.model,
            self.version,
            self.unknown1,
            self.unknown2,
            self.unknown3,
            self.flags,
            self.unknown4)

    def to_full_iv(self) -> bytes:
        data = HDR_MAGIC + bytes([self.IV])
        if len(data) < 0x10:
            raise BaseBinaryError("IV is too short")
        return data

    @ staticmethod
    def is_valid(data: bytes):
        if len(data) < (HDR_FMT.size + 4):
            return False
        if HDR_FMT.unpack(data[:HDR_FMT.size])[0] != HDR_MAGIC:
            return False
        return True


class BaseBinaryContainer():
    def __init__(self, header: bytes, checksum: int, data: bytes) -> None:
        self.checksum = checksum
        self.data = data
        self.header = header

    def is_encrypted(self) -> bool:
        return True if self.header.flags & 2 else False

    def is_nested(self) -> bool:
        return BaseBinaryHeader.is_valid(self.data)

    @ staticmethod
    def from_bytes(data: bytes):
        return BaseBinaryContainer(
            BaseBinaryHeader.from_bytes(data),
            CKSUM_FMT.unpack(data[-4:])[0],
            data[HDR_FMT.size:-4])

    def to_bytes(self) -> bytes:
        return self.header.to_bytes() + self.data + CKSUM_FMT.pack(self.checksum)

    def validate(self) -> bool:
        calculated = zlib.adler32(self.header.to_bytes() + self.data)
        BaseBinaryError.checksum_assert(self.checksum, calculated)

    def to_str(self):
        return "Model: 0x%x, Version: 0x%x, Flags: 0x%x, IV: 0x%s, Cksum: %s" % (
            self.header.model,
            self.header.version,
            self.header.flags,
            self.header.IV,
            hex(self.checksum))

    @ staticmethod
    def create(header: BaseBinaryHeader, payload: bytes):
        cksum = zlib.adler32(header.to_bytes() + payload)
        cont = BaseBinaryContainer(header, cksum, payload)
        cont.validate()
        return cont


class ModelInfo():
    def __init__(self, name, key, post_cksum):
        self.name = name
        self.key = key
        self.post_cksum = post_cksum

    @ staticmethod
    def get_info(model: int):
        info = KNOWN_MODELS.get(model)
        if info is None:
            raise BaseBinaryError("Unknown model %s" % hex(model), None)
        (name, key) = info
        real_key = None if key is None else shuffle_key(bytes.fromhex(key))
        return ModelInfo(name, real_key, model != 102)


def extract(data):
    cc = BaseBinaryContainer.from_bytes(data)
    info = ModelInfo.get_info(cc.header.model)
    print("%s '%s'" % (cc.to_str(), info.name))
    if cc.is_encrypted():
        if(info.key is None):
            raise BaseBinaryError("Can't decrypt, no known key")
        if not info.post_cksum:
            cc.validate()
        payload = encrypt_payload(
            info.key, cc.header.to_full_iv(), cc.data, True)

        if info.post_cksum:
            BaseBinaryError.checksum_assert(
                cc.checksum,
                zlib.adler32(cc.header.to_bytes() + payload))

        if not info.post_cksum:
            BaseBinaryError.checksum_assert(
                CKSUM_AX54G_FMT.unpack(payload[-0x20:])[0],
                zlib.adler32(payload[:-0x20]))
        return payload

    cc.validate()
    return cc.data if not cc.is_nested() else extract(cc.data)


def create(productId: int, version: int, data: bytes, encrypt: bool):
    model = ModelInfo.get_info(productId)
    if productId == 0x66 and len(data) != 0x180000:
        raise BaseBinaryError("Airport expects exact length of 0x180000")
    if encrypt:
        inner_hdr = BaseBinaryHeader(productId, 0x2, version, 0x00)
        payload = encrypt_payload(
            model.key, inner_hdr.to_full_iv(), data, False)
        inner = BaseBinaryContainer.create(inner_hdr, payload).to_bytes()
    else:
        inner = data
    outer_hdr = BaseBinaryHeader(productId, 0, version, 0x00)
    outer = BaseBinaryContainer.create(outer_hdr, inner)
    return outer.to_bytes()


def main(args):
    if args.list:
        print("Prod\tModel")
        for k, v in KNOWN_MODELS.items():
            print("%s\t%s" % ("0x{:02x}".format(k), v[0]))
        return

    if args.extract and args.create:
        print("NO!")
        return

    if args.extract:
        input = open(args.extract, "rb").read()
        output = extract(input)
        if(args.output):
            open(args.output, "wb").write(output)
    elif args.create:
        input = open(args.create, "rb").read()
        pid = int(args.product_id, 16)
        ver = int(args.product_version, 16)
        output = create(pid, ver, input, args.encrypt)
        if(args.output):
            open(args.output, "wb").write(output)
    else:
        parser.print_help()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--create", help="Create basebinary")
    parser.add_argument("-x", "--extract", help="Extract basebinary")
    parser.add_argument("-p", "--product-id",
                        required="--create" in sys.argv,
                        help="Product id when creating basebinary")
    parser.add_argument("-pv", "--product-version",
                        required="--create" in sys.argv,
                        help="Product version when creating basebinary")
    parser.add_argument(
        "-e", "--encrypt", help="Encrypt basebinary", action='store_true')
    parser.add_argument(
        "-L", "--list", help="List known product ids", action='store_true')
    parser.add_argument("-o", "--output", help="output file")
    try:
        main(parser.parse_args())
    except BaseBinaryError as e:
        print(e)
        sys.exit(1)
