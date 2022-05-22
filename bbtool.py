#!/usr/bin/env python3
# Heavily borrowed from: https://github.com/x56/airpyrt-tools
import struct
import zlib
import sys
from Crypto.Cipher import AES
import argparse


HDR_MAGIC = b'APPLE-FIRMWARE\x00'
HDR_FMT = struct.Struct(">15sB2I4BI")


class BaseBinaryError(Exception):
    pass


class BaseBinaryHeader():
    def __init__(
            self,
            model: int,
            flags,
            version: int,
            iv,
            unknown1,
            unknown2,
            unknown3,
            unknown4) -> None:
        self.model = model
        self.flags = flags
        self.version = version
        self.IV = iv
        self.unknown1 = unknown1
        self.unknown2 = unknown2
        self.unknown3 = unknown3
        self.unknown4 = unknown4

    @staticmethod
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

    @staticmethod
    def is_valid(data: bytes):
        if len(data) < (HDR_FMT.size + 4):
            return False
        if HDR_FMT.unpack(data[:HDR_FMT.size])[0] != HDR_MAGIC:
            return False
        return True

    def to_str(self):
        return "Model: 0x%x, Version: 0x%x, Flags: 0x%x, IV: 0x%s" % (self.model, self.version, self.flags, self.IV)
        # return "iv %x a:%x b%x c:%x d:%x" % (
        #    self.IV, self.unknown1, self.unknown2, self.unknown3, self.unknown4)


class BaseBinaryContainer():
    def __init__(self, header, checksum, data: bytes) -> None:
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
            struct.unpack(">I", data[-4:])[0],
            data[HDR_FMT.size:-4])

    def to_bytes(self) -> bytes:
        return self.header.to_bytes() + self.data + struct.pack(">I", self.checksum)

    @ staticmethod
    def cksum(hdr, data) -> bool:
        return zlib.adler32(hdr + data)

    def validate(self) -> bool:
        return self.checksum == zlib.adler32(self.header.to_bytes() + self.data)


class ModelInfo():
    def __init__(self, name, key):
        self.name = name
        self.key = key

    @ staticmethod
    def derive_key(key: str) -> bytes:
        key2 = bytes.fromhex(key)
        derived_key = [0] * len(key2)
        for i in range(len(key2)):
            derived_key[i] = key2[i] ^ (i + 0x19)
        return bytes(derived_key)

    @ staticmethod
    def get_info(model: int):
        # names https://web.archive.org/web/20210612211745/http://www.sallonoroff.co.uk/blog/2015/07/apple-airport-firmware-updates/
        # keys https://github.com/x56/airpyrt-tools
        models = {
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
        info = models.get(model)
        if info is None:
            return ModelInfo("Unknown model %s" % hex(model), None)
        (name, key) = info
        return ModelInfo(name, None if key is None else ModelInfo.derive_key(key))


class Decryptor():

    def chunks(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i + n]

    @staticmethod
    def decrypt_chunk(encrypted_data, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = bytearray()
        bytes_left = len(encrypted_data)
        while bytes_left:
            if bytes_left > 0x10:
                dd = encrypted_data[-bytes_left:-(bytes_left-0x10)]
                d = cipher.decrypt(dd)
                decrypted_data += bytearray(d)
            elif bytes_left == 0x10:
                dd = encrypted_data[-bytes_left:]
                d = cipher.decrypt(dd)
                decrypted_data += bytearray(d)
            else:
                dd = encrypted_data[-bytes_left:]
                decrypted_data += dd

            if bytes_left > 0x10:
                bytes_left -= 0x10
            else:
                bytes_left = 0
        return decrypted_data

    @ staticmethod
    def decrypt_raw(key: bytes, iv: bytes, data: bytes) -> bytes:
        decrypted_data = bytearray()
        for data in Decryptor.chunks(data, 0x8000):
            r = Decryptor.decrypt_chunk(data, key, iv)
            decrypted_data += bytearray(r)
        return bytes(decrypted_data)

    @ staticmethod
    def decrypt(container: BaseBinaryContainer, key: bytes) -> bytes:
        return Decryptor.decrypt_raw(key, HDR_MAGIC+bytes([container.header.IV]), container.data)


def extract(filename: str):
    def nester(data):
        cc = BaseBinaryContainer.from_bytes(data)
        info = ModelInfo.get_info(cc.header.model)
        print("%s %s" % (info.name, cc.header.to_str()))
        if cc.is_encrypted():
            if(info.key is None):
                raise BaseBinaryError("Can't decrypt, no known key")
            else:
                fw = Decryptor.decrypt(cc, info.key)
                checksum_of = fw if cc.header.model != 102 else cc.data
                if BaseBinaryContainer.cksum(cc.header.to_bytes(), checksum_of) == cc.checksum:
                    return fw
                else:
                    raise BaseBinaryError("checksum failed")

        if not cc.validate():
            raise BaseBinaryError("checksum failed")

        if cc.is_nested():
            nester(cc.data)
        else:
            return(cc.data)
    try:
        nester(open(filename, "rb").read())
    except BaseBinaryError as e:
        print(e)
        sys.exit()


# find . -name "*.basebinary" -exec ./bbtool.py {} \;
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--extract", help="file to extract")
    parser.add_argument("--output", help="output file to write to")
    args = parser.parse_args()
    if(args.extract):
        extract(args.extract)
