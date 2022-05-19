#!/usr/bin/env python3
# Heavily borrowed from: https://github.com/x56/airpyrt-tools

from ctypes.wintypes import HDC
from glob import has_magic
import struct
import zlib
from Crypto.Cipher import AES


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


class BaseBinaryContainer():
    def __init__(
            self,
            header,
            checksum,
            data: bytes) -> None:
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

    def validate(self) -> bool:
        return self.checksum == zlib.adler32(self.header.to_bytes() + self.data)


class Decryptor():

    @ staticmethod
    def derive_key(key: str) -> bytes:
        key2 = bytes.fromhex(key)
        derived_key = [0] * len(key2)
        for i in range(len(key2)):
            derived_key[i] = key2[i] ^ (i + 0x19)
        return bytes(derived_key)

    @staticmethod
    def decrypt_chunk(encrypted_data, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = bytearray()
        bytes_left = len(encrypted_data)
        while bytes_left:
            if bytes_left > 0x10:
                decrypted_data += bytearray(cipher.decrypt(
                    encrypted_data[-bytes_left:-(bytes_left-0x10)]))
                bytes_left -= 0x10
            elif bytes_left == 0x10:
                decrypted_data += bytearray(
                    cipher.decrypt(encrypted_data[-bytes_left:]))
                bytes_left = 0
            else:
                decrypted_data += encrypted_data[-bytes_left:]
                bytes_left = 0

        return decrypted_data

    @ staticmethod
    def decrypt(container: BaseBinaryContainer) -> bytes:
        keys = {
            # 3 : "",
            # 102: "",
            # 104 : "",
            # 105 : "",
            # 106 : "",
            107: "5249c351028bf1fd2bd1849e28b23f24",
            108: "bb7deb0970d8ee2e00fa46cb1c3c098e",
            # 109 : "",
            # 113 : "",
            # 114 : "",
            115: "1075e806f4770cd4763bd285a64e9174",
            # 116 : "",
            # 117 : "",
            # 119 : "",
            120: "688cdd3b1b6bdda207b6cec2735292d2",
        }

        if not container.is_encrypted():
            return container
        key = keys.get(container.header.model)
        if key is None:
            raise BaseBinaryError("Unknown model %s" %
                                  hex(container.header.model))
        key = Decryptor.derive_key(key)
        iv = HDR_MAGIC+bytes([container.header.IV])
        print(len(iv))
        decrypted_data = bytearray()
        remaining_length = len(container.data)
        chunk_length = 0x8000
        while remaining_length:
            if remaining_length > chunk_length:
                data = container.data[-remaining_length:-
                                      (remaining_length-chunk_length)]
            else:
                data = container.data[-remaining_length:]

            r = Decryptor.decrypt_chunk(data, key, iv)
            decrypted_data += bytearray(r)

            if remaining_length > chunk_length:
                remaining_length -= chunk_length
            else:
                remaining_length = 0

            print(remaining_length)
        return bytes(decrypted_data)
