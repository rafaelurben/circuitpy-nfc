"""
Tools for Mifare 1k NFC cards
"""

import math

from nfc_driver import MFRC522
from nfc_utils import int2hex, list2hex, bytes2str


class Key():
    """Key for classic Mifare authentication"""

    A = MFRC522.AUTHENT1A
    B = MFRC522.AUTHENT1B

    def __init__(self, key, mode=A):
        if not isinstance(key, list):
            key = list(key)
        if len(key) != 6 or not all([0 <= x <= 255 for x in key]):
            raise ValueError("Key must be 6 bytes long")
        if mode not in [self.A, self.B]:
            raise ValueError("Mode must be Key.A or Key.B")
        self.key = key
        self.mode = mode

    @classmethod
    def default(cls):
        return cls([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])


class NFCTag():
    """Class representing a Mifare 1k NFC tag"""

    DATA_BLOCKS = [
        0x01, 0x02,
        0x04, 0x05, 0x06,
        0x08, 0x09, 0x0A,
        0x0C, 0x0D, 0x0E,
        0x10, 0x11, 0x12,
        0x14, 0x15, 0x16,
        0x18, 0x19, 0x1A,
        0x1C, 0x1D, 0x1E,
        0x20, 0x21, 0x22,
        0x24, 0x25, 0x26,
        0x28, 0x29, 0x2A,
        0x2C, 0x2D, 0x2E,
        0x30, 0x31, 0x32,
        0x34, 0x35, 0x36,
        0x38, 0x39, 0x3A,
        0x3C, 0x3D, 0x3E,
    ]

    def __init__(self, rdr: MFRC522, raw_uid, tag_type):
        self.rdr = rdr
        self.raw_uid = raw_uid
        self.tag_type = tag_type

    def __str__(self):
        u = self.raw_uid
        return f'<NFCTag type="0x{self.tag_type:02x}" uid="0x{u[0]:02x}{u[1]:02x}{u[2]:02x}{u[3]:02x}" />'

    def _authenticate_block(self, blockaddr, key: Key = None) -> bool:
        if key is None:
            key = Key.default()
        elif not isinstance(key, Key):
            raise ValueError("Key must be an instance of Key!")

        stat = self.rdr.auth(key.mode, blockaddr, key.key, self.raw_uid)
        if stat != MFRC522.OK:
            print(f"[!!] 0x{blockaddr:02x}: Authentication failed! ({stat})")
            return False
        return True

    def _print_block(self, blockaddr, data, sign='<<', additional='') -> None:
        print(
            f"[{sign}] 0x{int2hex(blockaddr)}: {list2hex(data)} {bytes2str(data)}", additional)

    def _write_block(self, blockaddr, data, key=None, force=False) -> bool:
        if not force and blockaddr not in self.DATA_BLOCKS:
            raise ValueError(
                "Operation CANCELLED! Writing this block could make the tag unusable! Use force=true with caution!")
        elif len(data) > 16:
            raise ValueError("Must be 16 bytes!")
        elif len(data) < 16:
            data += b'\x00' * (16 - len(data))

        if not self._authenticate_block(blockaddr, key):
            return False

        stat = self.rdr.mifare_write(blockaddr, data)
        if stat != MFRC522.OK:
            print(f"[>!] 0x{blockaddr:02x}: Writing failed! ({stat})")
            return False

        self._print_block(blockaddr, data, '>>')
        return True

    def _clear_block(self, blockaddr, key=None, force=False) -> bool:
        return self._write_block(blockaddr, b'\x00' * 16, key, force)

    def _read_block(self, blockaddr, key=None) -> list | None:
        if not self._authenticate_block(blockaddr, key):
            return None

        stat, data = self.rdr.mifare_read(blockaddr)
        if stat != MFRC522.OK:
            print(f"[!<] 0x{blockaddr:02x}: Reading failed! ({stat})")
            return None

        if len(data) != 16:
            print(
                f"[!<] 0x{blockaddr:02x}: Reading failed! (invalid data length: {len(data)} ({data}))")
            return None

        self._print_block(blockaddr, data, '<<')
        return data

    def _override_block(self, blockaddr, data, pos=0, key=None, force=False) -> bool:
        if len(data) + pos > 16:
            raise ValueError("Must be 16 bytes!")

        olddata = self._read_block(blockaddr, key) or b'\x00' * 16

        newdata = olddata[:pos] + list(data) + olddata[pos + len(data):]
        return self._write_block(blockaddr, newdata, key, force)

    def read_blocks(self, addresses=range(0x00, 0x40), key=None) -> list:
        data = []

        for i in addresses:
            block = self._read_block(i, key)
            if not block:
                break
            data.append(block)
        return data

    def data_read(self, startpos=0, key=None) -> list:
        """Read all data blocks (excluding the empty keyb blocks)"""
        if startpos < 0 or startpos > len(self.DATA_BLOCKS)-1:
            raise ValueError("Invalid startpos!")
        return self.read_blocks(self.DATA_BLOCKS[startpos::], key)

    def data_clear(self, key=None) -> bool:
        """Clear all data blocks (excluding the empty keyb blocks)"""
        for i in self.DATA_BLOCKS:
            if not self._clear_block(i, key):
                return False
        return True

    def data_write(self, data, startpos=0, key=None) -> bool:
        """Write to all data blocks (only if needed, excluding the empty keyb blocks)"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif not isinstance(data, bytes):
            raise ValueError("Data must be a string or bytes!")
        elif startpos < 0 or startpos > len(self.DATA_BLOCKS)-1:
            raise ValueError("Invalid startpos!")

        blocks_required = math.ceil(len(data) / 16)
        blocks_available = len(self.DATA_BLOCKS)-startpos
        if blocks_required > blocks_available:
            raise ValueError(
                f"Data too long! {blocks_required} blocks required, but only {blocks_available} available!")

        for i in range(startpos, startpos+blocks_required):
            if not self._write_block(self.DATA_BLOCKS[i], data[i*16:(i+1)*16], key):
                return False
        return True


class NFCReader(MFRC522):
    "Class based functions for the MFRC522"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        print("[--] NFC Reader initialized!")

    def get_tag(self) -> NFCTag | None:
        """Get a tag if there is one, otherwise return None"""

        (stat, tag_type) = self.request(MFRC522.REQALL)
        if stat == MFRC522.OK:
            (stat, raw_uid) = self.anticoll()
            if stat == MFRC522.OK:
                if self.select_tag(raw_uid) == MFRC522.OK:
                    tag = NFCTag(self, raw_uid, tag_type)
                    print("[++] Found tag:", tag)
                    return tag
        return None

    def scan_for_tag(self) -> NFCTag:
        """Scan for a tag and return a NFCTag object if found"""

        print("[--] Scanning for tag...")

        while True:
            tag = self.get_tag()
            if tag is not None:
                return tag
