from mfrc_driver import MFRC522


def _int2hex(data):
    return "{:02x}".format(data)


def _list2hex(data):
    return ":".join(list(map(_int2hex, data)))


def _list2str(data):
    return " ".join(map(lambda x: f"{repr(chr(x))[1:-1]:>4}".replace(r'\x00', '----'), data))


class NFCTag():
    DATA_BLOCKS = [1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 16, 17, 18, 20, 21, 22, 24, 25, 26, 28, 29, 30,
                   32, 33, 34, 36, 37, 38, 40, 41, 42, 44, 45, 46, 48, 49, 50, 52, 53, 54, 56, 57, 58, 60, 61, 62]

    def __init__(self, rdr: MFRC522, raw_uid, tag_type):
        self.rdr = rdr
        self.raw_uid = raw_uid
        self.tag_type = tag_type

    def __str__(self):
        u = self.raw_uid
        return f'<NFCTag: type="0x{self.tag_type:02x}" uid="0x{u[0]:02x}{u[1]:02x}{u[2]:02x}{u[3]:02x}">'

    def _authenticate_block(self, blockaddr, key=[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], verbose=False):
        if self.rdr.auth(MFRC522.AUTHENT1A, blockaddr, key, self.raw_uid) != MFRC522.OK:
            print(f"[!!] 0x{blockaddr:02x}: Authentication failed!")
            return False
        return True

    def _print_block(self, blockaddr, data, sign='<', additional='') -> None:
        print(
            f"[{sign}] 0x{_int2hex(blockaddr)}: {_list2hex(data)} {_list2str(data)}", additional)

    def _write_block(self, blockaddr, data, key=[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], verbose=False):
        if len(data) > 16:
            print(f"[>!] Must be 16 bytes!")
            return False
        elif len(data) < 16:
            data += b'\x00' * (16 - len(data))

        if not self._authenticate_block(blockaddr, key, verbose):
            return False

        if self.rdr.write(blockaddr, data) != MFRC522.OK:
            print(f"[>!] Failed to write block at 0x{blockaddr:02x}!")
            return False

        if verbose:
            self._print_block(blockaddr, data, '>>')
        return True

    def _clear_block(self, blockaddr, key=[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], verbose=False):
        return self._write_block(blockaddr, b'\x00' * 16, key, verbose)

    def _read_block(self, blockaddr, key=[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], verbose=False):
        if not self._authenticate_block(blockaddr, key, verbose):
            return None

        data = self.rdr.read(blockaddr)
        if data is None or len(data) != 16:
            print(
                f"[!<] Failed to read block at 0x{blockaddr:02x}! (data={data})")
            return None

        if verbose:
            self._print_block(blockaddr, data, '<<')
        return data

    def _override_block(self, blockaddr, data, start=0, key=[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], verbose=False):
        if len(data) + start > 16:
            print(f"[>!] Must be 16 bytes!")
            return False

        olddata = self._read_block(blockaddr, key, verbose)
        if olddata is None:
            return

        newdata = olddata[:start] + list(data) + olddata[start + len(data):]
        return self._write_block(blockaddr, newdata, key, verbose)

    def read_all(self, key=[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], verbose=False):
        data = []

        for i in range(0, 64):
            block = self._read_block(i, key, verbose)
            if not block:
                break
            data.append(block)
        return data

    def clear_all_data(self, key=[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], verbose=False):
        for i in self.DATA_BLOCKS:
            if not self._clear_block(i, key, verbose):
                return False
        return True


class NFCReader(MFRC522):
    "Class based functions for the MFRC522"

    def get_tag(self) -> NFCTag | None:
        """Get a tag if there is one, otherwise return None"""

        (stat, tag_type) = self.request(MFRC522.REQALL)
        if stat == MFRC522.OK:
            (stat, raw_uid) = self.anticoll()
            if stat == MFRC522.OK:
                if self.select_tag(raw_uid) == MFRC522.OK:
                    return NFCTag(self, raw_uid, tag_type)
        return None

    def scan_for_tag(self) -> NFCTag:
        """Scan for a tag and return a NFCTag object if found"""
        while True:
            tag = self.get_tag()
            if tag is not None:
                return tag
