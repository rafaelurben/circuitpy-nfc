"""Utils for tags using the ndef formatting"""

from nfc_tools import NFCTag, Key


class NDEFRecord():
    """A NDEF record"""

    def __init__(self, data):
        self.data = data
        self.tnf = data[0]
        self.type = data[1:3]
        self.id = data[3:4]
        self.payload_length = data[4]
        self.payload = data[5:5+self.payload_length]
        self.record_length = 5+self.payload_length

    def __str__(self):
        return "TNF: {0}, Type: {1}, ID: {2}, Payload Length: {3}, Payload: {4}".format(self.tnf, self.type, self.id, self.payload_length, self.payload)


class NDEFMessage():
    """A NDEF message"""

    def __init__(self) -> None:
        pass

    @classmethod
    def parse_from_data(cls, data):
        ...


class NDEFTag():
    KEYA0 = Key([0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5], Key.A)
    KEYA1 = Key([0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7], Key.A)
    KEYB = Key([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], Key.B)

    def __init__(self, tag: NFCTag):
        self.tag = tag

    def format(self, key=KEYB):
        self.tag._write_block(
            0x01, b'\x14\x01\x03\xe1\x03\xe1\x03\xe1\x03\xe1\x03\xe1\x03\xe1\x03\xe1', key=key)
        self.tag._write_block(
            0x02, b'\x03\xe1\x03\xe1\x03\xe1\x03\xe1\x03\xe1\x03\xe1\x03\xe1\x03\xe1', key=key)

    def clean(self, keyw0=KEYB, keyw1=KEYA1):
        self.tag.data_write(
            b'\x03\x00\xFE', blocks=self.tag.MAIN_DATA_BLOCKS, key=keyw1)
        self.tag.data_clear(blocks=self.tag.MAIN_DATA_BLOCKS[1::], key=keyw1)

    def read(self, key=KEYA1) -> NDEFMessage:
        data = []

        for b in self.tag.MAIN_DATA_BLOCKS:
            block = self.tag._read_block(b, key=key)
            data += block
            if 0xFE in block:
                break

        return NDEFMessage.parse_from_data(data)

    def write(self, data, key=KEYA1):
        self.tag.data_write(data, blocks=self.tag.MAIN_DATA_BLOCKS, key=key)
