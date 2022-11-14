"""Utils for tags using the ndef formatting"""

from nfc_tools import NFCTag, Key
from nfc_utils import bytes2str

class NDEFRecord():
    """A NDEF record"""

    def __init__(self) -> None:
        ...

    @classmethod
    def parse_from_data(cls, data: bytes):
        """Parse a NDEF record from a byte array"""
        print(data)
        
        self = cls()
        
        dat = data.pop(0)
        self.mb = dat & (0x1 << 7) # message begin
        self.me = dat & (0x1 << 6) # message end
        self.cf = dat & (0x1 << 5) # chunk flag
        self.sr = dat & (0x1 << 4) # short record
        self.il = dat & (0x1 << 3) # id length present?
        self.tnf = dat & 0x7       # type name format

        self.type_length = data.pop(0)

        if self.sr:
            self.payload_length = data.pop(0)
        else:
            self.payload_length = (data.pop(0) << 24) + (data.pop(0) << 16) + (data.pop(0) << 8) + data.pop(0)

        if self.il:
            self.id_length = data.pop(0)
            
        self.record_type = 0
        for _ in range(self.type_length):
            self.record_type = (self.record_type << 8) + data.pop(0)
        
        if self.il:
            self.record_id = 0
            for _ in range(self.id_length):
                self.record_id = (self.record_id << 8) + data.pop(0)        
        
        print(self.payload_length, len(data), data, bytes2str(data))
        return self

class NDEFTag():
    KEYA0 = Key([0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5], Key.A)
    KEYA1 = Key([0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7], Key.A)
    KEYB = Key([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], Key.B)

    def __init__(self, tag: NFCTag):
        self.tag = tag
        self._buffer = []
        self._buf_next_block_index = 0

    def format(self, key=KEYB):
        self.tag._write_block(
            0x01, b'\x14\x01\x03\xe1\x03\xe1\x03\xe1\x03\xe1\x03\xe1\x03\xe1\x03\xe1', key=key)
        self.tag._write_block(
            0x02, b'\x03\xe1\x03\xe1\x03\xe1\x03\xe1\x03\xe1\x03\xe1\x03\xe1\x03\xe1', key=key)

    def clean(self, keyw0=KEYB, keyw1=KEYA1):
        self.tag.data_write(
            b'\x03\x00\xFE', blocks=self.tag.MAIN_DATA_BLOCKS, key=keyw1)
        self.tag.data_clear(blocks=self.tag.MAIN_DATA_BLOCKS[1::], key=keyw1)

    def _read_next(self, key=KEYA1):
        if len(self._buffer) == 0:
            self._buffer.extend(self.tag._read_block(self.tag.MAIN_DATA_BLOCKS[self._buf_next_block_index], key=key))
            self._buf_next_block_index += 1
        return self._buffer.pop(0)

    def _read_next_n(self, n):
        return [self._read_next() for _ in range(n)]

    def read_records(self) -> list[NDEFRecord]:
        records = []
        
        while True:
            tlv_type = self._read_next()
            
            if tlv_type == 0x00:
                continue
            elif tlv_type == 0xFE:
                break
            
            tlv_len = self._read_next()
            if tlv_len == 0xFF:
                tlv_len = (self._read_next() << 8) + self._read_next()

            data = self._read_next_n(tlv_len)
            
            if tlv_type == 0x03:
                records.append(NDEFRecord.parse_from_data(data))
            elif tlv_type == 0xDF:
                records.append(("Proprietary message", data))

        return records

    def write(self, data, key=KEYA1):
        self.tag.data_write(data, blocks=self.tag.MAIN_DATA_BLOCKS, key=key)
