"""Utils for tags using the ndef formatting"""

from nfc_tools import NFCTag, Key
from nfc_utils import bytes2str


class NDEFRecordHeader():
    """NDEF Record Header"""

    TNF_TYPES = {
        0x00: "Empty",
        0x01: "NFC Forum well-known type",
        0x02: "Media-type",
        0x03: "Absolute URI",
        0x04: "External type",
        0x05: "Unknown",
        0x06: "Unchanged",
        0x07: "Reserved"
    }

    def __repr__(self) -> str:
        return str(self.__dict__)

    def __init__(self, mb: bool = False, me: bool = False, cf: bool = False, sr: bool = False, il: bool = False, tnf: int = 0) -> None:
        self.mb = mb    # Message Begin
        self.me = me    # Message End
        self.cf = cf    # Chunk Flag
        self.sr = sr    # Short Record
        self.il = il    # ID Length
        self.tnf = tnf  # Type Name Format (TNF)

    @classmethod
    def from_int(cls, dat: int) -> 'NDEFRecordHeader':
        """Create a NDEFRecordHeader from a 8bit int"""

        return cls(
            mb=True if dat & (0x1 << 7) else False,
            me=True if dat & (0x1 << 6) else False,
            cf=True if dat & (0x1 << 5) else False,
            sr=True if dat & (0x1 << 4) else False,
            il=True if dat & (0x1 << 3) else False,
            tnf=dat & 0x7
        )

    def to_int(self) -> int:
        """Convert the header to an int"""

        dat = 0
        if self.mb:
            dat |= 0x1 << 7
        if self.me:
            dat |= 0x1 << 6
        if self.cf:
            dat |= 0x1 << 5
        if self.sr:
            dat |= 0x1 << 4
        if self.il:
            dat |= 0x1 << 3
        dat |= self.tnf
        return dat


class NDEFRecord():
    """A NDEF record"""

    WELL_KNOWN_TYPES = {
        0x54: "Text",
        0x55: "URI",
    }

    WELL_KNOWN_URI_TYPES = {
        0x00: "",
        0x01: "http://www.",
        0x02: "https://www.",
        0x03: "http://",
        0x04: "https://",
        0x05: "tel:",
        0x06: "mailto:",
        0x07: "ftp://anonymous:anonymous@",
        0x08: "ftp://ftp.",
        0x09: "ftps://",
        0x0A: "sftp://",
        0x0B: "smb://",
        0x0C: "nfs://",
        0x0D: "ftp://",
        0x0E: "dav://",
        0x0F: "news:",
        0x10: "telnet://",
        0x11: "imap:",
        0x12: "rtsp://",
        0x13: "urn:",
        0x14: "pop:",
        0x15: "sip:",
        0x16: "sips:",
        0x17: "tftp:",
        0x18: "btspp://",
        0x19: "btl2cap://",
        0x1A: "btgoep://",
        0x1B: "tcpobex://",
        0x1C: "irdaobex://",
        0x1D: "file://",
        0x1E: "urn:epc:id:",
        0x1F: "urn:epc:tag:",
        0x20: "urn:epc:pat:",
        0x21: "urn:epc:raw:",
        0x22: "urn:epc:",
        0x23: "urn:nfc:",
    }

    def __repr__(self) -> str:
        return str({"tnf": self.readable_tnf, "type": self.readable_type, "id": self.record_id, "payload": self.payload})

    @property
    def readable_tnf(self) -> str:
        """Get the human readable tnf"""
        return NDEFRecordHeader.TNF_TYPES.get(self.flags.tnf, self.flags.tnf)

    @property
    def readable_type(self) -> str:
        """Get the human readable type of the record"""
        if self.flags.tnf == 0x01:
            return self.WELL_KNOWN_TYPES.get(self.record_type, self.record_type)
        return bytes2str(self.record_type)

    @property
    def payload(self) -> str:
        """The payload as a string"""

        tnf = self.flags.tnf

        if tnf == 0x1:  # NDEF Well-known type
            wkt = self.record_type
            if wkt == 0x55:  # URI
                identifier = self.raw_payload[0]
                prefix = self.WELL_KNOWN_URI_TYPES[identifier]
                url = self.raw_payload[1:]
                return prefix + url.decode("utf-8")
        return self.raw_payload

    @classmethod
    def from_bytes(cls, datastream) -> "NDEFRecord":
        self = cls()
        self.flags = NDEFRecordHeader.from_int(datastream.pop(0))
        self.len_type = datastream.pop(0)

        if self.flags.sr:
            self.len_payload = datastream.pop(0)
        else:
            self.len_payload = (
                (datastream.pop(0) << 24) + \
                (datastream.pop(0) << 16) + \
                (datastream.pop(0) << 8) + \
                (datastream.pop(0))
            )

        if self.flags.il:
            self.len_id = datastream.pop(0)

        self.record_type = 0
        for _ in range(self.len_type):
            self.record_type = (self.record_type << 8) + datastream.pop(0)

        if self.flags.il:
            self.record_id = 0
            for _ in range(self.len_id):
                self.record_id = (self.record_id << 8) + datastream.pop(0)
        else:
            self.record_id = None

        self.raw_payload = []
        for _ in range(self.len_payload):
            self.raw_payload.append(datastream.pop(0))
        self.raw_payload = bytes(self.raw_payload)

        return self

    def get_raw_bytes(self) -> bytes:
        """Get the raw bytes of the record"""

        return self.raw_bytes


class NDEFMessage():
    def __init__(self) -> None:
        self.records = []

    def __repr__(self) -> str:
        return str(self.__dict__)

    @classmethod
    def parse_from_bytes(cls, data: bytes, total_length: int = None) -> "NDEFRecord":
        """Parse a NDEF message from a byte array"""

        self = cls()
        self.total_length = total_length

        while True:
            # data is being passed by reference
            rec = NDEFRecord.from_bytes(data)
            self.records.append(rec)

            if rec.flags.me:
                break

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
            self._buffer.extend(self.tag._read_block(
                self.tag.MAIN_DATA_BLOCKS[self._buf_next_block_index], key=key))
            self._buf_next_block_index += 1
        return self._buffer.pop(0)

    def _read_next_n(self, n):
        return [self._read_next() for _ in range(n)]

    def read_messages(self) -> list[NDEFMessage]:
        messages = []

        while len(self._buffer) > 0 or self._buf_next_block_index < len(self.tag.MAIN_DATA_BLOCKS):
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
                messages.append(NDEFMessage.parse_from_bytes(
                    data, total_length=tlv_len))
            elif tlv_type == 0xDF:
                messages.append(("Proprietary message", data))

        return messages

    def write(self, data, key=KEYA1):
        self.tag.data_write(data, blocks=self.tag.MAIN_DATA_BLOCKS, key=key)
