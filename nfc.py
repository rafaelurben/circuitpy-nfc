from mfrc_driver import MFRC522

def _int2hex(x):
    return "0x{:02x}".format(x)

def _list2hex(l):
    return " ".join(list(map(_int2hex, l)))

class NFCTag():
    def __init__(self, rdr, raw_uid, tag_type):
        self.rdr = rdr
        self.raw_uid = raw_uid
        self.tag_type = tag_type

    def __str__(self):
        u = self.raw_uid
        return f'<NFC Tag: type="0x{self.tag_type:02x}" uid="0x{u[0]:02x}{u[1]:02x}{u[2]:02x}{u[3]:02x}">'

    def read_all(self, key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]):
        """
        Read all the data from the card
        """

        data = []

        for i in range(0, 63, 4):
            if self.rdr.auth(MFRC522.AUTHENT1A, i, key, self.raw_uid) == MFRC522.OK:
                for j in range(i, i+4):
                    _block = self.rdr.read(j)
                    print(f"Address {_int2hex(j)} data: {_list2hex(_block)}")
                    data += _block
            else:
                print(f"Authentication error at address {i}")
                break

        self.stop_crypto1()


class NFCReader(MFRC522):
    "Class based functions for the MFRC522"

    def scan_for_tag(self) -> NFCTag:
        """Scan for a tag and return a NFCTag object if found"""
        while True:
            (stat, tag_type) = self.request(MFRC522.REQALL)
            if stat == MFRC522.OK:
                (stat, raw_uid) = self.anticoll()
                if stat == MFRC522.OK:
                    if self.select_tag(raw_uid) == MFRC522.OK:
                        return NFCTag(self, raw_uid, tag_type)
                
