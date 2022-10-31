import board
import digitalio
import time

from nfc_tools import NFCReader, NFCTag, Key
from ndef import NDEFTag

DEFAULTkeyA = Key([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], Key.A)
DEFAULTkeyB = Key([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], Key.B)
NDEFkeyA0 = Key([0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5], Key.A)
NDEFkeyA1 = Key([0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7], Key.A)

rdr = NFCReader(board.SCK, board.MOSI, board.MISO, board.D2, board.D7)
rdr.set_antenna_gain(0x07 << 4)
led = digitalio.DigitalInOut(board.LED)
led.direction = digitalio.Direction.OUTPUT

try:
    led.value = False
    while True:

        tag = rdr.scan_for_tag()
        led.value = True

        ntag = NDEFTag(tag)
        #ntag.clean()
        ntag.read()
        
        rdr.stop_crypto1()
        led.value = False

        print()
        time.sleep(2.5)

except KeyboardInterrupt:
    print("Bye")
