import nfc
import board
import digitalio

rdr = nfc.NFCReader(board.SCK, board.MOSI, board.MISO, board.D2, board.D7)
rdr.set_antenna_gain(0x07 << 4)
led = digitalio.DigitalInOut(board.LED)
led.direction = digitalio.Direction.OUTPUT

print("Started NFC reader")

try:
    while True:
        led.value = True

        tag = rdr.scan_for_tag()
        print(tag)
        tag.read_all()

except KeyboardInterrupt:
    print("Bye")
