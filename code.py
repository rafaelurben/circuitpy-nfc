import nfc_tools
import board
import digitalio

rdr = nfc_tools.NFCReader(board.SCK, board.MOSI, board.MISO, board.D2, board.D7)
rdr.set_antenna_gain(0x07 << 4)
led = digitalio.DigitalInOut(board.LED)
led.direction = digitalio.Direction.OUTPUT

try:
    while True:
        led.value = False

        tag = rdr.scan_for_tag()
        led.value = True

        tag.read_blocks()

except KeyboardInterrupt:
    print("Bye")
