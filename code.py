import nfc_tools
import board
import digitalio
import time

rdr = nfc_tools.NFCReader(board.SCK, board.MOSI, board.MISO, board.D2, board.D7)
rdr.set_antenna_gain(0x07 << 4)
led = digitalio.DigitalInOut(board.LED)
led.direction = digitalio.Direction.OUTPUT

try:
    led.value = False
    while True:

        tag = rdr.scan_for_tag()
        led.value = True

        tag.read_blocks()
        
        rdr.stop_crypto1()
        led.value = False

        print()
        time.sleep(2.5)

except KeyboardInterrupt:
    print("Bye")
