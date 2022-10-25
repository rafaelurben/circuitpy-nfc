import nfc
import board
import digitalio

rdr = nfc.NFCReader(board.SCK, board.MOSI, board.MISO, board.D2, board.D7)
rdr.set_antenna_gain(0x07 << 4)
led = digitalio.DigitalInOut(board.LED)
led.direction = digitalio.Direction.OUTPUT

print("[ii] Started NFC reader!")

try:
    while True:
        print("[ii] Scanning...")
        led.value = False

        tag = rdr.scan_for_tag()
        led.value = True

        print("[ii] Found", tag)

        tag.read_all(verbose=True)

except KeyboardInterrupt:
    print("Bye")
