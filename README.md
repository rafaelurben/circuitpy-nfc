# CircuitPython NFC

Using a **RC522 RFID Module** with **CircuitPython** on a **Seeed XIAO RP2040**.

With code from <https://github.com/domdfcoding/circuitpython-mfrc522>.

## To do

- Implement NDEF messages

## NFC Default Access Keys

| Description      | Key A             | Key B             |
| ---------------- | ----------------- | ----------------- |
| Default          | FF FF FF FF FF FF | FF FF FF FF FF FF |
| NDEF sector 1    | A0 A1 A2 A3 A4 A5 | FF FF FF FF FF FF |
| NDEF sector 2-15 | D3 F7 D3 F7 D3 F7 | FF FF FF FF FF FF |
