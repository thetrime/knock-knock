Notes:
  Whitepaper and Apple disagree on which bits are stored in the chopped-up byte. Whitepaper says low 5 bits in the first and high 2 in the last, and Apple says high 5 bits in the first and low 2 in the last.

To run this as a non-root user, you need to grant some rights to bluepy-helper. First, find it:
```
find /usr/local/lib -name bluepy-helper
```

Then for each one:
```
sudo setcap 'cap_net_raw,cap_net_admin+eip' <path to bluepy-helper>
```

Example:
Address: FB6D083D25A4
Data:    1EFF4C001219102807CE0B3C33332ED37B5D9D8291B1D99D0B8615189700E0

This is made of:
Address:
[00]    FB: the low 4 bits of the first byte of the public key. The first 2 bits are set to 1. So the first byte is 0b__111011 (we do not yet know the first two bits)
[01-05] 6D083D25A4: Bytes 1-5 of the public key

Payload:
        (Table 5-2)
[06]    1E: Total length is 30 bytes (Apple spec is wrong, says 3. That is only true for the unseparated one)
[07]    FF: Type is 'manufacturer-specific'
[08-09] 4C00: Apple is the manufacturer (the endianness is swapped here)
        (Table 5-4)
[10]    12: OF type
[11]    19: OF length (25 bytes)
[12]    10: Status (0b0010000 indicates it has seen the owner in the last 24 hours and has full battery)
[13-34] 2807CE0B3C33332ED37B5D9D8291B1D99D0B86151897 (bytes 6-27 of the public key. Apple is wrong again, this time in the offsets)
[35]    00: The first two bits are the part of the first byte of the public key that got chopped off in the address. Now we know the first byte was 0x3b
[36]    E0: Apple says byte 5 of the public key, but that is in the address. Whitepaper says 00. But it's not 00 here. It's described as a hint, so maybe we can just ignore it

So the public key was: 3B6D083D25A42807CE0B3C33332ED37B5D9D8291B1D99D0B86151897


Example 2:

Got: 'rsp=$scan\x1eaddr=bDFA4651A5272\x1etype=h2\x1erssi=h43\x1eflag=h0\x1ed=b07FF4C0012025402\n'

Address:
[00]    DF: First byte of the public key is 0b__011111
[01-05] A4651A5272: Public key data

Payload:
        (Table 5-2)
[06]    07: Total length is 7 bytes
[07]    FF: Type is 'manufacturer-specific'
[08-09] 4C00: Apple is the manufacturer
[10]    12: OF Type
[11]    02: OF length (2 bytes)
[12]    54: Status (0b1010100: Battery full. Owner saw it recently)
[13]    02: First 2 bits of key are 0b11, yielding 0b11011111 which is just df