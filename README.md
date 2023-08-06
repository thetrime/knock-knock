# Installation

## System Prerequisites
Running with Raspbian Lite, I needed to install libglib2 and pip:
```
sudo apt install python3-pip libglib2.0-dev
```

## Python requirements
You can install the requirements with pip:
```
pip install -r requirements.txt
```

(you can also install these as root if you want them available system-wide)

Note that building the `cryptography` module requires a recent version of pip or for rust to be preinstalled. On raspbian, the current version of pip came with a precompiled version; on other operating systems I had to install rust.

## Permissions for running as a non-root user

To run this as a non-root user, you need to grant some rights to bluepy-helper. First, find it - if you installed the python packages with sudo, check here:

```
find /usr/local/lib -name bluepy-helper
```

otherwise, you need to look in your home directory:

```
find ~ -name bluepy-helper
```

Then for each one:

```
sudo setcap 'cap_net_raw,cap_net_admin+eip' <path to bluepy-helper>
```

# Usage

You need a file called `keys` which contains lines with 3 values:

1.  The time of pairing (in Zulu time, ISO8601 format)
2.  The shared secret (in hex, without any leading 0x)
3.  The public key (in hex, without any leading 0x)
4.  A label for the key

You can get this data from the `.record` files in `~/Library/com.apple.icloud/searchpartyd/OwnedBeacons`, after decrypting them

1.  paringDate
2.  sharedSecret.key.data
3.  publicKey.key.data
4.  Whatever you like

If you have a Mac that is synced with the same iCloud account that owns the AirTags, in the directory `decryptor` in this repository is a simple Swift program that will generate this file for you for all the devices you own.

# Technical details: How the BLE advertisement corresponds to the advertised key
## Worked example

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
```


# Notes on the window size
In experiments, it seemed that tags could be as much as 6 keys behind. This might be related to daylight saving changes - I was unable to find a conclusive explanation

# About the timing
It seems that tags switch their keys at :00, :15, :30 and :45 rather than 15 minutes since pairing. The code does not correctly implement this, but the window size covers the discrepancy