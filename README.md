# Installation

## Running as a non-root user

To run this as a non-root user, you need to grant some rights to bluepy-helper. First, find it:

```
find /usr/local/lib -name bluepy-helper
```

Then for each one:

```
sudo setcap 'cap_net_raw,cap_net_admin+eip' <path to bluepy-helper>
```

## Installing cryptography

This requires either a later version of pip or rust to be installed

# Usage

You need a file called `keys` which contains lines with 3 values:

1.  The time of pairing
2.  The shared secret
3.  The private key (_just_ the private part)
4.  A label for the key

You can get this data from the `.record` files in `~/Library/com.apple.icloud/searchpartyd/OwnedBeacons`, after decrypting them

1.  paringDate
2.  sharedSecret.key.data
3.  privateKey.key.data
4.  Whatever you like

Note that we do not technically need the private key - the public one would do. You just have to change the code around `# Compute P_1` that computes p_0 - this is the public part, deriving it from the private part. We could skip that and just supply the public part (future work!)

If you have a Mac that is synced with the same iCloud account that owns the AirTags, in the directory `decryptor` in this repository is a simple Swift program that will generate this file for you for all the devices you own.

# To do:

- Use the public, rather than private key
- See if I can get this working inside the devcontainer. There are potentially just permission problems holding it up.

# How the BLE advertisement corresponds to the advertised key

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
