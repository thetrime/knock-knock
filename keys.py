"""
Find AirTags that you own without involving Apple in the process
"""
from binascii import unhexlify
from datetime import datetime
from time import time
from collections import deque
import threading

from bluepy import btle
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from ecdsa.ellipticcurve import Point
from ecdsa.curves import NIST224p

keys = []
ENDIANNESS = "big"
now = time()
twelve_hours_ago = now - 12*60*60
twelve_hours_ahead = now + 12*60*60
G = NIST224p.generator
n = NIST224p.order
WINDOW_SIZE = 10

def refresh_key(key, echo):
    """
    Update a given key to the next key period
    """
    t_i = key['time'] + 15*60
    # Derive SK_1 from SK_0
    xkdf = X963KDF(
        algorithm=hashes.SHA256(),
        length=32,
        sharedinfo=b"update",
    )
    sk_1 = xkdf.derive(key['sharedKey'])

    # Derive AT_1 from SK_1
    xkdf = X963KDF(
        algorithm=hashes.SHA256(),
        length=72,
        sharedinfo=b"diversify",
    )
    at_1 = xkdf.derive(sk_1)

    # Derive u_1 and v_1 from this
    u_1 = int.from_bytes(at_1[:36], ENDIANNESS)
    v_1 = int.from_bytes(at_1[36:], ENDIANNESS)

    # Reduce u and v into P-224 scalars
    u_1 = (u_1 % (n-1)) + 1
    v_1 = (v_1 % (n-1)) + 1

    # Compute P_1
    p_0 = key['privateKey'] * G
    px_1 = u_1 * p_0 + v_1 * G
    date_time = datetime.fromtimestamp(t_i).strftime("%Y-%m-%d %H:%M:%S")
    advertised_key = "{0:#0{1}x}".format(px_1.x(), 58)
    if echo:
        print(date_time + " " + advertised_key + ": " + key['name'])
    if len(key['advertisedKeys']) > WINDOW_SIZE:
        key['advertisedKeys'].popLeft()
    key['advertisedKeys'].append(hex(px_1.x()))
    key['time'] = t_i
    key['sharedKey'] = sk_1

def load_keys():
    """
    Load stashed keys
    """
    keyfile = open("keys", "r", encoding="utf-8")
    min_t = twelve_hours_ago
    for line in keyfile:
        if line.startswith("#"):
            continue
        chunks = line.split(" ")
        sync_time = chunks[0]
        dt_0 = datetime.strptime(sync_time, '%Y-%m-%dT%H:%M:%S.%fZ')
        t_0 = (dt_0 - datetime(1970, 1, 1)).total_seconds()
        if t_0 < min_t:
            min_t = t_0
        keys.append({
            'time': t_0,
            'sharedKey': unhexlify(chunks[1]),
            'privateKey': int.from_bytes(unhexlify(chunks[2]), ENDIANNESS),
            'name': " ".join(chunks[3:]),
            'advertisedKeys': deque()
        })
    keyfile.close()

def refresh_keys():
    """
    Refresh all keys until they are at most 12 hours old
    """
    # Starting from the oldest key, get all the keys up to 12 hours ago
    for key in keys:
        while key['time'] < twelve_hours_ago + 24*60*60*7:
            refresh_key(key, False)

def stash_keys():
    """
    Save current key state
    """
    # Save keys so we dont have to do this next time
    print("All keys updated. Saving...")
    out = open("keys2", "w", encoding="utf-8")
    for key in keys:
        out.write(
            datetime.fromtimestamp(key['time']).isoformat(timespec='milliseconds') +
            "Z " +
            key['sharedKey'].hex() +
            " " +
            hex(key['privateKey']) +
            " " +
            key['name'] +
            "\n"
        )
    out.close()

class ScanPrint(btle.DefaultDelegate):
    """
    Delegate class to handle BLE scan callback
    """
    def __init__(self):
        btle.DefaultDelegate.__init__(self)

    def handleDiscovery(self, scanEntry, isNewDev, isNewData):
        for (_, _, val) in scanEntry.getScanData():
            if val[1:4] == 0xFF4C0012:
                # Apple advertisement
                key_prefix = scanEntry.addr
                # status = val[6]
                if val[5] == 25: # Full key
                    print("full key")
                    #key_prefix[6:27] = val[7:28]
                    key_prefix[0] ^= (val[29] >> 6)
                elif val[5] == 2: # Partial key
                    key_prefix[0] ^= (val[7] >> 6)
                for key in keys:
                    for candidate in key.advertisedKeys:
                        if candidate.startsWith(key_prefix):
                            print("Got notificaton from " + key['name'])

def update_keys_as_required():
    """
    Update keys until there are WINDOW_SIZE advertised keys available, with the current time
    being the middle of the array
    """
    # FIXME: Only refreshKey if needed
    for key in keys:
        refresh_key(key, False)

def main():
    """
    I have to document main()?
    """
    load_keys()
    refresh_keys()
    stash_keys()
    update_keys_as_required()
    scanner = btle.Scanner(0).withDelegate(ScanPrint())
    scanner.scan(0)

    # Then every 15 minutes, call refreshKey(key)


    # Now print out the key next 96 keys
    for key in keys:
        while key['time'] < twelve_hours_ahead:
            refresh_key(key, True)
