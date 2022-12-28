"""
Find AirTags that you own without involving Apple in the process
"""
from binascii import unhexlify
from datetime import datetime
from time import time, sleep
from collections import deque
import threading

from bluepy import btle
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from ecdsa.ellipticcurve import Point
from ecdsa.curves import NIST224p

keys = []
ENDIANNESS = "big"
G = NIST224p.generator
n = NIST224p.order
WINDOW_SIZE = 10

def update_key(key, echo):
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
    sk_1 = xkdf.derive(key['shared_key'])

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
    p_0 = Point(NIST224p.curve, key['pkx'], key['pky'])
    p_1 = u_1 * p_0 + v_1 * G
    date_time = datetime.fromtimestamp(t_i).strftime("%Y-%m-%d %H:%M:%S")
    if echo:
        print(date_time + " " + hex(p_1.x()) + ": " + key['name'])
    if len(key['advertised_prefixes']) > WINDOW_SIZE:
        key['advertised_prefixes'].popleft()
    # We only really care about the first 6 bytes of the key.
    # In the near-to-owner case, this is all that is advertised..
    # The full key is only needed if we want to upload a finding-report to Apple
    new_prefix = hex(p_1.x())[0:14]
    key['advertised_prefixes'].append(new_prefix)
    key['time'] = t_i
    key['shared_key'] = sk_1

def load_keys(filename):
    """
    Load stashed keys
    """
    keyfile = open(filename, "r", encoding="utf-8")
    min_t = time() - 12*60*60
    key_lines = keyfile.read().splitlines()
    for line in key_lines:
        if line.startswith("#"):
            continue
        chunks = line.split(" ")
        sync_time = chunks[0]
        dt_0 = datetime.strptime(sync_time, '%Y-%m-%dT%H:%M:%SZ')
        t_0 = (dt_0 - datetime(1970, 1, 1)).total_seconds()
        if t_0 < min_t:
            min_t = t_0
        pkx = chunks[2][2:58]
        pky = chunks[2][58:]
        keys.append({
            'time': t_0,
            'shared_key': unhexlify(chunks[1]),
            'pkx': int.from_bytes(unhexlify(pkx), ENDIANNESS),
            'pky': int.from_bytes(unhexlify(pky), ENDIANNESS),
            'name': " ".join(chunks[3:]),
            'advertised_prefixes': deque()
        })
    keyfile.close()

def rehydrate_keys():
    """
    Refresh all keys until they are at most 12 hours old
    """
    # Starting from the oldest key, get all the keys up to WINDOW_SIZE/2 * 15 minutes ago
    for key in keys:
        while key['time'] < time() - (WINDOW_SIZE/2) * 15 * 60:
            update_key(key, False)

def stash_keys(filename):
    """
    Save current key state
    """
    # Save keys so we dont have to do this next time
    print("All keys updated. Saving...")
    out = open(filename, "w", encoding="utf-8")
    for key in keys:
        out.write(
            datetime.fromtimestamp(key['time']).isoformat(timespec='seconds') +
            "Z " +
            key['shared_key'].hex() +
            " " +
            hex(key['pkx'])[2:] +
            hex(key['pky'])[2:] +
            " " +
            key['name'] +
            "\n"
        )
    out.close()

class ScanPrint(btle.DefaultDelegate):
    """
    Delegate class to handle BLE scan callback
    """
    def __init__(self, callback):
        btle.DefaultDelegate.__init__(self)
        self.callback = callback

    def handleDiscovery(self, scanEntry, isNewDev, isNewData):
        """
        Callback from bluepy when a device is discovered
        """
        for (code_type, _, val) in scanEntry.getScanData():
            if code_type == 0xff and val[0:6] == "4c0012":
                # print("Apple device discovered")
                data = unhexlify(val)
                # Apple advertisement
                first_byte = int(scanEntry.addr[0:2], 16) & 0b00111111
                key_prefix = scanEntry.addr.replace(":", "")[2:]
                # status = val[6:7]
                # This contains the battery info and whether the
                # AirTag was seen by its owner recently
                if data[3] == 25:
                    # Full key. Rest of the key is in val[8:..]
                    # but we don't really need it - just the prefix
                    special_bits = data[27]
                elif data[3] == 2: # Partial key
                    special_bits = data[5]
                else:
                    print(f"Bad special bits {data[5]}")
                first_byte |= ((special_bits << 6) & 0b11000000)
                first_byte &= 0xff
                if first_byte < 0x10:
                    key_prefix = "0x0" + hex(first_byte)[2] + key_prefix
                else:
                    key_prefix = hex(first_byte) + key_prefix
                # print("Key prefix is: " + key_prefix + " from address " + scanEntry.addr)
                for key in keys:
                    for candidate in list(key['advertised_prefixes']):
                        if candidate.startswith(key_prefix):
                            self.callback(key['name'], scanEntry.rssi)
                            # print(f"Got notificaton from {key['name']} with signal strength {scanEntry.rssi} dBm")

def update_keys_as_required():
    """
    Update keys until there are WINDOW_SIZE advertised keys available, with the current time
    being the middle of the array
    """
    while True:
        for key in keys:
            while key['time'] < time() + (WINDOW_SIZE/2) * 15 * 60:
                update_key(key, False)
        sleep(60)


def setup(filename):
    """
    Prepare the key data in filename
    """
    print("Loading keys")
    load_keys(filename)
    print(f"Loaded {len(keys)} keys. Rehydrating...")
    # We stash the keys after rehydrating. To avoid getting too far ahead, we keep WINDOW_SIZE/2 blocks behind
    rehydrate_keys()
    print("Keys rehydrated. Stashing hydrated keys")
    stash_keys(filename)
    return [key['name'] for key in keys]

def start(callback):
    """
    Start running the collector
    """
    # Now we can start to update the keys
    print("Scheduling keyroller")
    thread = threading.Thread(target=update_keys_as_required, daemon=True)
    thread.start()
    print("Preparing scanner")
    scanner = btle.Scanner(0).withDelegate(ScanPrint(callback))
    print("Scanning")
    scanner.scan(0)

if __name__ == "__main__":
    setup('keys')
