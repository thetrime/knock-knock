import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from binascii import hexlify, unhexlify
from ecdsa.ellipticcurve import Point
from ecdsa.curves import NIST224p
from datetime import datetime
from time import time

def refreshKey(key, echo):
    t_i = key['time'] + 15*60
    # Derive SK_1 from SK_0
    xkdf = X963KDF(
        algorithm=hashes.SHA256(),
        length=32,
        sharedinfo=b"update",
    )
    SK = xkdf.derive(key['sharedKey'])

    # Derive AT_1 from SK_1
    xkdf = X963KDF(
        algorithm=hashes.SHA256(),
        length=72,
        sharedinfo=b"diversify",
    )
    AT = xkdf.derive(SK)

    # Derive u_1 and v_1 from this
    u_1 = int.from_bytes(AT[:36], endianness)
    v_1 = int.from_bytes(AT[36:], endianness)

    # Reduce u and v into P-224 scalars
    u_1 = (u_1 % (n-1)) + 1
    v_1 = (v_1 % (n-1)) + 1

    # Compute P_1
    P = key['privateKey'] * G
    Px = u_1 * P + v_1 * G    
    date_time = datetime.fromtimestamp(t_i).strftime("%Y-%m-%d %H:%M:%S")
    advertised_key = "{0:#0{1}x}".format(Px.x(), 58)
    if (echo):
        print(date_time + " " + advertised_key + ": " + key['name'])
    key['advertisedKey'] = hex(Px.x())
    key['time'] = t_i
    key['sharedKey'] = SK


keys = []
endianness = "big"
now = time()
twelve_hours_ago = now - 12*60*60
twelve_hours_ahead = now + 12*60*60
min_t = twelve_hours_ago

f = open("keys", "r")
for line in f:
    if (line.startswith("#")):
        continue
    chunks = line.split(" ")
    time = chunks[0]
    dt_0 = datetime.strptime(time, '%Y-%m-%dT%H:%M:%S.%fZ')
    t_0 = (dt_0 - datetime(1970, 1, 1)).total_seconds()
    if (t_0 < min_t):
        min_t = t_0
    keys.append({'time': t_0, 'sharedKey': unhexlify(chunks[1]), 'privateKey': int.from_bytes(unhexlify(chunks[2]), endianness), 'name': " ".join(chunks[3:])})
f.close()
G = NIST224p.generator
n = NIST224p.order

# Starting from the oldest key, get all the keys up to 12 hours ago 
for key in keys:
    while (key['time'] < twelve_hours_ago + 24*60*60*7):
        refreshKey(key, False)
        if "94b5598de9" in key['advertisedKey']:
            print("Eureka: " + datetime.fromtimestamp(key['time']).isoformat(timespec='milliseconds') + "Z ")

quit()

# Save keys so we dont have to do this next time
print("All keys updated. Saving...")
f = open("keys2", "w")
for key in keys:
    #f.write(datetime.fromtimestamp(key['time']).isoformat(timespec='milliseconds') + "Z " + key['sharedKey'].hex() + " " + key['privateKey'].to_bytes(28, endianness).hex() + " " + key['name'] + "\n")
    f.write(datetime.fromtimestamp(key['time']).isoformat(timespec='milliseconds') + "Z " + key['sharedKey'].hex() + " " + hex(key['privateKey']) + " " + key['name'] + "\n")
f.close()

# Now print out the key next 96 keys
for key in keys:
    while (key['time'] < twelve_hours_ahead):
        refreshKey(key, True)
