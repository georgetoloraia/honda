import subprocess
import os
import re
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from hashlib import sha256
from binascii import hexlify, unhexlify

# Parameters
G = secp256k1.G
p = secp256k1.p
target_hex = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"
target_bytes = unhexlify(target_hex)
STEP = 2**64
N = 50  # number of offsets
offset = 0  # base scalar — you can randomize this for multiple runs

# Decompress pubkey
def decompress(pub_hex):
    b = unhexlify(pub_hex)
    x = int.from_bytes(b[1:], 'big')
    y_even = b[0] == 0x02
    alpha = (x ** 3 + secp256k1.b) % p
    beta = pow(alpha, (p + 1) // 4, p)
    y = beta if (beta % 2 == 0) == y_even else p - beta
    return Point(x, y, curve=secp256k1)

# Compress pubkey
def compress(P: Point) -> str:
    prefix = '02' if P.y % 2 == 0 else '03'
    return prefix + format(P.x, '064x')

# Private key to WIF (compressed)
def priv_to_wif(priv_int):
    priv_hex = format(priv_int, '064x')
    prefix = "80" + priv_hex + "01"
    first_sha = sha256(unhexlify(prefix)).digest()
    second_sha = sha256(first_sha).digest()
    checksum = second_sha[:4]
    wif_bytes = unhexlify(prefix) + checksum
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    # Base58 encoding
    value = int.from_bytes(wif_bytes, byteorder='big')
    result = ''
    while value > 0:
        value, mod = divmod(value, 58)
        result = alphabet[mod] + result
    padding = 0
    for c in wif_bytes:
        if c == 0:
            padding += 1
        else:
            break
    return '1' * padding + result

# Run keyhunt
def run_keyhunt(pubkeys):
    with open("pubkeys.txt", "w") as f:
        for key in pubkeys:
            f.write(key + "\n")

    subprocess.run([
        "./keyhunt", "-t", "12", "-m", "bsgs", "-f", "pubkeys.txt",
        "-r", f"{offset}:{offset + N * STEP - 1}", "-k", "512", "-q"
    ])

    if not os.path.exists("KEYFOUNDKEYFOUND.txt"):
        return []

    found = []
    with open("KEYFOUNDKEYFOUND.txt") as f:
        lines = f.readlines()
        for line in lines:
            match = re.search(r"privkey (\w+)", line)
            if match:
                privkey = int(match.group(1), 16)
                found.append(privkey)

    os.remove("KEYFOUNDKEYFOUND.txt")
    return found

# Main
target_point = decompress(target_hex)
target_x = target_point.x
print(f"🔍 Target X: {target_x}")
pubkeys = []
scalars = []

# Generate 50 pubkeys offset + i*STEP
for i in range(N):
    scalar = offset + i * STEP
    pub = compress(scalar * G)
    pubkeys.append(pub)
    scalars.append(scalar)

print(f"🚀 Running keyhunt on {N} pubkeys...")
found_privkeys = run_keyhunt(pubkeys)

if not found_privkeys:
    print("❌ No match found by keyhunt.")
else:
    for partial in found_privkeys:
        full_priv = partial  # offset is 0, so full_priv = partial
        pub = compress(full_priv * G)
        print(f"🔑 Checking privkey: {hex(full_priv)} → pub: {pub}")
        if pub == target_hex:
            print(f"\n✅ Match found! Private key: {hex(full_priv)}")
            wif = priv_to_wif(full_priv)
            print(f"🔐 WIF: {wif}")
            with open("found_wif.txt", "a") as f:
                f.write(f"{wif}\n")
        else:
            print("⚠️ Found key does not match target.")
