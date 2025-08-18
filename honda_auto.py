import subprocess
import os
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from binascii import unhexlify
import hashlib
import base58

# Parameters
G = secp256k1.G
p = secp256k1.p
target_hex = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"
NUM_KEYS = 50
STEP = 2**64
KEYHUNT_RANGE = "1:ffffffffffffffff"

# WIF export (compressed)
def to_wif(privkey: int) -> str:
    priv_hex = privkey.to_bytes(32, 'big')
    extended = b'\x80' + priv_hex + b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return base58.b58encode(extended + checksum).decode()

# Decompress pubkey hex to Point
def decompress(pub_hex: str) -> Point:
    b = unhexlify(pub_hex)
    x = int.from_bytes(b[1:], 'big')
    y_even = b[0] == 0x02
    alpha = (x ** 3 + secp256k1.b) % p
    beta = pow(alpha, (p + 1) // 4, p)
    y = beta if (beta % 2 == 0) == y_even else p - beta
    return Point(x, y, curve=secp256k1)

# Compress point to pubkey hex
def compress(P: Point) -> str:
    prefix = '02' if P.y % 2 == 0 else '03'
    return prefix + format(P.x, '064x')

# Run keyhunt and return found privkey
def run_keyhunt() -> int | None:
    subprocess.run([
        "./keyhunt", "-t", "12", "-m", "bsgs", "-f", "pubkeys.txt",
        "-r", KEYHUNT_RANGE, "-k", "512", "-q"
    ])
    if not os.path.exists("KEYFOUNDKEYFOUND.txt"):
        return None

    with open("KEYFOUNDKEYFOUND.txt") as f:
        for line in f:
            if "privkey" in line:
                hexkey = line.strip().split("privkey ")[-1]
                return int(hexkey, 16)
    return None

# Main process
target_point = decompress(target_hex)
target_y = target_point.y
print(f"🔍 Target X: {target_point.x}")

base_scalar = 43235168737637194824777423110161193957656  # example seed, can randomize

pubkeys = []
offset_map = {}

for i in range(NUM_KEYS):
    scalar = base_scalar + i * STEP
    offset_map[i] = scalar
    new_point = target_point + (-scalar * G)

    if (target_y < p // 2 and new_point.y > p // 2) or (target_y > p // 2 and new_point.y < p // 2):
        pubkeys.append(compress(new_point))

# Save pubkeys to file
with open("pubkeys.txt", "w") as f:
    for pub in pubkeys:
        f.write(pub + "\n")

print(f"🚀 Running keyhunt on {len(pubkeys)} flipped pubkeys...")
privkey = run_keyhunt()

if privkey:
    for idx, scalar in offset_map.items():
        full_priv = scalar + privkey
        pub_reconstructed = compress(full_priv * G)
        if pub_reconstructed == target_hex:
            wif = to_wif(full_priv)
            print(f"\n✅ MATCH FOUND at index {idx}")
            print(f"🔐 Private Key (decimal): {full_priv}")
            print(f"🔐 Private Key (hex): {hex(full_priv)}")
            print(f"🔑 WIF: {wif}")

            with open("found_wif.txt", "a") as wf:
                wf.write(wif + "\n")
            break
    else:
        print("❌ Privkey found but mismatch with target.")
else:
    print("❌ No match found by keyhunt.")
