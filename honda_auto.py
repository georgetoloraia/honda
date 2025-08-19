import subprocess
import os
import re
import hashlib
import base58
from random import randint
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from binascii import unhexlify

G = secp256k1.G
p = secp256k1.p

target_hex = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"

def decompress(pub_hex: str) -> Point:
    b = unhexlify(pub_hex)
    x = int.from_bytes(b[1:], 'big')
    y_even = b[0] == 0x02
    alpha = (x ** 3 + secp256k1.b) % p
    beta = pow(alpha, (p + 1) // 4, p)
    y = beta if (beta % 2 == 0) == y_even else p - beta
    return Point(x, y, curve=secp256k1)

def compress(P: Point) -> str:
    return ('02' if P.y % 2 == 0 else '03') + format(P.x, '064x')

def priv_to_wif(priv: int) -> str:
    raw = b'\x80' + priv.to_bytes(32, 'big') + b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    return base58.b58encode(raw + checksum).decode()

def run_keyhunt() -> str:
    subprocess.run([
        "./keyhunt", "-t", "12", "-m", "bsgs", "-f", "pubkey.txt",
        "-r", "1:ffffffffffffffff", "-k", "512", "-q"
    ])
    if not os.path.exists("KEYFOUNDKEYFOUND.txt"):
        return ""
    with open("KEYFOUNDKEYFOUND.txt") as f:
        content = f.read()
    os.remove("KEYFOUNDKEYFOUND.txt")
    return content

def extract_found_keys(output: str):
    return re.findall(r"privkey (\w+)\s+.*?Publickey (\w+)", output)

# MAIN LOOP
target_point = decompress(target_hex)
print(f"🔍 Target X: {target_point.x}")

while True:
    random_privs = []
    pubkeys = []

    # Generate 50 flipped public keys
    for _ in range(50):
        r = randint(2**134, 2**135)
        flipped_point = target_point + (-r * G)
        flipped_pub = compress(flipped_point)
        pubkeys.append(flipped_pub)
        random_privs.append(r)

    with open("pubkey.txt", "w") as f:
        f.write("\n".join(pubkeys) + "\n")

    print("🚀 Running keyhunt on 50 pubkeys...")
    output = run_keyhunt()
    if not output:
        print("❌ No key found. Retrying...\n")
        continue

    # Parse found keys
    matches = extract_found_keys(output)
    if not matches:
        print("❌ No valid match in keyhunt output. Retrying...\n")
        continue

    for hex_priv, found_pub in matches:
        found_priv = int(hex_priv, 16)
        if found_pub in pubkeys:
            index = pubkeys.index(found_pub)
            random_priv = random_privs[index]
            target_priv = (found_priv + random_priv) % secp256k1.q
            target_pub = compress(target_priv * G)

            print(f"\n✅ Found key!")
            print(f"🧩 Found privkey:     {hex(found_priv)}")
            print(f"➕ Random priv used:  {random_priv}")
            print(f"🔐 Final target priv: {hex(target_priv)}")
            print(f"🔑 Reconstructed pub: {target_pub}")
            print(f"🎯 Target pubkey:     {target_hex}")

            if target_pub == target_hex:
                wif = priv_to_wif(target_priv)
                print("🎉 Match confirmed! Saving to found_wif.txt")
                with open("found_wif.txt", "a") as f:
                    f.write(wif + "\n")
                exit(0)
            else:
                print("⚠️ Reconstructed pub does not match target.")
