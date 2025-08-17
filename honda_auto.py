# import subprocess
# from fastecdsa.curve import secp256k1
# from fastecdsa.point import Point
# from binascii import unhexlify
# import os

# # === CONFIG ===
# # target_hex = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"
# target_hex = "02dba61b59516e8855f3e1f890c407b3b0ae7050087b955b8678fa4de7e796f40b"
# G = secp256k1.G
# p = secp256k1.p

# # === FUNCTIONS ===
# def decompress(pub_hex: str) -> Point:
#     b = unhexlify(pub_hex)
#     x = int.from_bytes(b[1:], 'big')
#     y_even = b[0] == 0x02
#     alpha = (x**3 + secp256k1.a * x + secp256k1.b) % p
#     beta = pow(alpha, (p + 1) // 4, p)
#     y = beta if (beta % 2 == 0) == y_even else p - beta
#     return Point(x, y, curve=secp256k1)

# def compress(point: Point) -> str:
#     prefix = '02' if point.y % 2 == 0 else '03'
#     return prefix + format(point.x, '064x')

# def run_keyhunt(pubkey_hex):
#     with open("pubkey.txt", "w") as f:
#         f.write(pubkey_hex + "\n")

#     print("🚀 Running keyhunt...")
#     subprocess.run(["./keyhunt", "-m", "bsgs", "-f", "pubkey.txt", "-r", "1:ffffffffffff", "-t", "12", "-k", "128"])

#     if os.path.exists("KEYFOUNDKEYFOUND.txt"):
#         with open("KEYFOUNDKEYFOUND.txt") as f:
#             content = f.read().strip()
#             if content:
#                 return int(content, 16)
#     return None

# # === MAIN ===
# if __name__ == "__main__":
#     target = decompress(target_hex)
#     print("🔍 Target X:", target.x)
#     prev_y = target.y

#     for i in range(132095795529831058500, 132095795529831058608):
#         guess = target + (-i * G)

#         if (guess.y % 2) != (prev_y % 2):
#             print(f"🔁 Y flipped in target + (-{i} * G): Y = {guess.y}")
#             pub_hex = compress(guess)
#             print("🧪 Trying keyhunt with compressed pub:", pub_hex)
#             found = run_keyhunt(pub_hex)
#             if found:
#                 priv = found + i
#                 print(f"✅ Private key found: {hex(priv)}")
#                 break
#             else:
#                 print("❌ keyhunt did not find match")
#         prev_y = guess.y




#--------------------------------------------------------

import subprocess
import os
import re
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from binascii import unhexlify

# Parameters
G = secp256k1.G
p = secp256k1.p
target_hex = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"
target_bytes = unhexlify(target_hex)

# Decompress public key
def decompress(pub_hex: str) -> Point:
    b = unhexlify(pub_hex)
    x = int.from_bytes(b[1:], 'big')
    y_even = b[0] == 0x02
    alpha = (x ** 3 + secp256k1.a * x + secp256k1.b) % p
    beta = pow(alpha, (p + 1) // 4, p)
    y = beta if (beta % 2 == 0) == y_even else p - beta
    return Point(x, y, curve=secp256k1)

# Compress public key
def compress(P: Point) -> str:
    prefix = '02' if P.y % 2 == 0 else '03'
    return prefix + format(P.x, '064x')

# Run keyhunt
def run_keyhunt(pub_hex: str):
    with open("pubkey.txt", "w") as f:
        f.write(pub_hex + "\n")

    subprocess.run([
        "./keyhunt", "-t", "12", "-m", "bsgs", "-f", "pubkey.txt",
        "-r", "1:fffffffffffff", "-k", "128", "-q"
    ])

    if not os.path.exists("KEYFOUNDKEYFOUND.txt"):
        return None

    with open("KEYFOUNDKEYFOUND.txt") as f:
        content = f.read()

    match = re.search(r"privkey (\w+)", content)
    if match:
        return int(match.group(1), 16)
    return None

# Main flipping scan
target_point = decompress(target_hex)
target_x = target_point.x
target_y = target_point.y

print(f"🔍 Target X: {target_x}")

max_steps = 2**135  # you can increase this for deeper search

for i in range(38987797333629756134543969225778613408548, max_steps, 2**64):
    neg_step = -i * G
    new_point = target_point + neg_step

    if new_point.y > p // 2 and (target_y < p // 2):
        flipped_pub = compress(new_point)
        print(f"🔁 Y flipped in target + (-{i} * G): Y = {new_point.y}")
        print(f"🧪 Trying keyhunt with compressed pub: {flipped_pub}")
        print("🚀 Running keyhunt...")

        privkey = run_keyhunt(flipped_pub)
        if privkey:
            print(f"\n✅ Private key found: {hex(privkey)}")
            break
