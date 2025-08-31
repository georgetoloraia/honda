from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from binascii import unhexlify

G = secp256k1.G
p = secp256k1.p

def decompress(pub_hex: str) -> Point:
    b = unhexlify(pub_hex)
    x = int.from_bytes(b[1:], 'big')
    y_even = b[0] == 0x02
    alpha = (x * x * x + secp256k1.a * x + secp256k1.b) % p
    beta = pow(alpha, (p + 1) // 4, p)  # p % 4 == 3
    y = beta if (beta % 2 == 0) == y_even else p - beta
    return Point(x, y, curve=secp256k1)

def compress(P: Point) -> str:
    prefix = '02' if (P.y % 2 == 0) else '03'
    return prefix + format(P.x, '064x')

# --- inputs ---
target_hex = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"
target = decompress(target_hex)


minimal = 0x100000000000000000000000000000

with open("135.txt", "a") as f:
    for i in range(0xffff):
        gamyofi = i * minimal

        gamyofi_hex = gamyofi * G

        res = target + (-gamyofi_hex)
        
        need_write = compress(res)
        # print(f"{gamyofi} = {compress(res)}")
        f.write(f"{need_write}\n")
    f.close()
