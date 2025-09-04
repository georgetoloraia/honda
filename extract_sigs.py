#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests, hashlib, base58, struct, sys, time

# ====== CONFIG ======
PUBHEX = "0229c1aa6978e9c01145176317b9e50eb0b91aa31744709284a4189086d3840f43" # "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"
BASE = "https://blockstream.info/api"   # Mainnet
MAX_TXS_PER_ADDR = 1000                 # უსაფრთხო ლიმიტი pagination-ზე
REQ_TIMEOUT = 20

# ====== Utils ======

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def dsha256(b: bytes) -> bytes:
    return sha256(sha256(b))

def h160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def varint(n: int) -> bytes:
    if n < 0xfd:   return n.to_bytes(1, 'little')
    if n <= 0xffff: return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff: return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')

def le_hex(x: str) -> bytes:
    return bytes.fromhex(x)[::-1]

def be_hex(b: bytes) -> str:
    return b.hex()

# ----- Bech32 (BIP173) minimal encoder for P2WPKH -----
# Credit: compact implementation adapted for clarity (no external deps)
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25) & 0xff
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    return [(polymod >> 5*(5-i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join([BECH32_CHARSET[d] for d in combined])

def convertbits(data, frombits, tobits, pad=True):
    acc = 0; bits = 0; ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def encode_segwit_address(hrp, witver, witprog: bytes):
    if witver > 16 or len(witprog) < 2 or len(witprog) > 40:
        raise ValueError("invalid segwit program")
    data = [witver] + convertbits(list(witprog), 8, 5)
    return bech32_encode(hrp, data)

# ----- Addresses from pubkey -----

def p2pkh_address(pub: bytes) -> str:
    ver = b'\x00' + h160(pub)
    chk = dsha256(ver)[:4]
    return base58.b58encode(ver+chk).decode()

def p2sh_p2wpkh_address(pub: bytes) -> str:
    redeem = bytes.fromhex("0014") + h160(pub)      # 0 <20-byte>
    redeem_h160 = h160(redeem)
    ver = b'\x05' + redeem_h160
    chk = dsha256(ver)[:4]
    return base58.b58encode(ver+chk).decode()

def p2wpkh_bech32_address(pub: bytes) -> str:
    return encode_segwit_address("bc", 0, h160(pub))

# ----- Scripts -----

def p2pkh_scriptcode_from_pub(pub: bytes) -> str:
    # scriptCode = DUP HASH160 <h160(pub)> EQUALVERIFY CHECKSIG
    return "76a914" + h160(pub).hex() + "88ac"

def read_push(data: bytes, i: int):
    """read one pushdata from scriptsig: returns (payload_bytes, next_index)."""
    if i >= len(data):
        raise ValueError("unexpected end of scriptsig")
    op = data[i]; i += 1
    if op <= 0x4b:
        l = op
    elif op == 0x4c:
        if i >= len(data): raise ValueError("PUSHDATA1 short read")
        l = data[i]; i += 1
    elif op == 0x4d:
        if i+2 > len(data): raise ValueError("PUSHDATA2 short read")
        l = int.from_bytes(data[i:i+2], "little"); i += 2
    elif op == 0x4e:
        if i+4 > len(data): raise ValueError("PUSHDATA4 short read")
        l = int.from_bytes(data[i:i+4], "little"); i += 4
    else:
        raise ValueError(f"unexpected opcode {op:#x}")
    if i+l > len(data): raise ValueError("push length exceeds scriptsig size")
    payload = data[i:i+l]; i += l
    return payload, i

def sig_from_scriptsig_hex(scriptsig_hex: str) -> str:
    """Return DER+SIGHASH signature (hex) from scriptsig hex (first push)."""
    b = bytes.fromhex(scriptsig_hex)
    i = 0
    sig, i = read_push(b, i)
    return sig.hex()

def parse_der_sig(sig_hex: str):
    """Input: DER+1byte sighash hex. Output: (r, s, sighash_type)."""
    b = bytes.fromhex(sig_hex)
    if len(b) < 9 or b[0] != 0x30:
        raise ValueError("not a DER sequence")
    der, sighash_type = b[:-1], b[-1]
    i = 2
    if i >= len(der) or der[i] != 0x02: raise ValueError("DER parse r tag")
    i += 1
    rlen = der[i]; i += 1
    r = int.from_bytes(der[i:i+rlen], 'big'); i += rlen
    if der[i] != 0x02: raise ValueError("DER parse s tag")
    i += 1
    slen = der[i]; i += 1
    s = int.from_bytes(der[i:i+slen], 'big'); i += slen
    return r, s, sighash_type

# ----- Sighash builders -----

def legacy_sighash_z(full_tx_json: dict, in_idx: int, scriptCode_hex: str, sighash_type: int) -> str:
    # Full legacy SIGHASH_ALL preimage
    tx = full_tx_json
    version = tx["version"]
    locktime = tx["locktime"]
    vins = tx["vin"]
    vouts = tx["vout"]

    pre = struct.pack("<I", version)
    pre += varint(len(vins))
    for idx, vin in enumerate(vins):
        prev_txid = vin["txid"]
        vout = vin["vout"]
        pre += le_hex(prev_txid)
        pre += struct.pack("<I", vout)
        if idx == in_idx:
            sc = bytes.fromhex(scriptCode_hex)
            pre += varint(len(sc)) + sc
        else:
            pre += varint(0)
        pre += struct.pack("<I", vin["sequence"])
    pre += varint(len(vouts))
    for o in vouts:
        # Blockstream returns value in sats (int)
        val = o["value"]
        spk = bytes.fromhex(o["scriptpubkey"])
        pre += struct.pack("<q", val)
        pre += varint(len(spk)) + spk
    pre += struct.pack("<I", locktime)
    pre += struct.pack("<I", sighash_type)
    return dsha256(pre).hex()

def bip143_sighash_z(full_tx_json: dict, in_idx: int, amount_sats: int, scriptCode_hex: str, sighash_type: int) -> str:
    # BIP-143 SIGHASH_ALL
    tx = full_tx_json
    version = tx["version"]
    locktime = tx["locktime"]
    vins = tx["vin"]
    vouts = tx["vout"]

    # hashPrevouts
    hp = b''.join(le_hex(v["txid"]) + struct.pack("<I", v["vout"]) for v in vins)
    hashPrevouts = dsha256(hp)

    # hashSequence
    hs = b''.join(struct.pack("<I", v["sequence"]) for v in vins)
    hashSequence = dsha256(hs)

    # hashOutputs
    ho = b''
    for o in vouts:
        val = o["value"]
        spk = bytes.fromhex(o["scriptpubkey"])
        ho += struct.pack("<q", val) + varint(len(spk)) + spk
    hashOutputs = dsha256(ho)

    this = vins[in_idx]
    outpoint = le_hex(this["txid"]) + struct.pack("<I", this["vout"])
    scriptCode = bytes.fromhex(scriptCode_hex)

    pre  = struct.pack("<I", version)
    pre += hashPrevouts
    pre += hashSequence
    pre += outpoint
    pre += varint(len(scriptCode)) + scriptCode
    pre += struct.pack("<q", amount_sats)
    pre += struct.pack("<I", this["sequence"])
    pre += hashOutputs
    pre += struct.pack("<I", locktime)
    pre += struct.pack("<I", sighash_type)
    return dsha256(pre).hex()

# ----- Blockstream API -----

def http_get_json(url):
    r = requests.get(url, timeout=REQ_TIMEOUT)
    r.raise_for_status()
    return r.json()

def get_address_txs_all(addr: str, limit=MAX_TXS_PER_ADDR):
    """Fetches all txs for address with pagination. Returns list of tx JSONs."""
    txs = []
    # First page:
    page = http_get_json(f"{BASE}/address/{addr}/txs")
    txs.extend(page)
    last = None
    # Then chain pages with last_seen_txid
    while page and len(txs) < limit:
        last = page[-1]["txid"]
        page = http_get_json(f"{BASE}/address/{addr}/txs/chain/{last}")
        if not page: break
        txs.extend(page)
        # polite sleep to avoid rate limits
        time.sleep(0.2)
    return txs[:limit]

def get_tx(txid: str):
    return http_get_json(f"{BASE}/tx/{txid}")

# ====== MAIN LOGIC ======

def main():
    pub = bytes.fromhex(PUBHEX)
    addr_p2pkh = p2pkh_address(pub)
    addr_p2sh  = p2sh_p2wpkh_address(pub)
    addr_bech32= p2wpkh_bech32_address(pub)

    addrs = [addr_p2pkh, addr_p2sh, addr_bech32]
    print("Addresses:", addrs)

    rows = []  # (txid, input_index, rhex, shex, zhex, pubkey, sighash_type_hex, addr_type, amount)
    # iterate all addresses
    for addr in addrs:
        try:
            txs = get_address_txs_all(addr)
        except Exception as e:
            print(f"[WARN] fetch txs for {addr} failed: {e}")
            continue

        for tx in txs:
            txid = tx["txid"]
            vins = tx["vin"]
            for i, vin in enumerate(vins):
                # Legacy P2PKH spend: scriptsig contains sig and pubkey
                if vin.get("scriptsig"):
                    try:
                        sighex = sig_from_scriptsig_hex(vin["scriptsig"])
                        # Extract pubkey (second push) to ensure it's OUR pubkey
                        # We need to read scriptsig again:
                        b = bytes.fromhex(vin["scriptsig"])
                        j = 0
                        sig_b, j = read_push(b, j)
                        pub_b, j = read_push(b, j)
                        if pub_b.hex() != PUBHEX:
                            continue  # not our pubkey
                        r, s, ht = parse_der_sig(sighex)
                        # scriptCode = prevout's scriptpubkey for legacy is actually P2PKH template with our pubkey-hash
                        # but we can also fetch prev tx vout spk directly:
                        prevtx = get_tx(vin["txid"])
                        spk = prevtx["vout"][vin["vout"]]["scriptpubkey"]
                        z = legacy_sighash_z(get_tx(txid), i, spk, ht)
                        rows.append((txid, i, f"{r:x}", f"{s:x}", z, PUBHEX, f"{ht:02x}", "legacy", None))
                    except Exception as e:
                        # ignore parse errors for unrelated inputs
                        continue

                # SegWit P2WPKH / P2SH-P2WPKH: witness = [sig, pub]
                if "witness" in vin and vin["witness"]:
                    wit = vin["witness"]
                    if len(wit) >= 2 and wit[1] == PUBHEX:
                        try:
                            sighex = wit[0]
                            r, s, ht = parse_der_sig(sighex)
                            # scriptCode (BIP143) = P2PKH template with h160(pub)
                            sc = p2pkh_scriptcode_from_pub(bytes.fromhex(PUBHEX))
                            prevtx = get_tx(vin["txid"])
                            amount_sats = prevtx["vout"][vin["vout"]]["value"]
                            z = bip143_sighash_z(get_tx(txid), i, amount_sats, sc, ht)
                            addr_type = "segwit"
                            rows.append((txid, i, f"{r:x}", f"{s:x}", z, PUBHEX, f"{ht:02x}", addr_type, amount_sats))
                        except Exception:
                            continue

    # Analyze duplicate r (nonce reuse)
    rs = {}
    for row in rows:
        rhex = row[2]
        rs.setdefault(rhex, []).append(row)

    print("\nFound signatures:", len(rows))
    dups = {rhex: lst for rhex, lst in rs.items() if len(lst) > 1}
    if dups:
        print("POTENTIAL NONCE REUSE! Same r appears multiple times:")
        for rhex, lst in dups.items():
            tx_inputs = [(row[0], row[1]) for row in lst]
            print(rhex, "->", tx_inputs)
    else:
        print("No duplicate r found for this pubkey.")

    # CSV dump
    if rows:
        print("\nCSV:")
        print("txid,input_index,r,s,z,pubkey,sighash_type,addr_type,amount_sats")
        for row in rows:
            print(",".join("" if v is None else str(v) for v in row))
    else:
        print("No spends found for these addresses.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
