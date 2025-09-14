# honda command

```
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
```
