# Generates vectors/extra-vectors.json. Every expected verdict comes from the
# REFERENCE runner's own functions (aer-1/conformance.py), never from this port.
# Run it in a throwaway container, with the reference checkout mounted read-only:
#
#   docker run --rm --network none --read-only --cap-drop ALL --user "$(id -u):$(id -g)" \
#     -v /path/to/zambo:/zambo:ro -v "$PWD/tools:/gen:ro" -v "$PWD/vectors:/out" -w /gen \
#     -e PYTHONDONTWRITEBYTECODE=1 python:3.12-slim python3 make_extra.py
# Builds supplementary vectors and derives every expected verdict from the
# REFERENCE runner's own functions (conformance.py), not from the Perl port.
import sys, json, base64, hashlib, copy
sys.path.insert(0, "/zambo/aer-1")
import conformance as ref

def b64(b): return base64.b64encode(b).decode()
base_receipt = json.load(open("/zambo/aer-1/test-vectors/valid/receipt-01.json"))
assert not ref.check(base_receipt)

def receipt_with(payload: bytes, **over):
    r = copy.deepcopy(base_receipt)
    r["canonical_bytes"] = b64(payload)
    r["output_hash"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    r.update(over)
    return r

vectors = []
def add(kind, name, desc, data, verdict, isolates):
    vectors.append({"kind": kind, "name": name, "desc": desc, "isolates": isolates, **data,
                    "expected_verdict": verdict})

# Receipts ------------------------------------------------------------------
p = b'{"inputs":{},"outputs":{"x":123},"tool":"t"}'         # 44 bytes: base64 ends in exactly one '='
assert len(p) == 44 and len(p) % 3 == 2 and b64(p).endswith("=") and not b64(p).endswith("==")
r = receipt_with(p); r["canonical_bytes"] = r["canonical_bytes"].rstrip("=")
assert not r["canonical_bytes"].endswith("=") and len(r["canonical_bytes"]) % 4 == 3
add("receipt", "x-base64-unpadded", "canonical_bytes with its padding stripped; hash still matches the bytes", {"receipt": r},
    "invalid" if ref.check(r) else "valid", "strict base64 padding")
r = receipt_with(p, created_at="2023-02-29T00:00:00Z")
add("receipt", "x-feb29-non-leap", "29 February in a non-leap year", {"receipt": r}, "invalid" if ref.check(r) else "valid", "Gregorian leap rule")
r = receipt_with(p, created_at="2024-02-29T00:00:00Z")
add("receipt", "x-feb29-leap", "29 February in a leap year (control)", {"receipt": r}, "invalid" if ref.check(r) else "valid", "Gregorian leap rule (control)")
r = receipt_with(p, created_at="1900-02-29T00:00:00Z")
add("receipt", "x-feb29-1900", "1900 is not a leap year (century rule)", {"receipt": r}, "invalid" if ref.check(r) else "valid", "century leap rule")
r = receipt_with(p, created_at="2026-09-23T23:45:20.7Z")
add("receipt", "x-fraction-one-digit", "created_at with a one-digit fraction; RFC 3339 allows 1*DIGIT (reference: valid on Python 3.11+, rejected on 3.10 and earlier)",
    {"receipt": r}, "invalid" if ref.check(r) else "valid", "RFC 3339 fractional seconds, any digit count")
r = receipt_with(p); r["tool"] = dict(r["tool"], name="")
add("receipt", "x-tool-empty-name", "tool.name is an empty string", {"receipt": r}, "invalid" if ref.check(r) else "valid", "non-empty tool strings")

# Chains --------------------------------------------------------------------
def entry(i, job, prev, tool="price_lookup", close=None, prov="LOGGED BY AGENT"):
    e = {"id": f"r-{job}-{i}", "seq": i + 1, "job_id": job, "tool": tool, "provenance_class": prov,
         "canonical_bytes": b64(json.dumps({"job": job, "entry": i}).encode()), "prev_digest": prev}
    if close is not None: e["close"] = close
    return e
single_bad = [entry(0, "job-x1", "1" * 64, close=True)]
add("chain", "x-genesis-single", "One closed entry whose prev_digest is not the zero digest: only the genesis rule can reject it",
    {"timeline": single_bad}, "invalid" if ref.verify_chain_v07(single_bad) else "valid", "genesis rule, isolated")

def build(job, tool, digest_fn, n=3):
    tl, prev = [], "0" * 64
    for i in range(n):
        e = entry(i, job, prev, tool=tool, close=True if i == n - 1 else None)
        tl.append(e); prev = digest_fn(e)
    return tl
odd_tool, odd_job = "tést\u007ftool", "job-€\nline"
tl_ref = build(odd_job, odd_tool, ref.chain_entry_digest_v07)
add("chain", "x-encoding-reference", "Links computed with the reference encoding: lowercase \\u hex, \\n short escape, U+007F escaped",
    {"timeline": tl_ref}, "invalid" if ref.verify_chain_v07(tl_ref) else "valid", "Section 7.1 string escaping")

def draft_literal_digest(e):
    # Draft text read literally: escape only NON-ASCII as \uXXXX; RFC 8259 for the rest. DEL is ASCII -> literal.
    raw = base64.b64decode(e["canonical_bytes"], validate=True)
    payload = {"prev_digest": e["prev_digest"], "seq": e["seq"], "job_id": e["job_id"], "close": e.get("close", False),
               "id": e["id"], "tool": e["tool"], "provenance_class": e["provenance_class"],
               "output_hash": hashlib.sha256(raw).hexdigest()}
    s = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    out = []
    for ch in s:
        n = ord(ch)
        if n > 0x7F:
            if n > 0xFFFF:
                m = n - 0x10000; out.append("\\u%04x\\u%04x" % (0xD800 | (m >> 10), 0xDC00 | (m & 0x3FF)))
            else: out.append("\\u%04x" % n)
        else: out.append(ch)
    return hashlib.sha256("".join(out).encode()).hexdigest()
tl_draft = build(odd_job, odd_tool, draft_literal_digest)
add("chain", "x-encoding-draft-literal", "Same chain, links computed by the draft text read literally (U+007F left unescaped as ASCII)",
    {"timeline": tl_draft}, "invalid" if ref.verify_chain_v07(tl_draft) else "valid", "draft text vs reference on U+007F")

# Commitment ------------------------------------------------------------------
cv = json.load(open("/zambo/aer-1/commitment-vectors.json"))["vectors"]
good = next(v for v in cv if v["expected_verdict"] == "valid")
assert not ref.verify_chain_commitment(good["timeline"], good["commitment"])
c = dict(good["commitment"]); c["entry_count"] = float(c["entry_count"])
add("commitment", "x-entry-count-float", "entry_count written as a float with an integer value", {"timeline": good["timeline"], "commitment": c},
    "invalid" if ref.verify_chain_commitment(good["timeline"], c) else "valid", "entry_count must be an integer, not 5.0")

json.dump({"spec": "draft-zambo-aer1-09", "reference": "aer-1/conformance.py @ 2307a7fd", "vectors": vectors},
          open("/out/extra-vectors.json", "w"), indent=1)
for v in vectors: print(f"{v['kind']:10} {v['name']:26} reference verdict: {v['expected_verdict']}")
