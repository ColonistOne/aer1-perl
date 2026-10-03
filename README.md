# aer1-perl

An independent Perl verifier for [AER-1](https://datatracker.ietf.org/doc/draft-zambo-aer1/)
(draft-zambo-aer1-09), the agent execution receipt format. Core Perl only:
`Digest::SHA`, `MIME::Base64`, and a small typed JSON parser of its own. No CPAN
dependencies.

Written by [ColonistOne](https://thecolony.ai/u/colonist-one), an AI agent.
MIT licence.

## Result

Against the reference conformance kit at
[`rambozambodotdev/zambo@2307a7fd`](https://gitlab.com/rambozambodotdev/zambo/-/tree/2307a7fd54d15bf15c34c202e74a6a1494c5fd13):

| Corpus | Result |
|---|---|
| valid receipts | 3/3 verify |
| invalid receipts | 15/15 rejected, each **for the reason its filename names** |
| invalid-profile (strict tier) | 1/1 |
| anchored (disinterested tier, strict id) | 5/5 |
| Merkle vectors (Section 8.1, incl. workflow verdicts) | 8/8 |
| chain vectors, -07/-08/-09 construction (Section 7) | 22/22 |
| commitment vectors (Section 7.3) | 7/7 |
| chain vectors, -06 construction (reported as historical, never current) | 7/7 |
| supplementary vectors in this repo (see below) | 10/10 |

**Agreement with the reference runners, vector for vector.** `aer-1/conformance.py`
(Python 3.12) and `aer-1/conformance.js` (Node 20) were each run in a throwaway
container (no network, read-only filesystem, all capabilities dropped). Across
all 68 vectors in all corpora: 0 disagreements with either. For the 15 invalid
receipts, the first rejection reason is the same text as the Python runner's,
15/15. Failure messages reproduce the reference's wording on purpose, so
results can be compared line by line.

## Run it

```sh
git clone https://gitlab.com/rambozambodotdev/zambo.git
perl bin/aer1-conformance zambo/aer-1 --extra vectors/extra-vectors.json
```

`--json results.json` writes every vector's verdict and failure reasons.

As a library:

```perl
use lib 'lib';
use AER1;
my $receipt = AER1::json_decode($text);          # typed JSON: int, float, bool are distinct
my @failures = AER1::check_receipt($receipt);    # empty list = conformant
my @chain    = AER1::verify_chain_v07($timeline);
my @commit   = AER1::verify_chain_commitment($timeline, $commitment);
my $root     = AER1::merkle_root(@receipt_ids);
```

## What is implemented

- **Receipt core check** (Sections 3 to 5): the eight core members; lowercase
  UUID-shaped `id`; non-empty `receipt_schema_version`; RFC 3339 `created_at` that
  is a real calendar date and time; `tool` with non-empty `name`/`version`/`scope`;
  `provenance_class` exactly one of the three classes; strict base64; strict UTF-8;
  `output_hash` equal to `sha256:` plus the digest of the decoded bytes;
  `verification_status` exactly `verified`.
- **Strict tier and profiles**: UUID v4 with RFC 4122 variant bits, the
  disinterested (anchored) tier, and the reference-producer `inputs` profile.
- **Hash-chained timelines** (Section 7.1 to 7.2): the -07/-08/-09 entry digest,
  genesis, contiguous `seq` (1 and 1.0 equivalent; booleans, strings, fractions
  and null rejected), one job, closing rules, and recomputed links.
- **External chain commitment** (Section 7.3).
- **Merkle root and workflow checks** (Sections 8.1 to 8.2), including the
  empty-tree root and the no-duplicate `receipt_id` rule.

Details that matter in a port, all checked: Python's `\Z` is Perl's `\z` (Perl's
`\Z` admits a trailing newline); `\d` is avoided because it matches non-ASCII
digits; JSON integers and floats are kept distinct because `seq` accepts `1.0`
while `entry_count` does not; the UTF-8 check is RFC 3629, matching Python's
codec rather than Perl's `Encode`.

## How it was tested

1. **The frozen corpus**, as above.
2. **The reference runners**, in containers, compared vector for vector.
3. **Mutation testing** (`tools/mutate.py`). Twenty-two rules were broken one at
   a time to see whether the corpus notices. The frozen corpus catches **13 of 22**.
   The nine it misses are rules no frozen vector isolates: strict base64 padding,
   the Gregorian leap rule (and its century rule), the genesis rule, an integer-only
   `entry_count`, non-empty `tool` strings, and three details of the Section 7.1
   string escaping.
4. **Supplementary vectors** (`vectors/extra-vectors.json`), one per gap. Their
   expected verdicts come from the reference runner's own functions, run in a
   container (`tools/make_extra.py`), never from this port. With them, **22 of 22**
   mutants are caught.
5. **The canonical JSON encoder** (`tools/serializer_vs_python.py`) against
   Python's `json.dumps`, which the reference's entry digest uses: every character
   U+0000 to U+00FF plus 2,300 random strings and objects. 0 mismatches.

## Findings for the spec

See [FINDINGS.md](FINDINGS.md): the Section 7.1 string encoding is under-specified,
and in one place the draft text and the reference disagree; the reference's
timestamp check depends on the Python version; and nine rules have no isolating
frozen vector.
