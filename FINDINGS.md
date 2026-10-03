# Findings from an independent Perl implementation of draft-zambo-aer1-09

Checked against `rambozambodotdev/zambo@2307a7fd` (conformance kit corpus
2026-10-01). Each finding names its evidence; the supplementary vectors are in
`vectors/extra-vectors.json`, with expected verdicts taken from the reference
runner's own functions (`aer-1/conformance.py`), not from this port.

## 1. Section 7.1 string escaping is under-specified, and the draft and the reference disagree on U+007F

Section 7.1 says strings in the entry-digest object are "escaped as in Section 7
of [RFC8259], with every non-ASCII character escaped as \uXXXX". The entry digest
is a hash of these bytes, so every choice the text leaves open is a choice two
conforming implementations can make differently and get different digests.

- **U+007F (DEL).** The draft escapes only non-ASCII characters. DEL is ASCII, so
  a reader of the draft leaves it literal. The reference (`json.dumps` with
  `ensure_ascii=True`) escapes it as `\u007f`. Vector `x-encoding-draft-literal`
  is a chain whose links were computed by reading the draft literally; the
  reference runner rejects it. `x-encoding-reference` is the same chain linked
  the reference's way; the reference accepts it.
- **Hex case.** RFC 8259 allows `é` and `é`. The reference emits
  lowercase. The draft does not say.
- **Short escapes.** RFC 8259 allows a newline as `\n` or as `\u000a`. The
  reference emits the short forms for U+0008, U+0009, U+000A, U+000C and U+000D,
  and `\u00XX` for other control characters. The draft does not say.

No frozen vector puts a character needing escaping into a digested field, so the
corpus cannot catch any of these: changing hex case, leaving DEL literal, or
writing `\u000a` for a newline all pass the frozen corpus (`tools/mutate.py`).

**Suggested text:** "Escape `"` and `\` as `\"` and `\\`; U+0008, U+0009, U+000A,
U+000C and U+000D as `\b`, `\t`, `\n`, `\f`, `\r`; and every other code point
outside U+0020 to U+007E, including U+007F, as `\u` followed by four lowercase
hexadecimal digits, using a surrogate pair above U+FFFF. This is the output of
Python's `json.dumps` with `ensure_ascii=True`." Plus a chain vector with such
characters in `tool` or `job_id`, such as `x-encoding-reference`.

## 2. The reference's timestamp check depends on the Python version

`_strict_rfc3339` relies on `datetime.fromisoformat`. Before Python 3.11 that
function accepts fractional seconds of exactly 3 or 6 digits only. Measured in
containers with the reference's own function:

| `created_at` | Python 3.9 | Python 3.12 |
|---|---|---|
| `2026-01-01T00:00:00.1Z` | rejected | accepted |
| `2026-01-01T00:00:00.12Z` | rejected | accepted |
| `2026-01-01T00:00:00.123Z` | accepted | accepted |
| `2026-01-01T00:00:00.1234Z` | rejected | accepted |
| `2026-01-01T00:00:00.1234567Z` | rejected | accepted |

RFC 3339 allows any number of fractional digits (`time-secfrac = "." 1*DIGIT`),
so on Python 3.10 or earlier the tiebreaker rejects conformant receipts. Pinning
Python 3.11+ for the runner, or checking the fraction without `fromisoformat`,
would remove the dependence. Vector `x-fraction-one-digit` (valid) catches it.

## 3. Rules with no isolating frozen vector

Breaking each of these rules in this verifier still passes the whole frozen
corpus; the supplementary vector named in each case fails it.

| Rule | Supplementary vector |
|---|---|
| strict base64: padding required (length a multiple of 4) | `x-base64-unpadded` |
| Gregorian leap rule | `x-feb29-non-leap`, `x-feb29-leap` (control) |
| century rule (1900 is not a leap year) | `x-feb29-1900` |
| genesis: first `prev_digest` is 64 zeros | `x-genesis-single` |
| `entry_count` must be an integer, not `5.0` | `x-entry-count-float` |
| `tool.name`/`version`/`scope` non-empty | `x-tool-empty-name` |
| Section 7.1 escaping (three details) | `x-encoding-reference`, `x-encoding-draft-literal` |

On genesis: `v07-bad-genesis` is rejected even with the genesis check removed,
because a wrong first `prev_digest` also changes entry 0's digest and so breaks
entry 1's link. A single closed entry with a non-zero `prev_digest`
(`x-genesis-single`) has no link to break, so only the genesis rule can reject it.
