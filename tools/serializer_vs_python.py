#!/usr/bin/env python3
"""Compare AER1::canonical_json with Python's json.dumps(sort_keys=True,
separators=(",", ":")) (the encoding the reference's entry digest uses) on every
character U+0000..U+00FF plus random strings and objects mixing control,
non-ASCII and astral characters. The frozen corpus never exercises this
encoding, so it is checked here directly.

    python3 tools/serializer_vs_python.py
"""
import json, pathlib, random, subprocess, sys, tempfile

random.seed(20261003)
pool = [chr(c) for c in range(0, 0x100)] + [" ", "€", "￿", "\U0001F600", "\U00010000", "\U0010FFFF", "/", "\\", '"']
cases = [chr(c) for c in range(0, 0x100)]
cases += ["".join(random.choice(pool) for _ in range(random.randint(0, 12))) for _ in range(2000)]
cases += [{random.choice(pool) * random.randint(1, 3): random.choice(pool) for _ in range(random.randint(1, 5))} for _ in range(300)]
here = pathlib.Path(__file__).resolve().parent.parent
with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False) as f:
    for c in cases:
        f.write(json.dumps({"in": c}) + "\t" + json.dumps(c, sort_keys=True, separators=(",", ":")) + "\n")
perl = r'''
open my $fh, "<:raw", $ARGV[0] or die; my ($n, $bad) = (0, 0);
while (my $l = <$fh>) { chomp $l; my ($in, $want) = split /\t/, $l, 2; utf8::decode($in);
  my $got = AER1::canonical_json(AER1::json_decode($in)->{in}); $n++;
  if ($got ne $want) { $bad++; print "MISMATCH want $want got $got\n" if $bad <= 5 } }
print "$n cases, $bad mismatches\n"; exit($bad ? 1 : 0);'''
r = subprocess.run(["perl", f"-I{here / 'lib'}", "-MAER1", "-e", perl, f.name], capture_output=True, text=True)
print(r.stdout.strip() or r.stderr.strip())
sys.exit(r.returncode)
