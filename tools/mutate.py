#!/usr/bin/env python3
"""Mutation test: break one rule in lib/AER1.pm at a time and report whether
the corpus notices. A rule no vector can fail is a rule the corpus does not
test, however many vectors pass.

    python3 tools/mutate.py /path/to/zambo/aer-1 [--extra vectors/extra-vectors.json]
"""
import pathlib, shutil, subprocess, sys, tempfile

MUTANTS = {
    "UUID end anchor \\z -> \\Z (admits a trailing newline)": [("[0-9a-f]{4}-[0-9a-f]{12}\\z/;\nmy $STRICT_UUID_RE", "[0-9a-f]{4}-[0-9a-f]{12}\\Z/;\nmy $STRICT_UUID_RE")],
    "provenance end anchor \\z -> \\Z": [("LOGGED BY AGENT)\\z/;", "LOGGED BY AGENT)\\Z/;")],
    "base64: no length % 4 check": [("$s =~ $B64_RE && length($s) % 4 == 0;", "$s =~ $B64_RE;")],
    "UTF-8 check always passes": [("return $b =~ /\\A(?:[\\x00-\\x7F]", "return 1 || $b =~ /\\A(?:[\\x00-\\x7F]")],
    "calendar: ignore day of month": [("return $d >= 1 && $d <= $dim ? 1 : 0;", "return 1;")],
    "calendar: February always 29": [("$leap ? 29 : 28", "29")],
    "calendar: no century rule": [("my $leap = ($y % 4 == 0 && $y % 100 != 0) || $y % 400 == 0;", "my $leap = $y % 4 == 0;")],
    "offset range unchecked": [("return 0 unless $oh <= 23 && $om <= 59", "1")],
    "entry digest omits tool": [("        tool             => $e->{tool},\n", "")],
    "entry digest keeps seq 1.0 as a float": [("$seq = AER1::Int->new(sprintf '%.0f', $iv) if defined $iv;", "1;")],
    "entry digest: missing close as null": [("exists $e->{close} ? $e->{close} : $FALSE", "exists $e->{close} ? $e->{close} : undef")],
    "chain: no genesis check": [("push @f, 'entry 0 prev_digest is not 64 zero characters' if $pd ne '0' x 64;", "1;")],
    "chain: no job_id check": [("elsif ($e->{job_id} ne $job) { push @f, \"entry $i job_id mixes jobs\" }", "")],
    "chain: boolean seq accepted": [("return 0 + $v->{lex} if is_int($v);", "return 0 + $v->{lex} if is_int($v); return 1 if ref $v eq 'AER1::Bool';")],
    "commitment: entry_count 5.0 accepted": [("unless is_int($cnt);", "unless defined int_value($cnt);"), ("my $n = 0 + $cnt->{lex};", "my $n = int_value($cnt);")],
    "Merkle: no odd-node duplication": [("push @level, $level[-1] if @level % 2;", "1;")],
    "Merkle: empty tree is 64 zeros": [("return sha256_hex('') unless @level;", "return '0' x 64 unless @level;")],
    "workflow: duplicate receipt_id allowed": [("if ($seen{$s->{receipt_id}}++)", "if (0)")],
    "escape: uppercase \\u hex": [("else { $o .= sprintf('\\\\u%04x', $n) }", "else { $o .= sprintf('\\\\u%04X', $n) }")],
    "escape: U+007F left literal": [("elsif ($n >= 0x20 && $n <= 0x7E)", "elsif ($n >= 0x20 && $n <= 0x7F)")],
    "escape: newline as \\u000a": [("elsif ($n == 10) { $o .= '\\\\n' }", "elsif ($n == 10) { $o .= '\\\\u000a' }")],
    "tool: empty strings allowed": [("unless is_obj($t) && !grep { !ne_str($t->{$_}) }", "unless is_obj($t) && !grep { !is_str($t->{$_}) }")],
}

def main():
    here = pathlib.Path(__file__).resolve().parent.parent
    corpus = sys.argv[1]
    args = [corpus] + (["--extra", sys.argv[sys.argv.index("--extra") + 1]] if "--extra" in sys.argv else [])
    src = (here / "lib" / "AER1.pm").read_text()
    survived = 0
    for name, pairs in MUTANTS.items():
        mutated = src
        for old, new in pairs:
            if mutated.count(old) != 1:
                sys.exit(f"mutant '{name}': pattern not found exactly once; update tools/mutate.py")
            mutated = mutated.replace(old, new)
        d = pathlib.Path(tempfile.mkdtemp())
        try:
            (d / "lib").mkdir(); shutil.copytree(here / "bin", d / "bin")
            (d / "lib" / "AER1.pm").write_text(mutated)
            r = subprocess.run(["perl", str(d / "bin" / "aer1-conformance"), *args], capture_output=True, text=True, cwd=here)
        finally:
            shutil.rmtree(d)
        caught = [l.split(": FAIL")[0].split("] ")[-1].strip() for l in r.stdout.splitlines() if ": FAIL" in l]
        survived += r.returncode == 0
        print(f"{'caught  ' if r.returncode else 'SURVIVED'} | {name:44} | {', '.join(caught[:3])}")
    print(f"\n{len(MUTANTS) - survived}/{len(MUTANTS)} mutants caught")
    return 1 if survived else 0

if __name__ == "__main__":
    sys.exit(main())
