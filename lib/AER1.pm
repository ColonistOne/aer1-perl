package AER1;

# AER-1 verifier (draft-zambo-aer1-09), core Perl only.
#
# Covers: receipt core check (Section 3-4), provenance classes (Section 5),
# the -07/-08/-09 hash-chained timeline (Section 7.1-7.2), the -09 external
# chain commitment (Section 7.3), the Section 8.1 Merkle root, and the
# offline workflow checks (Section 8.2 steps 3-4). Also the optional
# strict-id/disinterested tier, the reference-producer profile, and the
# historical -06 chain construction (reported as historical, never current).
#
# Failure messages reproduce the reference runner's (aer-1/conformance.py)
# word for word, so results can be compared vector for vector and so the
# workflow `rejected_by` substrings match.

use strict;
use warnings;
use Digest::SHA qw(sha256 sha256_hex);
use MIME::Base64 ();

our $VERSION = '0.1.0';

# ---------------------------------------------------------------------------
# Typed JSON. Python's json module distinguishes int from float and both from
# bool; AER-1's rules depend on that (seq accepts 1.0, entry_count does not),
# so values are parsed into explicit types rather than Perl scalars whose
# numeric/string nature is implicit.
#   object -> HASH ref     array -> ARRAY ref     string -> plain scalar
#   int    -> AER1::Int    float -> AER1::Float   true/false -> AER1::Bool
#   null   -> undef  (presence is tested with exists, as Python's `in`)
# ---------------------------------------------------------------------------

package AER1::Int;   sub new { my ($c, $lex) = @_; bless { lex => $lex }, $c }
package AER1::Float; sub new { my ($c, $num) = @_; bless { v => $num }, $c }
package AER1::Bool;  sub new { my ($c, $b) = @_; bless { b => $b ? 1 : 0 }, $c }
package AER1;

our $TRUE  = AER1::Bool->new(1);
our $FALSE = AER1::Bool->new(0);

sub json_decode {
    my ($text) = @_;            # a character string
    my $pos = 0;
    my $v = _j_value(\$text, \$pos);
    _j_ws(\$text, \$pos);
    die "JSON: trailing data at $pos\n" if $pos < length $text;
    return $v;
}

sub _j_ws { my ($s, $p) = @_; pos($$s) = $$p; $$s =~ /\G[ \t\n\r]*/gc; $$p = pos($$s) }

sub _j_value {
    my ($s, $p) = @_;
    _j_ws($s, $p);
    pos($$s) = $$p;
    if ($$s =~ /\G\{/gc) {
        $$p = pos($$s);
        my %h;
        _j_ws($s, $p); pos($$s) = $$p;
        if ($$s =~ /\G\}/gc) { $$p = pos($$s); return \%h }
        while (1) {
            _j_ws($s, $p); pos($$s) = $$p;
            die "JSON: expected key at $$p\n" unless $$s =~ /\G"/gc;
            $$p = pos($$s);
            my $k = _j_string($s, $p);
            _j_ws($s, $p); pos($$s) = $$p;
            die "JSON: expected ':' at $$p\n" unless $$s =~ /\G:/gc;
            $$p = pos($$s);
            $h{$k} = _j_value($s, $p);      # duplicate keys: last wins (as Python)
            _j_ws($s, $p); pos($$s) = $$p;
            if ($$s =~ /\G,/gc) { $$p = pos($$s); next }
            if ($$s =~ /\G\}/gc) { $$p = pos($$s); return \%h }
            die "JSON: expected ',' or '}' at $$p\n";
        }
    }
    if ($$s =~ /\G\[/gc) {
        $$p = pos($$s);
        my @a;
        _j_ws($s, $p); pos($$s) = $$p;
        if ($$s =~ /\G\]/gc) { $$p = pos($$s); return \@a }
        while (1) {
            push @a, _j_value($s, $p);
            _j_ws($s, $p); pos($$s) = $$p;
            if ($$s =~ /\G,/gc) { $$p = pos($$s); next }
            if ($$s =~ /\G\]/gc) { $$p = pos($$s); return \@a }
            die "JSON: expected ',' or ']' at $$p\n";
        }
    }
    if ($$s =~ /\G"/gc) { $$p = pos($$s); return _j_string($s, $p) }
    if ($$s =~ /\Gtrue/gc)  { $$p = pos($$s); return $TRUE }
    if ($$s =~ /\Gfalse/gc) { $$p = pos($$s); return $FALSE }
    if ($$s =~ /\Gnull/gc)  { $$p = pos($$s); return undef }
    if ($$s =~ /\G(-?(?:0|[1-9][0-9]*))((?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/gc) {
        my ($int, $rest) = ($1, $2);
        $$p = pos($$s);
        return length $rest ? AER1::Float->new(0 + ($int . $rest)) : AER1::Int->new($int);
    }
    die "JSON: unexpected input at $$p\n";
}

sub _j_string {
    my ($s, $p) = @_;     # position is just after the opening quote
    my $out = '';
    pos($$s) = $$p;
    while (1) {
        if ($$s =~ /\G([^"\\\x00-\x1f]+)/gc) { $out .= $1; next }
        if ($$s =~ /\G"/gc) { $$p = pos($$s); return $out }
        if ($$s =~ /\G\\(["\\\/bfnrt])/gc) {
            $out .= { '"' => '"', '\\' => '\\', '/' => '/', b => "\b", f => "\f",
                      n => "\n", r => "\r", t => "\t" }->{$1};
            next;
        }
        if ($$s =~ /\G\\u([0-9a-fA-F]{4})/gc) {
            my $cp = hex $1;
            # A high surrogate followed by an escaped low surrogate combines
            # into one character, as Python's decoder does; lone surrogates
            # are kept as-is.
            if ($cp >= 0xD800 && $cp <= 0xDBFF && $$s =~ /\G\\u(d[c-f][0-9a-f]{2})/gci) {
                $cp = 0x10000 + (($cp - 0xD800) << 10) + (hex($1) - 0xDC00);
            }
            no warnings qw(surrogate nonchar non_unicode);
            $out .= chr $cp;
            next;
        }
        die "JSON: bad string at " . pos($$s) . "\n";
    }
}

# Python json.dumps(obj, sort_keys=True, separators=(",", ":")) with the
# default ensure_ascii=True: every character outside ' '..'~' is escaped,
# non-ASCII as lowercase \uXXXX (surrogate pairs above the BMP).
sub canonical_json {
    my ($v) = @_;
    return 'null' unless defined $v;
    my $r = ref $v;
    return _py_str($v) if !$r;
    return $v->{b} ? 'true' : 'false' if $r eq 'AER1::Bool';
    return _py_int($v->{lex}) if $r eq 'AER1::Int';
    return _py_float_repr($v->{v}) if $r eq 'AER1::Float';
    return '[' . join(',', map { canonical_json($_) } @$v) . ']' if $r eq 'ARRAY';
    if ($r eq 'HASH') {
        return '{' . join(',', map { _py_str($_) . ':' . canonical_json($v->{$_}) }
                                sort keys %$v) . '}';
    }
    die "canonical_json: unsupported value\n";
}

sub _py_int { my ($lex) = @_; $lex =~ s/^-0+$/0/; return $lex }

sub _py_str {
    my ($s) = @_;
    my $o = '"';
    for my $ch (split //, $s) {
        my $n = ord $ch;
        if    ($ch eq '\\') { $o .= '\\\\' }
        elsif ($ch eq '"')  { $o .= '\\"' }
        elsif ($n == 8)  { $o .= '\\b' }
        elsif ($n == 12) { $o .= '\\f' }
        elsif ($n == 10) { $o .= '\\n' }
        elsif ($n == 13) { $o .= '\\r' }
        elsif ($n == 9)  { $o .= '\\t' }
        elsif ($n >= 0x20 && $n <= 0x7E) { $o .= $ch }
        elsif ($n > 0xFFFF) {
            my $m = $n - 0x10000;
            $o .= sprintf('\\u%04x\\u%04x', 0xD800 | (($m >> 10) & 0x3FF), 0xDC00 | ($m & 0x3FF));
        }
        else { $o .= sprintf('\\u%04x', $n) }
    }
    return $o . '"';
}

# Python's repr(float): the shortest digits that round-trip, fixed notation
# for exponents -4..15, otherwise d.ddde+XX. Only reached for non-integer
# seq values on paths that digest without type checks.
sub _py_float_repr {
    my ($x) = @_;
    return 'NaN' if $x != $x;
    return $x > 0 ? 'Infinity' : '-Infinity' if $x * 0 != 0;
    my $g;
    for my $p (1 .. 17) { $g = sprintf('%.*e', $p - 1, $x); last if 0 + $g == $x }
    my ($mant, $exp) = $g =~ /^(-?[0-9.]+)e([+-][0-9]+)$/;
    $exp = 0 + $exp;
    my ($sign, $digits) = $mant =~ /^(-?)(.*)$/;
    $digits =~ s/\.//; $digits =~ s/0+$//; $digits = '0' if $digits eq '';
    if ($exp >= -4 && $exp < 16) {
        my $pt = $exp + 1;
        my $str = $pt <= 0 ? '0.' . ('0' x -$pt) . $digits
                : $pt >= length $digits ? $digits . ('0' x ($pt - length $digits)) . '.0'
                : substr($digits, 0, $pt) . '.' . substr($digits, $pt);
        return $sign . $str;
    }
    my $m = length $digits > 1 ? substr($digits, 0, 1) . '.' . substr($digits, 1) : $digits;
    return sprintf('%s%se%s%02d', $sign, $m, $exp < 0 ? '-' : '+', abs $exp);
}

# --------------------------------------------------------------------------
# Type predicates mirroring the reference runner's isinstance() checks.
# --------------------------------------------------------------------------
sub is_str  { defined $_[0] && !ref $_[0] }
sub is_obj  { ref $_[0] eq 'HASH' }
sub is_arr  { ref $_[0] eq 'ARRAY' }
sub is_bool { ref $_[0] eq 'AER1::Bool' }
sub is_true { is_bool($_[0]) && $_[0]{b} }
sub is_int  { ref $_[0] eq 'AER1::Int' }                       # Python int, never bool
sub ne_str  { is_str($_[0]) && length $_[0] }                  # non-empty str
# seq rule: an int, or a float with an integer value; never a bool.
sub int_value {
    my ($v) = @_;
    return 0 + $v->{lex} if is_int($v);
    if (ref $v eq 'AER1::Float') {
        my $x = $v->{v};
        return $x if $x == $x && $x * 0 == 0 && $x == int $x;
    }
    return undef;
}

# --------------------------------------------------------------------------
# Primitives.
# --------------------------------------------------------------------------
my $UUID_RE        = qr/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/;
my $STRICT_UUID_RE = qr/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/;
my $RFC3339_RE     = qr/\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?(Z|[+-]([0-9]{2}):([0-9]{2}))\z/;
my $HASH_RE        = qr/\Asha256:[0-9a-f]{64}\z/;
my $HEX64_RE       = qr/\A[0-9a-f]{64}\z/;
my $PROV_RE        = qr/\A(?:EXECUTED BY [A-Z0-9][A-Z0-9 ._-]*|OBSERVED VIA GATEWAY|LOGGED BY AGENT)\z/;
my $B64_RE         = qr/\A[A-Za-z0-9+\/]*={0,2}\z/;

sub rfc3339_shape { is_str($_[0]) && $_[0] =~ $RFC3339_RE }

# Shape, then offset range (HH 00-23, MM 00-59), then a real calendar
# date/time: year 1-9999, Gregorian leap years, second 0-59 (no leap second),
# any number of fractional digits. Mirrors _strict_rfc3339 on Python 3.11+.
sub rfc3339_strict {
    my ($s) = @_;
    return 0 unless is_str($s);
    my ($y, $mo, $d, $h, $mi, $se, $z, $oh, $om) = $s =~ $RFC3339_RE or return 0;
    if ($z ne 'Z') { return 0 unless $oh <= 23 && $om <= 59 }
    return 0 unless $y >= 1 && $mo >= 1 && $mo <= 12 && $h <= 23 && $mi <= 59 && $se <= 59;
    my $leap = ($y % 4 == 0 && $y % 100 != 0) || $y % 400 == 0;
    my $dim = (31, $leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[$mo - 1];
    return $d >= 1 && $d <= $dim ? 1 : 0;
}

# Strict base64: the reference regex plus correct padding (length % 4 == 0),
# as Python's b64decode(validate=True). Returns the bytes, or undef.
sub b64_strict {
    my ($s) = @_;
    return undef unless is_str($s) && $s =~ $B64_RE && length($s) % 4 == 0;
    return MIME::Base64::decode_base64($s);
}

# RFC 3629 well-formed UTF-8 (rejects overlongs, surrogates, > U+10FFFF;
# accepts noncharacters), which is what Python's utf-8 codec accepts.
sub utf8_valid {
    my ($b) = @_;
    return $b =~ /\A(?:[\x00-\x7F]
                      |[\xC2-\xDF][\x80-\xBF]
                      |\xE0[\xA0-\xBF][\x80-\xBF]
                      |[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}
                      |\xED[\x80-\x9F][\x80-\xBF]
                      |\xF0[\x90-\xBF][\x80-\xBF]{2}
                      |[\xF1-\xF3][\x80-\xBF]{3}
                      |\xF4[\x80-\x8F][\x80-\xBF]{2})*\z/x ? 1 : 0;
}

sub _utf8_bytes { my ($s) = @_; utf8::encode($s); return $s }

# --------------------------------------------------------------------------
# Section 3-5: the receipt core check. Returns a list of failure reasons;
# an empty list means conformant.
# --------------------------------------------------------------------------
my @CORE = qw(id receipt_schema_version created_at tool provenance_class
              canonical_bytes output_hash verification_status);

sub check_receipt {
    my ($r) = @_;
    return ('receipt is not a JSON object') unless is_obj($r);
    my @f;
    for my $m (@CORE) { push @f, "missing required member: $m" unless exists $r->{$m} }
    return @f if @f;
    push @f, 'id is not a lowercase UUID' unless is_str($r->{id}) && $r->{id} =~ $UUID_RE;
    push @f, 'receipt_schema_version is not a non-empty string' unless ne_str($r->{receipt_schema_version});
    my $ca = $r->{created_at};
    if    (!is_str($ca))         { push @f, 'created_at is not a string' }
    elsif (!rfc3339_shape($ca))  { push @f, 'created_at is not RFC 3339' }
    elsif (!rfc3339_strict($ca)) { push @f, 'created_at is not a valid calendar date/time' }
    my $t = $r->{tool};
    push @f, 'tool is not an object with name/version/scope strings'
        unless is_obj($t) && !grep { !ne_str($t->{$_}) } qw(name version scope);
    push @f, 'provenance_class is not a known class'
        unless is_str($r->{provenance_class}) && $r->{provenance_class} =~ $PROV_RE;
    my $raw = b64_strict($r->{canonical_bytes});
    if (!defined $raw) { push @f, 'canonical_bytes is not valid base64' }
    elsif (!utf8_valid($raw)) { push @f, 'canonical_bytes is not valid UTF-8'; $raw = undef }
    my $oh = $r->{output_hash};
    if (!is_str($oh) || $oh !~ $HASH_RE) { push @f, 'output_hash is not sha256: + lowercase hex digest' }
    elsif (defined $raw && $oh ne 'sha256:' . sha256_hex($raw)) {
        push @f, 'output_hash does not match sha256(canonical_bytes)';
    }
    push @f, 'verification_status is not verified'
        unless is_str($r->{verification_status}) && $r->{verification_status} eq 'verified';
    return @f;
}

# Reference-producer profile: the canonical payload is a JSON object that
# carries `inputs`. Core-valid receipts may fail this; interop verifiers
# MUST still accept them.
sub check_reference_profile {
    my ($r) = @_;
    return ('receipt is not a JSON object') unless is_obj($r);
    my $cb = $r->{canonical_bytes};
    return ('canonical_bytes is not a string') unless is_str($cb);
    # Python: b64decode(validate=True) without the regex pre-check.
    my $raw = ($cb =~ /\A[A-Za-z0-9+\/]*={0,2}\z/ && length($cb) % 4 == 0) ? MIME::Base64::decode_base64($cb) : undef;
    return ('canonical_bytes is not valid base64') unless defined $raw;
    return ('canonical_bytes is not valid UTF-8') unless utf8_valid($raw);
    my $text = $raw; utf8::decode($text);
    my $payload = eval { json_decode($text) };
    return ('canonical payload is not JSON') if $@;
    return ('canonical payload is not a JSON object') unless is_obj($payload);
    return ("reference-producer payload omits the 'inputs' member") unless exists $payload->{inputs};
    return ();
}

# Optional disinterested (anchored) tier, with the -09 strict id profile.
sub check_disinterested_tier {
    my ($r) = @_;
    my @f;
    my $rid = is_obj($r) ? $r->{id} : undef;
    push @f, 'id is not a UUID v4 (strict profile)' unless is_str($rid) && $rid =~ $STRICT_UUID_RE;
    my $a = is_obj($r) ? $r->{anchor} : undef;
    return ('anchor is not an object') unless is_obj($a);
    my @k = sort keys %$a;
    push @f, 'anchor has members other than log/leaf_hash/anchored_at/proof'
        unless "@k" eq 'anchored_at leaf_hash log proof';
    push @f, 'anchor.log is not a non-empty string' unless ne_str($a->{log});
    my $leaf = $a->{leaf_hash};
    if (!is_str($leaf) || $leaf !~ $HASH_RE) {
        push @f, 'anchor.leaf_hash is not sha256: + lowercase hex digest';
    } else {
        my $cb = $r->{canonical_bytes};
        my $raw;
        if (!is_str($cb) || $cb !~ $B64_RE) { push @f, 'canonical_bytes is not valid base64' }
        else {
            $raw = b64_strict($cb);
            push @f, 'canonical_bytes is not valid UTF-8 base64' if !defined $raw || !utf8_valid($raw);
        }
        push @f, 'anchor.leaf_hash does not match canonical_bytes'
            if defined $raw && $leaf ne 'sha256:' . sha256_hex($raw);
    }
    my $at = $a->{anchored_at};
    if    (!rfc3339_shape($at))  { push @f, 'anchor.anchored_at is not RFC 3339' }
    elsif (!rfc3339_strict($at)) { push @f, 'anchor.anchored_at is not a valid calendar date/time' }
    push @f, 'anchor.proof is not an object' unless is_obj($a->{proof});
    return @f;
}

# --------------------------------------------------------------------------
# Section 7.1: the entry digest. SHA-256 over the UTF-8 bytes of the
# canonical JSON object {close, id, job_id, output_hash, prev_digest,
# provenance_class, seq, tool}; a missing close digests as false; seq in
# integer form. Dies on bad base64 or a missing member (fail closed).
# --------------------------------------------------------------------------
sub entry_digest {
    my ($e) = @_;
    die "entry is not an object\n" unless is_obj($e);
    my $raw = b64_strict($e->{canonical_bytes});
    die "canonical_bytes is not valid base64\n" unless defined $raw;
    for my $m (qw(prev_digest seq job_id id tool provenance_class)) {
        die "'$m'\n" unless exists $e->{$m};
    }
    my $seq = $e->{seq};
    if (ref $seq eq 'AER1::Float') {
        my $iv = int_value($seq);
        $seq = AER1::Int->new(sprintf '%.0f', $iv) if defined $iv;
    }
    my %payload = (
        prev_digest      => $e->{prev_digest},
        seq              => $seq,
        job_id           => $e->{job_id},
        close            => exists $e->{close} ? $e->{close} : $FALSE,
        id               => $e->{id},
        tool             => $e->{tool},
        provenance_class => $e->{provenance_class},
        output_hash      => sha256_hex($raw),
    );
    return sha256_hex(_utf8_bytes(canonical_json(\%payload)));
}

# Section 7.2: chain rules for the -07/-08/-09 construction.
sub verify_chain_v07 {
    my ($tl) = @_;
    return ('timeline is not a non-empty list') unless is_arr($tl) && @$tl;
    my @f;
    my ($job, $prev);
    for my $i (0 .. $#$tl) {
        my $e = $tl->[$i];
        return ("entry $i is not an object") unless is_obj($e);
        my $cb = $e->{canonical_bytes};
        return ("entry $i canonical_bytes is not valid base64") unless defined b64_strict($cb);
        for my $m (qw(id tool provenance_class job_id prev_digest)) {
            return ("entry $i missing $m") unless ne_str($e->{$m});
        }
        my $seq = int_value($e->{seq});
        return ("entry $i seq is not an integer") unless defined $seq;
        push @f, sprintf('entry %d seq %d breaks contiguity (expected %d)', $i, $seq, $i + 1)
            if $seq != $i + 1;
        if (!defined $job) { $job = $e->{job_id} }
        elsif ($e->{job_id} ne $job) { push @f, "entry $i job_id mixes jobs" }
        my $pd = $e->{prev_digest};
        if ($i == 0) {
            push @f, 'entry 0 prev_digest is not 64 zero characters' if $pd ne '0' x 64;
        } elsif ($pd ne $prev) {
            push @f, sprintf('entry %d prev_digest does not match the digest of entry %d', $i, $i - 1);
        }
        if (exists $e->{close} && !is_bool($e->{close})) {
            push @f, "entry $i close is not a boolean";
        } elsif ($i < $#$tl && is_true($e->{close})) {
            push @f, "entry $i carries close:true before the last entry";
        }
        $prev = entry_digest($e);
    }
    my $last = $tl->[-1];
    push @f, 'last entry does not carry close: true' unless is_obj($last) && is_true($last->{close});
    return @f;
}

# The -06 construction (digest = SHA-256 of the decoded canonical_bytes only).
# Retained for historical chains, which MUST NOT be reported as verifying
# under the current construction (draft Section 7.4).
sub verify_chain_v06_historical {
    my ($tl) = @_;
    return ('timeline is not a non-empty list') unless is_arr($tl) && @$tl;
    my @f;
    my $prev;
    for my $i (0 .. $#$tl) {
        my $e = $tl->[$i];
        if (!is_obj($e)) { push @f, "entry $i is not an object"; last }
        my $raw = b64_strict($e->{canonical_bytes});
        if (!defined $raw) { push @f, "entry $i canonical_bytes is not valid base64"; last }
        my $pd = $e->{prev_digest};
        if ($i == 0) {
            push @f, 'entry 0 prev_digest is not 64 zero characters' unless is_str($pd) && $pd eq '0' x 64;
        } elsif (!is_str($pd) || $pd ne $prev) {
            push @f, sprintf('entry %d prev_digest does not match the digest of entry %d', $i, $i - 1);
        }
        $prev = sha256_hex($raw);
    }
    my $last = $tl->[-1];
    push @f, 'last entry does not carry close: true' if is_obj($last) && !is_true($last->{close});
    return @f;
}

# Section 7.3 (-09): the external chain commitment.
sub verify_chain_commitment {
    my ($tl, $c) = @_;
    return ('timeline is not a non-empty list') unless is_arr($tl) && @$tl;
    return ('commitment is not a JSON object') unless is_obj($c);
    my @f;
    my $job = $c->{job_id};
    push @f, 'commitment job_id is not a non-empty string' unless ne_str($job);
    my $dg = $c->{final_entry_digest};
    push @f, 'commitment final_entry_digest is not 64 lowercase hex characters'
        unless is_str($dg) && $dg =~ /\A[0-9a-f]{64}\n?\z/;      # Python's `$` admits one final \n
    my $cnt = $c->{entry_count};
    push @f, 'commitment entry_count is not an integer' unless is_int($cnt);
    my $pub = $c->{published_at};
    if    (!rfc3339_shape($pub))  { push @f, 'commitment published_at is not RFC 3339' }
    elsif (!rfc3339_strict($pub)) { push @f, 'commitment published_at is not a valid calendar date/time' }
    return @f if @f;
    my $n = 0 + $cnt->{lex};
    push @f, sprintf('commitment entry_count %d does not match the timeline length %d', $n, scalar @$tl)
        if $n != @$tl;
    for my $i (0 .. $#$tl) {
        my $e = $tl->[$i];
        if (!is_obj($e) || !ne_str($e->{job_id})) { push @f, "entry $i has no usable job_id" }
        elsif ($e->{job_id} ne $job) { push @f, "entry $i job_id does not match the commitment job_id" }
    }
    my $want = eval { entry_digest($tl->[-1]) };
    if ($@) { chomp(my $err = $@); push @f, "final entry digest could not be recomputed: $err" }
    elsif ($dg ne $want) { push @f, 'commitment final_entry_digest does not match the recomputed digest of the last entry' }
    return @f;
}

# --------------------------------------------------------------------------
# Section 8.1: the Merkle root. Leaf = SHA-256 of the UTF-8 receipt id;
# node = SHA-256(left || right) over raw 32-byte digests; an odd last node
# is duplicated; the empty tree is SHA-256 of the empty input.
# --------------------------------------------------------------------------
sub merkle_root_from_digests {
    my (@level) = @_;
    return sha256_hex('') unless @level;
    while (@level > 1) {
        push @level, $level[-1] if @level % 2;
        @level = map { sha256($level[2 * $_] . $level[2 * $_ + 1]) } 0 .. @level / 2 - 1;
    }
    return unpack 'H*', $level[0];
}

sub merkle_root { my (@ids) = @_; merkle_root_from_digests(map { sha256(_utf8_bytes($_)) } @ids) }

# Section 8.2 steps 3-4: offline workflow verification.
sub verify_workflow {
    my ($w) = @_;
    return ('workflow is not a JSON object') unless is_obj($w);
    my @f;
    push @f, 'workflow type is not "verifiable-workflow-receipt"'
        unless is_str($w->{type}) && $w->{type} eq 'verifiable-workflow-receipt';
    push @f, 'workflow version is not a non-empty string' unless ne_str($w->{version});
    push @f, 'workflow workflow_id is not a lowercase UUID' unless is_str($w->{workflow_id}) && $w->{workflow_id} =~ $UUID_RE;
    push @f, 'workflow receipt_id is not a lowercase UUID' unless is_str($w->{receipt_id}) && $w->{receipt_id} =~ $UUID_RE;
    push @f, 'workflow session_id is not a non-empty string' unless ne_str($w->{session_id});
    push @f, 'workflow goal is not a non-empty string' unless ne_str($w->{goal});
    push @f, 'workflow status is not a non-empty string' unless ne_str($w->{status});
    push @f, 'workflow output_hash is not a 64-char lowercase hex SHA-256 digest'
        unless is_str($w->{output_hash}) && $w->{output_hash} =~ $HEX64_RE;
    push @f, 'workflow verify_url is not an http(s) URL string'
        unless is_str($w->{verify_url}) && $w->{verify_url} =~ /\Ahttps?:\/\//;
    my $steps = $w->{steps};
    unless (is_arr($steps) && @$steps) { push @f, 'workflow steps is not a non-empty list'; return @f }
    for my $i (0 .. $#$steps) {
        my $s = $steps->[$i];
        my $n = $i + 1;
        unless (is_obj($s)) { push @f, "step $n is not an object"; next }
        push @f, "step $n seq is not an integer" unless defined int_value($s->{seq});
        push @f, "step $n receipt_id is not a string" unless is_str($s->{receipt_id});
        push @f, "step $n tool is not a non-empty string" unless ne_str($s->{tool});
        push @f, "step $n receipt_hash is not a 64-char lowercase hex SHA-256 digest"
            unless is_str($s->{receipt_hash}) && $s->{receipt_hash} =~ $HEX64_RE;
        push @f, "step $n started_at is not a valid RFC 3339 timestamp" unless rfc3339_strict($s->{started_at});
        push @f, "step $n ended_at is not a valid RFC 3339 timestamp" unless rfc3339_strict($s->{ended_at});
        push @f, "step $n status is not a non-empty string" unless ne_str($s->{status});
    }
    return @f if @f;
    my $n = @$steps;
    for my $i (0 .. $#$steps) {
        my $seq = int_value($steps->[$i]{seq});
        if ($seq != $i + 1) {
            my $shown = ref $steps->[$i]{seq} eq 'AER1::Float' ? _py_float_repr($steps->[$i]{seq}{v}) : $steps->[$i]{seq}{lex};
            push @f, "step seq values are not 1..$n in order (index $i carries seq $shown)";
            last;
        }
    }
    my %seen;
    for my $s (@$steps) {
        if ($seen{$s->{receipt_id}}++) { push @f, "duplicate receipt_id: $s->{receipt_id}"; last }
    }
    my $root = merkle_root(map { $_->{receipt_id} } @$steps);
    push @f, 'merkle_root does not match the recomputed Section 8.1 root'
        unless is_str($w->{merkle_root}) && $w->{merkle_root} eq $root;
    return @f;
}

1;
