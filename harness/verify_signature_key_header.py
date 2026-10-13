"""Signature-Key header parser checked against the signature-key.json vectors.

The header is an RFC 9651 Dictionary keyed by signature label. Each member's
value is a Token naming the scheme, carrying parameters. These vectors are
parser and dispatch cases rather than signature cases: they fix what an AAuth
verifier, which accepts only the jwt scheme from agents, answers for each
shape.

Usage: python3 -I verify_signature_key_header.py <signature-key.json>
"""
import json, re, sys

SUPPORTED = {"jwt"}                     # AAuth PS endpoint, agent-presented
REQUIRED  = {"jwt": {"jwt"}, "jkt-jwt": {"jwt"}, "self-jwt": {"jwt"},
             "jwks_uri": {"id", "dwk", "kid"}, "jwks": {"url", "kid"},
             "hwk": {"kty", "alg"}}

TOKEN = re.compile(r"[A-Za-z*][A-Za-z0-9:/!#$%&'*+\-.^_`|~]*")
KEY   = re.compile(r"[a-z*][a-z0-9_\-.*]*")

class Malformed(Exception):
    pass

def _ws(s, i):
    while i < len(s) and s[i] == " ":
        i += 1
    return i

def _bare(s, i):
    """A bare item: Token, String, or Boolean. Returns (value, kind, i)."""
    if i < len(s) and s[i] == '"':
        j = i + 1
        out = []
        while j < len(s):
            if s[j] == "\\":
                j += 1
                out.append(s[j])
            elif s[j] == '"':
                return "".join(out), "string", j + 1
            else:
                out.append(s[j])
            j += 1
        raise Malformed("unterminated string")
    if i < len(s) and s[i] == "?":
        if s[i + 1] in "01":
            return s[i + 1] == "1", "boolean", i + 2
        raise Malformed("bad boolean")
    m = TOKEN.match(s, i)
    if m:
        return m.group(0), "token", m.end()
    raise Malformed(f"no bare item at offset {i}")

def _params(s, i):
    out = {}
    while i < len(s) and s[i] == ";":
        i = _ws(s, i + 1)
        m = KEY.match(s, i)
        if not m:
            raise Malformed("bad parameter key")
        k, i = m.group(0), m.end()
        if i < len(s) and s[i] == "=":
            v, _, i = _bare(s, i + 1)
        else:
            v = True                     # RFC 9651 4.1.1.2 bare boolean true
        out[k] = v
    return out, i

def parse_dictionary(s):
    i, members = 0, {}
    i = _ws(s, i)
    while i < len(s):
        m = KEY.match(s, i)
        if not m:
            raise Malformed(f"bad dictionary key at offset {i}")
        key, i = m.group(0), m.end()
        if i < len(s) and s[i] == "=":
            value, kind, i = _bare(s, i + 1)
            params, i = _params(s, i)
        else:
            value, kind = True, "boolean"
            params, i = _params(s, i)
        members[key] = {"value": value, "kind": kind, "params": params}
        i = _ws(s, i)
        if i < len(s):
            if s[i] != ",":
                raise Malformed(f"expected comma at offset {i}")
            i = _ws(s, i + 1)
    return members

def evaluate(header, label="sig"):
    """Returns (scheme, params, error)."""
    try:
        members = parse_dictionary(header)
    except Malformed as e:
        return None, None, ("invalid_signature", f"malformed header: {e}")

    if label not in members:
        return None, None, ("invalid_signature",
                            f"no member named {label!r}; present: "
                            f"{sorted(members)}")
    m = members[label]
    if m["kind"] != "token":
        return None, None, ("invalid_signature",
                            f"scheme must be a Token, got a {m['kind']}")
    scheme, params = m["value"], m["params"]
    if scheme not in SUPPORTED:
        return scheme, params, ("unsupported_scheme",
                                f"{scheme!r} not in {sorted(SUPPORTED)}")
    need = REQUIRED.get(scheme, set())
    absent = need - set(params)
    if absent:
        return scheme, params, ("invalid_signature",
                                f"{scheme} requires {sorted(absent)}")
    return scheme, params, None

def main(path):
    d = json.load(open(path))
    cases = d["cases"]
    print(f"{d['kind']} / {d['spec']}\n{len(cases)} cases\n")
    npass = nfail = 0
    notes = []
    for i, c in enumerate(cases, 1):
        scheme, params, err = evaluate(c["header"])
        exp_err = c.get("error")
        got_err = err[0] if err else None
        ok = (got_err == exp_err)
        detail = []
        if ok and "scheme" in c and scheme != c["scheme"]:
            ok, _ = False, detail.append(
                f"scheme {scheme!r} != expected {c['scheme']!r}")
        if ok and "params" in c and params is not None:
            # compare only the string-valued params the fixture records;
            # flag any bare boolean we parsed that it does not list.
            strs = {k: v for k, v in params.items() if not isinstance(v, bool)}
            if strs != c["params"]:
                ok = False
                detail.append(f"params {strs} != expected {c['params']}")
            extra = {k for k, v in params.items() if isinstance(v, bool)}
            if extra - set(c["params"]):
                notes.append(
                    f"case {i}: parsed bare boolean param(s) "
                    f"{sorted(extra - set(c['params']))} that the fixture's "
                    f"'params' does not record")
        npass += ok; nfail += (not ok)
        print(f"  [{'ok  ' if ok else 'FAIL'}] {i}. {c['header'][:62]}")
        print(f"          -> scheme={scheme!r} error={got_err!r} "
              f"(expected {exp_err!r})")
        for dd in detail:
            print(f"          {dd}")
        if err:
            print(f"          reason: {err[1]}")
    print(f"\n  {npass}/{len(cases)} match")
    if notes:
        print("\n  observations, not failures:")
        for n in notes:
            print(f"    - {n}")
    return 0 if nfail == 0 else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
