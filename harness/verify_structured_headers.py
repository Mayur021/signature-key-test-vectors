"""RFC 9651 parse and canonical re-serialize, against the AAuth fixtures.

Covers testdata/vectors/signature-error.json and requirement.json. Each case
carries a `canonical` flag, which is true when the header as written is already
the canonical serialization of what it parses to. Re-serializing and comparing
is therefore the test, and it exercises the serializer as well as the parser.

Usage: python3 -I verify_structured_headers.py <signature-error.json> [requirement.json]
"""
import json, re, sys

TOKEN = re.compile(r"[A-Za-z*][A-Za-z0-9:/!#$%&'*+\-.^_`|~]*")
KEY   = re.compile(r"[a-z*][a-z0-9_\-.*]*")

class Malformed(Exception):
    pass

def _ws(s, i):
    while i < len(s) and s[i] == " ":
        i += 1
    return i

def _bare(s, i):
    if s[i] == '"':
        j, out = i + 1, []
        while j < len(s):
            if s[j] == "\\":
                j += 1; out.append(s[j])
            elif s[j] == '"':
                return ("".join(out), "string", j + 1)
            else:
                out.append(s[j])
            j += 1
        raise Malformed("unterminated string")
    if s[i] == "?":
        if s[i + 1] in "01":
            return (s[i + 1] == "1", "boolean", i + 2)
        raise Malformed("bad boolean")
    m = TOKEN.match(s, i)
    if m:
        return (m.group(0), "token", m.end())
    raise Malformed(f"no bare item at {i}")

def _params(s, i):
    out = {}
    while i < len(s) and s[i] == ";":
        i = _ws(s, i + 1)
        m = KEY.match(s, i)
        if not m:
            raise Malformed("bad param key")
        k, i = m.group(0), m.end()
        if i < len(s) and s[i] == "=":
            v, kind, i = _bare(s, i + 1)
        else:
            v, kind = True, "boolean"
        out[k] = (v, kind)
    return out, i

def _inner_list(s, i):
    """RFC 9651 3.1.1 Inner List."""
    assert s[i] == "("
    i = _ws(s, i + 1)
    items = []
    while i < len(s) and s[i] != ")":
        v, kind, i = _bare(s, i)
        p, i = _params(s, i)
        items.append((v, kind, p))
        i = _ws(s, i)
    if i >= len(s):
        raise Malformed("unterminated inner list")
    i += 1                                   # past ')'
    p, i = _params(s, i)
    return (items, p), i

def parse_dict(s):
    i, out = _ws(s, 0), {}
    while i < len(s):
        m = KEY.match(s, i)
        if not m:
            raise Malformed(f"bad key at {i}")
        k, i = m.group(0), m.end()
        if i < len(s) and s[i] == "=":
            i += 1
            if s[i] == "(":
                (items, lp), i = _inner_list(s, i)
                out[k] = {"kind": "innerlist", "value": items, "params": lp}
            else:
                v, kind, i = _bare(s, i)
                p, i = _params(s, i)
                out[k] = {"kind": kind, "value": v, "params": p}
        else:
            p, i = _params(s, i)
            out[k] = {"kind": "boolean", "value": True, "params": p}
        i = _ws(s, i)
        if i < len(s):
            if s[i] != ",":
                raise Malformed(f"expected comma at {i}")
            i = _ws(s, i + 1)
    return out

def ser_bare(v, kind):
    if kind == "string":
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if kind == "boolean":
        return "?1" if v else "?0"
    return str(v)

def ser_params(p, sep=";"):
    out = ""
    for k, (v, kind) in p.items():
        out += sep + k if (kind == "boolean" and v is True) else \
               sep + k + "=" + ser_bare(v, kind)
    return out

def ser_dict(d, sep=";"):
    parts = []
    for k, m in d.items():
        if m["kind"] == "innerlist":
            inner = " ".join(ser_bare(v, kd) + ser_params(pp, sep)
                             for v, kd, pp in m["value"])
            parts.append(f"{k}=({inner}){ser_params(m['params'], sep)}")
        elif m["kind"] == "boolean" and m["value"] is True and not m["params"]:
            parts.append(k)
        else:
            parts.append(k + "=" + ser_bare(m["value"], m["kind"])
                         + ser_params(m["params"], sep))
    return ", ".join(parts)

# ---------------------------------------------------------------- runners
def run_signature_error(path):
    d = json.load(open(path))
    print(f"signature-error / {d.get('spec')}\n{len(d['cases'])} cases\n")
    npass = nfail = 0
    for i, c in enumerate(d["cases"], 1):
        detail = []
        try:
            m = parse_dict(c["header"])
            code = m["error"]["value"] if "error" in m else None
            ok = code == c["code"]
            if not ok:
                detail.append(f"code {code!r} != {c['code']!r}")
            if "required_input" in c:
                got = [v for v, k, p in m["required_input"]["value"]]
                if got != c["required_input"]:
                    ok = False; detail.append(f"required_input {got} != {c['required_input']}")
            # canonical: does re-serializing reproduce the input exactly
            canon = ser_dict(m)
            is_canon = canon == c["header"]
            if is_canon != c["canonical"]:
                ok = False
                detail.append(f"canonical {is_canon} != {c['canonical']}")
                detail.append(f"reserialized: {canon}")
        except Malformed as e:
            ok = False; detail.append(f"parse failed: {e}")
        npass += ok; nfail += (not ok)
        print(f"  [{'ok  ' if ok else 'FAIL'}] {i}. {c['header'][:66]}")
        for x in detail:
            print(f"          {x}")
    print(f"\n  {npass}/{len(d['cases'])} match")
    return nfail

FIELD = {"requirement": "Requirement", "resource-token": "ResourceToken",
         "url": "URL", "code": "Code"}

def run_requirement(path):
    d = json.load(open(path))
    print(f"\nrequirement / {d.get('spec')}\n{len(d['cases'])} cases\n")
    npass = nfail = 0
    for i, c in enumerate(d["cases"], 1):
        detail = []
        try:
            m = parse_dict(c["header"])
            parsed = {}
            if "requirement" in m:
                parsed["Requirement"] = m["requirement"]["value"]
                for k, (v, kind) in m["requirement"]["params"].items():
                    if k in FIELD:
                        parsed[FIELD[k]] = v
            ok = parsed == c["parsed"]
            if not ok:
                detail.append(f"parsed {parsed} != {c['parsed']}")
            # canonical: the input is canonical only if re-serializing the
            # RECOGNISED fields reproduces it. Unknown params and extra
            # members are dropped, so their presence makes it non-canonical.
            rebuilt = {"requirement": {
                "kind": "token", "value": parsed.get("Requirement"),
                "params": {k: pv for k, pv in
                           m.get("requirement", {}).get("params", {}).items()
                           if k in FIELD}}}
            # These fixtures treat "; " as the canonical parameter separator.
            is_canon = (ser_dict(rebuilt, sep="; ") == c["header"])
            if is_canon != c["canonical"]:
                ok = False
                detail.append(f"canonical {is_canon} != {c['canonical']}")
                detail.append(f"reserialized: {ser_dict(rebuilt, sep='; ')}")
        except Malformed as e:
            ok = False; detail.append(f"parse failed: {e}")
        npass += ok; nfail += (not ok)
        print(f"  [{'ok  ' if ok else 'FAIL'}] {i}. {c['header'][:66]}")
        for x in detail:
            print(f"          {x}")
    print(f"\n  {npass}/{len(d['cases'])} match")
    return nfail

if __name__ == "__main__":
    bad = run_signature_error(sys.argv[1])
    if len(sys.argv) > 2:
        bad += run_requirement(sys.argv[2])
    sys.exit(1 if bad else 0)
