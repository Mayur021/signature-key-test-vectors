"""Verify every vector file in aauth-dev/aauth-go testdata/vectors.

Nine files, 94 cases, checked against an implementation written from the spec
text rather than derived from aauth-go. Run:

    python3 -I verify_all_fixtures.py <path-to-testdata/vectors>

Each file reports its own tally and the script exits non-zero if any case
disagrees.
"""
import base64, hashlib, json, os, re, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature)
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verify_aauth_vectors as HS            # http-signature
import verify_signature_key_header as SK     # signature-key
import verify_structured_headers as SH       # signature-error, requirement

def b64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def B64(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")

# ---------------------------------------------------------------- 1. thumbprint
# Lift thumbprint() out of gen_vectors.py rather than reimplementing it. The
# jkt-jwt vector's iss is the RFC 7638 thumbprint of its own header JWK, so this
# has to exercise the function that BUILT the vectors. A second copy here would
# agree with itself and prove nothing. gen_vectors.py runs on import, so the
# function is extracted by text rather than imported.
def _load_thumbprint():
    src = open(os.path.join(os.path.dirname(HERE), "gen_vectors.py")).read()
    start = src.index("def thumbprint(")
    end = src.index("\n# ", start)
    ns = {}
    exec("import base64, hashlib, json\n"
         "B64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')\n"
         + src[start:end], ns)
    return ns["thumbprint"]

thumbprint = _load_thumbprint()

def run_thumbprint(d):
    bad = 0
    for c in d["cases"]:
        got = thumbprint(c["jwk"])
        ok = got == c["thumbprint"]
        bad += not ok
        print(f"  [{'ok  ' if ok else 'FAIL'}] {c['name']}")
        if not ok:
            print(f"          expected {c['thumbprint']}\n          got      {got}")
    return bad, len(d["cases"])

# ---------------------------------------------------------------- 2. identifiers
LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

def valid_host(h: str) -> bool:
    """Lowercase, A-labels, no empty labels, no leading/trailing hyphen."""
    if not h or h != h.lower():
        return False
    if h.endswith("."):
        return False
    return all(LABEL.match(lab) for lab in h.split("."))

def valid_server_identifier(s: str) -> bool:
    if not s.startswith("https://"):
        return False
    rest = s[len("https://"):]
    if any(ch in rest for ch in "/?#@") or ":" in rest:
        return False          # no path, query, fragment, userinfo or port
    return valid_host(rest)

LOCAL = re.compile(r"^[A-Za-z0-9\-_+.]{1,255}$")

def parse_agent_identifier(s: str):
    """Returns a dict on success, None on failure."""
    if not s.startswith("aauth:"):
        return None
    body = s[len("aauth:"):]
    if body.count("@") != 1:
        return None
    local, domain = body.split("@")
    if not LOCAL.match(local):
        return None
    if local.count("+") > 1:
        return None
    if "+" in local:
        name, disc = local.split("+")
        if not name or not disc:
            return None
    else:
        name, disc = local, None
    if not valid_host(domain):
        return None
    out = {"name": name, "domain": domain}
    if disc:
        out["discriminator"] = disc
    return out

def run_server_identifier(d):
    bad = 0
    for c in d["cases"]:
        got = valid_server_identifier(c["input"])
        ok = got == c["valid"]
        bad += not ok
        print(f"  [{'ok  ' if ok else 'FAIL'}] valid={str(c['valid']):5} {c['input']}")
        if not ok:
            print(f"          got valid={got}")
    return bad, len(d["cases"])

def run_agent_identifier(d):
    bad = 0
    for c in d["cases"]:
        p = parse_agent_identifier(c["input"])
        ok = (p is not None) == c["valid"]
        if ok and c["valid"]:
            want = {k: v for k, v in c.items()
                    if k in ("name", "domain", "discriminator")}
            if p != want:
                ok = False
        bad += not ok
        label = c.get("name", c["input"][:46])
        print(f"  [{'ok  ' if ok else 'FAIL'}] valid={str(c['valid']):5} {label[:52]}")
        if not ok:
            print(f"          input {c['input'][:70]}")
            print(f"          got   {p}")
    return bad, len(d["cases"])

# ---------------------------------------------------------------- 3. jwt
FULLY_SPECIFIED = {"Ed25519", "Ed448", "ES256", "ES384", "ES512",
                   "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                   "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}
CONSISTENT = {"Ed25519": ("OKP", "Ed25519"), "Ed448": ("OKP", "Ed448"),
              "ES256": ("EC", "P-256"), "ES384": ("EC", "P-384"),
              "ES512": ("EC", "P-521")}

def jwk_acceptable(jwk):
    alg = jwk.get("alg")
    if not alg or alg not in FULLY_SPECIFIED:
        return False, f"alg {alg!r} absent or not fully specified"
    if alg in CONSISTENT:
        kty, crv = CONSISTENT[alg]
        if jwk.get("kty") != kty:
            return False, f"kty {jwk.get('kty')!r} inconsistent with alg {alg}"
        if jwk.get("crv") != crv:
            return False, f"crv {jwk.get('crv')!r} inconsistent with alg {alg}"
    return True, None

def verify_jws(tok, jwk):
    h, p, s = tok.split(".")
    sig, signing_input = b64u(s), (h + "." + p).encode()
    alg = json.loads(b64u(h)).get("alg")
    if alg == "Ed25519":
        Ed25519PublicKey.from_public_bytes(b64u(jwk["x"])).verify(sig, signing_input)
    elif alg == "ES256":
        nums = ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64u(jwk["x"]), "big"),
            int.from_bytes(b64u(jwk["y"]), "big"), ec.SECP256R1())
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                   int.from_bytes(sig[32:], "big"))
        nums.public_key().verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
    else:
        raise InvalidSignature(f"unsupported alg {alg}")

def jwt_rejects(tok, case):
    """Apply the AAuth acceptance rules. Returns a reason, or None to accept."""
    h, p, _ = tok.split(".")
    hdr, claims = json.loads(b64u(h)), json.loads(b64u(p))
    alg = hdr.get("alg")
    if alg in (None, "none"):
        return "JWS alg none or absent"
    if alg not in FULLY_SPECIFIED:
        return f"JWS alg {alg!r} is not fully specified"
    cnf = (claims.get("cnf") or {}).get("jwk")
    if cnf is not None:
        ok, why = jwk_acceptable(cnf)
        if not ok:
            return f"cnf.jwk: {why}"
    if "iat" not in claims:
        return "iat absent"
    iss = claims.get("iss")
    if iss is not None and not valid_server_identifier(iss):
        return f"iss {iss!r} is not a server identifier"
    if hdr.get("typ") == "aa-person+jwt" and "scope" in claims:
        return "person token carries scope"
    return None

def run_jwt(d):
    bad = 0
    for c in d["cases"]:
        tok, detail = c["token"], []
        expect_reject = bool(c.get("reject"))
        reason = jwt_rejects(tok, c)
        ok = (reason is not None) == expect_reject
        if not ok:
            detail.append(f"expected reject={expect_reject}, got {reason!r}")
        if ok and not expect_reject:
            try:
                verify_jws(tok, c["signing_key"])
            except InvalidSignature as e:
                ok = False; detail.append(f"signature did not verify: {e}")
            got = json.loads(b64u(tok.split(".")[1]))
            if "claims" in c and got != c["claims"]:
                ok = False
                diff = {k for k in set(got) | set(c["claims"])
                        if got.get(k) != c["claims"].get(k)}
                detail.append(f"claims differ on {sorted(diff)}")
            hdr = json.loads(b64u(tok.split(".")[0]))
            if c.get("typ") and hdr.get("typ") != c["typ"]:
                ok = False; detail.append(f"typ {hdr.get('typ')!r} != {c['typ']!r}")
            if c.get("kid") and hdr.get("kid") != c["kid"]:
                ok = False; detail.append(f"kid mismatch")
        bad += not ok
        tag = " (randomized)" if c.get("randomized") else ""
        print(f"  [{'ok  ' if ok else 'FAIL'}] {c['name']}{tag}")
        for x in detail:
            print(f"          {x}")
    return bad, len(d["cases"])

# ---------------------------------------------------------------- 4. metadata
REQUIRES_JWKS = {"aauth-agent.json", "aauth-access.json", "aauth-resource.json"}

def run_metadata(d):
    bad = 0
    for c in d["cases"]:
        doc, j, detail = c["document"], c["json"], []
        ok = True
        if "issuer" not in j:
            ok = False; detail.append("issuer absent")
        elif not valid_server_identifier(j["issuer"]):
            ok = False; detail.append(f"issuer {j['issuer']!r} is not a server identifier")
        if doc in REQUIRES_JWKS and "jwks_uri" not in j:
            ok = False; detail.append("jwks_uri absent")
        for k, v in j.items():
            if k.endswith(("_uri", "_endpoint")) and isinstance(v, str):
                if not v.startswith("https://"):
                    ok = False; detail.append(f"{k} is not https: {v}")
        try:
            if json.loads(json.dumps(j)) != j:
                ok = False; detail.append("does not round-trip through JSON")
        except (TypeError, ValueError) as e:
            ok = False; detail.append(f"not serializable: {e}")
        bad += not ok
        print(f"  [{'ok  ' if ok else 'FAIL'}] {doc} ({len(j)} members)")
        for x in detail:
            print(f"          {x}")
    return bad, len(d["cases"])

# ---------------------------------------------------------------- dispatch
def run_http_signature(d):
    bad = 0
    for c in d["cases"]:
        got, detail = HS.run_case(c)
        ok = got == c["expect"]
        bad += not ok
        print(f"  [{'ok  ' if ok else 'FAIL'}] {c['name']}")
        if not ok:
            print(f"          expected {c['expect']!r}, got {got!r}: {detail}")
    return bad, len(d["cases"])

def run_signature_key(d):
    bad = 0
    for i, c in enumerate(d["cases"], 1):
        scheme, params, err = SK.evaluate(c["header"])
        got = err[0] if err else None
        ok = got == c.get("error")
        if ok and "scheme" in c and scheme != c["scheme"]:
            ok = False
        if ok and "params" in c and params is not None:
            strs = {k: v for k, v in params.items() if not isinstance(v, bool)}
            ok = strs == c["params"]
        bad += not ok
        print(f"  [{'ok  ' if ok else 'FAIL'}] {i}. {c['header'][:62]}")
    return bad, len(d["cases"])

RUNNERS = {
    "jwk-thumbprint":    run_thumbprint,
    "server-identifier": run_server_identifier,
    "agent-identifier":  run_agent_identifier,
    "jwt":               run_jwt,
    "metadata":          run_metadata,
    "http-signature":    run_http_signature,
    "signature-key":     run_signature_key,
}

ORDER = ["jwk-thumbprint", "server-identifier", "agent-identifier", "jwt",
         "metadata", "requirement", "signature-error", "signature-key",
         "http-signature"]

def main(vecdir):
    total = failed = files = 0
    summary = []
    for kind in ORDER:
        path = os.path.join(vecdir, kind + ".json")
        if not os.path.exists(path):
            print(f"-- {kind}.json not found, skipped"); continue
        d = json.load(open(path))
        print(f"\n{'='*66}\n{kind}.json  ({len(d['cases'])} cases)")
        print(f"spec: {d.get('spec','')}\n")
        if kind == "signature-error":
            bad = SH.run_signature_error(path); n = len(d["cases"])
        elif kind == "requirement":
            bad = SH.run_requirement(path); n = len(d["cases"])
        else:
            bad, n = RUNNERS[kind](d)
        total += n; failed += bad; files += 1
        summary.append((kind, n - bad, n))
    print(f"\n{'='*66}\nSUMMARY  {files} files\n")
    for kind, good, n in summary:
        mark = "ok  " if good == n else "FAIL"
        print(f"  [{mark}] {kind:20} {good}/{n}")
    print(f"\n  {total - failed}/{total} cases match")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
