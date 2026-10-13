"""Independent RFC 9421 verifier for the AAuth http-signature test vectors.

Reconstructs each signature base from the request and the published
Signature-Input, verifies the signature with the vector's own key, applies the
tamper and verify directives, and compares the outcome to `expect`.

Usage: python3 -I verify_aauth_vectors.py <http-signature.json>
"""
import base64, hashlib, json, sys
from urllib.parse import urlsplit
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

DEFAULT_WINDOW = 60
def b64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def parse_signature_input(si):
    """sig=("a" "b");created=N  ->  (label, [components], {params})"""
    label, _, rest = si.partition("=")
    inner = rest[rest.index("(") + 1:rest.index(")")]
    comps = [t.strip('"') for t in inner.split()] if inner.strip() else []
    params = {}
    for p in rest[rest.index(")") + 1:].split(";"):
        if "=" in p:
            k, _, v = p.partition("=")
            params[k.strip()] = v.strip()
    return label.strip(), comps, params

def content_digest(body: bytes) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"

def build_base(req, signed, comps, si):
    u = urlsplit(req["url"])
    body = req.get("body", "")
    body_b = body.encode() if isinstance(body, str) else body
    hdrs = {k.lower(): v for k, v in req.get("headers", {}).items()}
    # Content-Digest is a signed field: take the published value if present,
    # otherwise derive it from the body.
    for k, v in signed.items():
        if k.lower() not in ("signature", "signature-input"):
            hdrs[k.lower()] = v
    if "content-digest" not in hdrs and body_b:
        hdrs["content-digest"] = content_digest(body_b)
    derived = {"@method": req["method"], "@authority": u.netloc, "@path": u.path,
               "@query": ("?" + u.query) if u.query else "?",
               "@target-uri": req["url"], "@scheme": u.scheme}
    lines, missing = [], []
    for c in comps:
        if c.startswith("@"):
            lines.append(f'"{c}": {derived[c]}')
        elif c in hdrs:
            lines.append(f'"{c}": {hdrs[c]}')
        else:
            missing.append(c)
    params = si[si.index("("):]
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines), missing

def verify_sig(base: bytes, sigfield: str, jwk: dict):
    raw = base64.b64decode(sigfield.split("=", 1)[1].strip(":"))
    try:
        if jwk["alg"] == "Ed25519":
            Ed25519PublicKey.from_public_bytes(b64u(jwk["x"])).verify(raw, base)
        elif jwk["alg"] == "ES256":
            nums = ec.EllipticCurvePublicNumbers(
                int.from_bytes(b64u(jwk["x"]), "big"),
                int.from_bytes(b64u(jwk["y"]), "big"), ec.SECP256R1())
            der = encode_dss_signature(int.from_bytes(raw[:32], "big"),
                                       int.from_bytes(raw[32:], "big"))
            nums.public_key().verify(der, base, ec.ECDSA(hashes.SHA256()))
        else:
            return False, f"unsupported alg {jwk['alg']}"
        return True, None
    except InvalidSignature:
        return False, "signature did not verify"

def run_case(c):
    req = dict(c["request"])
    for k, v in (c.get("tamper") or {}).items():
        if v == "" and k in ("method", "url"):
            continue                       # empty string means "leave alone"
        if k == "headers":
            req["headers"] = dict(req.get("headers", {}), **v)
        else:
            req[k] = v
    si = c["signed"]["Signature-Input"]
    _, comps, params = parse_signature_input(si)
    vd = c.get("verify") or {}

    # resource-required components the signer did not cover
    for need in vd.get("required_components", []):
        if need not in comps:
            return "invalid_input", f"required component {need!r} not covered"
    if vd.get("require_body_coverage"):
        for need in ("content-digest", "content-type"):
            if need not in comps:
                return "invalid_input", f"body coverage requires {need!r}"

    # freshness, before any cryptographic work
    if "at_offset" in vd:
        off = vd["at_offset"]
        window = vd.get("window_seconds", DEFAULT_WINDOW)
        if off < 0 and -off > window:
            return "clock_skew", f"created {-off}s ahead of clock, window {window}s"
        if off > window:
            return "invalid_signature", f"created {off}s old, window {window}s"

    base, missing = build_base(req, c["signed"], comps, si)
    if missing:
        return "invalid_input", f"covered component(s) absent from request: {missing}"

    # RFC 9530: a covered Content-Digest must agree with the body as received.
    # Signature verification alone does not catch a swapped body, because the
    # signature covers the digest field and not the bytes it summarises.
    if "content-digest" in comps:
        body = req.get("body", "")
        body_b = body.encode() if isinstance(body, str) else body
        presented = None
        for line in base.split("\n"):
            if line.startswith('"content-digest": '):
                presented = line.split(": ", 1)[1]
        actual = content_digest(body_b)
        if presented is not None and presented != actual:
            return "invalid_signature", (
                f"Content-Digest does not match body: covered {presented}, "
                f"body hashes to {actual}")
    ok, why = verify_sig(base.encode(), c["signed"]["Signature"], c["signing_key"])
    return ("valid", base) if ok else ("invalid_signature", why)

def main(path):
    d = json.load(open(path))
    cases = d["cases"]
    print(f"{d.get('kind','?')} / {d.get('spec','?')}  {len(cases)} cases\n")
    npass = nfail = 0
    for c in cases:
        got, detail = run_case(c)
        exp = c["expect"]
        good = got == exp
        npass += good; nfail += (not good)
        print(f"  [{'ok  ' if good else 'FAIL'}] {c['name']}")
        if not good:
            print(f"          expected {exp!r}, got {got!r}: {detail}")
    print(f"\n  {npass}/{len(cases)} match")
    return 0 if nfail == 0 else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
