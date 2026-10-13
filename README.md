# Signature-Key test vectors

Test vectors for [`draft-hardt-httpbis-signature-key`](https://github.com/dickhardt/signature-key),
covering the six JWK-based schemes, multiple signatures, post-quantum key
handling, and the document's reject rules.

Offered for [signature-key#25](https://github.com/dickhardt/signature-key/issues/25).

Every vector publishes the RFC 9421 signature base verbatim. That is the point
of the set. A published `Signature` value proves only that some verifier agrees
with it, and for the randomised algorithms it cannot even do that reproducibly.
The base is what lets an implementer check the signer half alone, and what tells
someone who fails a vector whether the fault is in canonicalization or in the
crypto.

31 vectors: 11 positive, 20 negative.

## What is here

| File | Contents |
|---|---|
| `signature-key-vectors.json` | the machine-readable bundle a harness consumes, no network access needed |
| `test-vectors-appendix.md` | the same set as a draft appendix, RFC 8792 wrapped, in the style of RFC 9421 Appendix B |
| `served/` | the 11 `.well-known` metadata documents and JWKS the discovery schemes resolve, laid out by host and path |
| `gen_vectors.py` | the generator, so every value can be regenerated and nothing has to be taken on faith |
| `harness/` | an independent verifier for the vectors already in `aauth-dev/aauth-go` |

## Derivation

These are derived from the draft text, not from an implementation. Where the
draft states a MUST or a MUST NOT, the negative vector names the section it came
from, so a disagreement is a disagreement about the text rather than about whose
code is right.

Keys come from fixed seeds and every vector declares `now`, so the set
regenerates identically and does not go stale. Private keys are included, which
is what lets someone regenerate a vector rather than trust it. Running the
generator twice produces byte-identical files, which is checked rather than
asserted.

Getting there needed two deliberate choices, and they are worth separating from
what the vectors claim. ECDSA signing here is the deterministic variant of
RFC 6979, and the hedged ML-DSA signature is produced from a fixed `rnd` stream
rather than an RBG. **That makes the generator deterministic. It does not make
those vectors reproduce-the-bytes vectors.** Another signer picks a different
`k` or a different `rnd` and produces a different, equally valid signature, so
they stay category 2 and a suite must still verify them rather than diff them.
The two kinds of determinism are easy to conflate and conflating them is how a
conformance suite ends up asserting the wrong thing.

## The caveat in #25

> Vectors generated from a single implementation encode that implementation's
> bugs as normative.

#25 asks for two things before anything is published: hand-verify the signature
bases against the spec text rather than trusting the generator, and have a
second implementation independently reproduce the Ed25519 vectors.

Both were done, in that order and for that reason.

Deriving the vectors from the draft text means the generator is not a second
opinion about an implementation, it is a reading of the specification. And the
existing `aauth-go` fixtures were re-verified first, by `harness/`, which
reconstructs every signature base from the request and the published
`Signature-Input` and then re-verifies each signature:

| Fixture | Cases | Result |
|---|---|---|
| `http-signature.json` | 13 | 13/13 |
| `signature-key.json` | 9 | 9/9 |

One thing that re-verification is worth stating on its own. Signature
verification alone does not catch a swapped body: the signature covers the
`Content-Digest` field, not the bytes that field summarises. RFC 9530
validation of the digest against the body is a separate step, and a verifier
missing it passes the tampered-body case while accepting modified bodies.

## Which signatures reproduce, and which cannot

#25 sets out three categories and asks that each vector say which it is in.
Every vector here carries `vector_category`.

**1. Key handling.** Nothing is signed. The key sits in a JWKS and the test is
whether an implementation declines it cleanly or falls over. Every
implementation can run these today, including, and especially, those with no
support for the algorithm in question.

**2. Verify only.** The vector carries the request, its base, the public key and
a signature. Any implementation supporting the algorithm checks it and gets a
definite answer. ECDSA and ML-DSA sit here.

**3. Reproduce the bytes.** Only these need determinism. Ed25519 is
deterministic under RFC 8032, so those signatures compare byte for byte and are
the primary reproducible set.

A suite that diffs an ECDSA or hedged ML-DSA signature reports failures that are
not failures. RFC 9421 Section 3.3.4 says so outright for ECDSA: "it is not
correct to recalculate a new signature on the signature base and compare the
results to an existing signature."

The signature base blocks in the appendix are RFC 8792 folded. Each carries its
unwrapped byte length and SHA-256, so an implementer can confirm the unfold
before spending time on a signature that was never going to verify.

## Post-quantum key handling

The two highest-value vectors need no ML-DSA support to run, which is the point
of them.

- A JWKS holding only an ML-DSA-44 key. An implementation without ML-DSA must
  report `unsupported_algorithm`, not throw.
- **A JWKS holding an Ed25519 key and an ML-DSA-44 key, where the vector selects
  the Ed25519 one by `kid`.** An implementation must find the usable key and
  ignore the one it cannot parse. The failure mode is a library that hits the
  unknown `kty` while enumerating and abandons a perfectly good key sitting next
  to it. This vector is marked MUST ACCEPT.

Keys are real ML-DSA-44, generated through FIPS 204 `ML-DSA.KeyGen_internal`
from a fixed seed, carried as the `AKP` key type of RFC 9964.

A signed ML-DSA vector is included twice: the hedged signature as a verify-only
vector, and the deterministic variant as **OPTIONAL**. The hedged form degrades
to the deterministic one when the RBG returns zeros, so an implementation able
to inject `rnd` reproduces those bytes. Most libraries do not expose that knob,
so the deterministic vector must not be required to pass. It is here because for
the implementations that can reach it, it is the only ML-DSA vector that tests a
signer rather than a verifier.

## The negative vectors

They cover the rules an implementation is most likely to get wrong rather than
the ones it is likely to get right:

- `signature-key` left out of the covered components, with `required_input`
  naming what the server requires
- `alg` absent, polymorphic (`EdDSA`), or inconsistent with `kty` or `crv`
- symmetric key material (`oct`, `HS256`), which names a shared secret rather
  than a public key
- `kid` presented with `hwk`, which the scheme forbids because there is nothing
  for an identifier to select
- `cnf` presented with `self-jwt`, which is a different trust model wearing this
  scheme's name
- `issuer` missing from a metadata document, and `issuer` not matching the
  identity the document was fetched under
- a `kid` that selects no member of the JWKS
- a JWT with no `exp`, one that expired at `now - 1`, and one whose `iat` is an
  hour ahead of `now`
- a selected member naming a scheme the verifier does not implement

Three vectors are marked MUST ACCEPT, and they are the ones a naive
implementation fails. The sharpest is the companion to `unsupported_scheme`: a
verifier must not reject a request because a member it did **not** select names
a scheme it does not implement. Without that rule no signer could offer a
signature under a new scheme without breaking every verifier that lacks it, so
none would, and the scheme registry would have no path into deployment. The
other two are the mixed JWKS above and a live assertion at `exp = now + 300`,
which is what stops a verifier that rejects everything from passing the expiry
cases for the wrong reason.

### Error codes

Ten of the thirteen `Signature-Error` codes are exercised:
`unsupported_algorithm`, `unsupported_scheme`, `invalid_input`, `invalid_key`,
`unknown_key`, `issuer_missing`, `issuer_mismatch`, `invalid_jwt`,
`expired_jwt`, `clock_skew`.

The three left alone, since a gap without a reason looks like an oversight:

- `invalid_signature` is already covered by the existing `http-signature.json`
  fixtures, which tamper the path, the body and the `Signature-Key` member.
- `invalid_request` is for a request malformed in a way unrelated to signature
  verification, so nothing about this header produces it.
- `revoked_jwt` cannot be a static vector. The draft says how a verifier learns
  of a withdrawal is out of scope and not discoverable from the JWT, so the
  condition lives entirely in verifier state that no file can establish.

## Not covered

- **`x509`**, which #25 lists as "if it stays". Left until it does.
- **Anything needing a live endpoint**, and the pairwise round-trip where one
  implementation signs and another verifies. #25 puts both out of scope for a
  specification repository, and they are
  [aauth-dev/conformance#1](https://github.com/aauth-dev/conformance/issues/1).

## Running it

```
pip install -r requirements.txt
python3 gen_vectors.py
```

Writes the JSON bundle, the appendix and `served/`, then verifies every
signature in the set against its own published base and exits non-zero if any
fails. It also refuses to build if two vectors ever claim one discovery path
with different documents, which the served tree cannot represent.

To re-verify the `aauth-go` fixtures:

```
python3 harness/verify_aauth_vectors.py path/to/http-signature.json
python3 harness/verify_signature_key_header.py path/to/signature-key.json
```

## Status

Built against `draft-hardt-httpbis-signature-key.md` at `main`, which at the
time of writing is byte-identical to the copy used here
(`b2b43db67a1aa5249d1166589834d44f81e97ea2e6375a07b475115efa196b7d`). #25
sequences this work after #21 through #24, all of which are now closed.

This repository is a staging ground, not a destination. #25 asks for two
artifacts in the `signature-key` repository itself, and
`aauth-dev/conformance#1` mirrors the static ones. Happy to open a pull request
against whichever of the two is wanted.

## Licence

Dedicated to the public domain under [CC0 1.0](LICENSE), and offered for
inclusion in `draft-hardt-httpbis-signature-key` under the terms of BCP 78.

An RFC appendix carries the IETF Trust's terms rather than a per-file licence,
so anything headed there should arrive without one of its own to strip. Test
vectors are only useful if nobody has to stop and work out whether they may use
them.
