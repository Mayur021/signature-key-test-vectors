# Test Vectors

Vectors for the Signature-Key schemes, derived from the draft text rather than from any implementation. Each publishes the signature base verbatim, so a signer can be checked without a live verifier.

Long lines use RFC 8792 single-backslash line folding; a line ending in `\` continues on the next line with no inserted whitespace.

All vectors use `created=1791275958` and cover `@method @authority @path signature-key`. Keys are derived from fixed seeds, so every value below is reproducible by rerunning the generator.

## A note on which signatures reproduce

Ed25519 is deterministic (RFC 8032), so an Ed25519 vector's `Signature` value is reproducible byte for byte and can be compared directly. ECDSA is randomised: each `ES256` signature below is one valid signature among many. For those, compare the **signature base** and then verify the signature. A conformance suite that diffs ECDSA signature bytes will report false failures.

## A.1 hwk-okp-ed25519 (`hwk`)

Inline OKP key. No kid, forbidden by the hwk scheme: the key is carried inline so there is nothing for an identifier to select. Ed25519 is deterministic (RFC 8032), so the Signature value reproduces byte for byte.

Category **3** (reproduce the bytes). Evaluate at `now = 1791275958`.

Request:

~~~ http-message
GET https://resource.example/api/documents
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="fFWGSTH7SN1gol911OE\
rq1sPFXT_LAG26zBtLm8ItK0";alg="Ed25519"
~~~

Signature base (269 bytes, SHA-256 `4dcf1a85d4e667e8734fe3ca108e4b96b4e2476a8b97bed9a9b05fff038fd083`):

~~~
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/documents
"signature-key": sig=hwk;kty="OKP";crv="Ed25519";x="fFWGSTH7SN1gol911\
OErq1sPFXT_LAG26zBtLm8ItK0";alg="Ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key")\
;created=1791275958
~~~

Expected headers:

~~~ http-message
Signature-Input: sig=("@method" "@authority" "@path" "signature-key")\
;created=1791275958
Signature: sig=:s9yYZzse99k5F+1NStoetBXxQfJ37sDxQmaV96A/0vrf+ph0uU9sm\
2COnpG6n6SWIRAxmV6z+9+fpAd7FdyeCQ==:
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="fFWGSTH7SN1gol911OE\
rq1sPFXT_LAG26zBtLm8ItK0";alg="Ed25519"
~~~

Key material (private key included so the vector can be regenerated):

~~~ json
{
  "public_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
    "alg": "Ed25519"
  },
  "private_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
    "alg": "Ed25519",
    "d": "ayuaMXaZDNNH9zOnyKYJM-AzageiMEuU_Si8nN3jvl8"
  },
  "alg": "Ed25519"
}
~~~

## A.2 hwk-ec-p256 (`hwk`)

Inline EC key. ECDSA is randomised, so the Signature value here is ONE valid signature, not the only one. Compare the signature base, then verify the signature; do not compare signature bytes.

Category **2** (verify only). Evaluate at `now = 1791275958`.

Request:

~~~ http-message
GET https://resource.example/api/documents
Signature-Key: sig=hwk;kty="EC";crv="P-256";x="LhnFCX9JWOQhInaap65wwL\
3rcT49WyvQSlIhMLO8lr4";y="PEr4OX8tM8oHdcYMrbeIQhl58q5XxkVG28CJQ8tS618\
";alg="ES256"
~~~

Signature base (312 bytes, SHA-256 `e5adb14b726b25fb4ac497366ba09e7d5dfc0c44f5e6b7d0bd83d7032244966f`):

~~~
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/documents
"signature-key": sig=hwk;kty="EC";crv="P-256";x="LhnFCX9JWOQhInaap65w\
wL3rcT49WyvQSlIhMLO8lr4";y="PEr4OX8tM8oHdcYMrbeIQhl58q5XxkVG28CJQ8tS6\
18";alg="ES256"
"@signature-params": ("@method" "@authority" "@path" "signature-key")\
;created=1791275958
~~~

Expected headers:

~~~ http-message
Signature-Input: sig=("@method" "@authority" "@path" "signature-key")\
;created=1791275958
Signature: sig=:sF4WOVhAYtU77Jf/TevaIss/b8iaB8VCguMuWsdIDRGuAQcNCo5M4\
YsDiK43Qus58clFiXzJQF30b/ZuxVAfyA==:
Signature-Key: sig=hwk;kty="EC";crv="P-256";x="LhnFCX9JWOQhInaap65wwL\
3rcT49WyvQSlIhMLO8lr4";y="PEr4OX8tM8oHdcYMrbeIQhl58q5XxkVG28CJQ8tS618\
";alg="ES256"
~~~

Key material (private key included so the vector can be regenerated):

~~~ json
{
  "public_jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "LhnFCX9JWOQhInaap65wwL3rcT49WyvQSlIhMLO8lr4",
    "y": "PEr4OX8tM8oHdcYMrbeIQhl58q5XxkVG28CJQ8tS618",
    "alg": "ES256"
  },
  "private_jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "LhnFCX9JWOQhInaap65wwL3rcT49WyvQSlIhMLO8lr4",
    "y": "PEr4OX8tM8oHdcYMrbeIQhl58q5XxkVG28CJQ8tS618",
    "alg": "ES256",
    "d": "nXC1TV0TVaRnm_lygKClwhxEKFTVXwyUqz-0Nxi5EF4"
  },
  "alg": "ES256"
}
~~~

## A.3 jkt-jwt-enclave-p256-delegates-ed25519 (`jkt-jwt`)

Enclave P-256 identity key delegates to an Ed25519 ephemeral request key via cnf.jwk. iss is the RFC 7638 thumbprint of the HEADER jwk, prefixed per the typ. The HTTP signature is made by the cnf.jwk key, not the enclave key. The delegation JWT itself is ECDSA and so not reproducible; the HTTP signature is Ed25519 and is.

Category **3** (reproduce the bytes). Evaluate at `now = 1791275958`.

Request:

~~~ http-message
GET https://resource.example/api/documents
Signature-Key: sig=jkt-jwt;jwt="eyJ0eXAiOiJqa3QtczI1Nitqd3QiLCJhbGciO\
iJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImhSX01YOF\
pEcmNtTzJVS2RQa0tIeDlwaVJxN3JBYTRCamFHYlRjbERzQ3MiLCJ5Ijoia2lYOU8ycVN\
5VWd1RnlQR0NBaTBJN3RkV1A0eTJGV2tFVjR3cmE2Q3IyZyIsImFsZyI6IkVTMjU2In19\
.eyJpc3MiOiJ1cm46amt0OnNoYS0yNTY6dnVwUUZMNlV2TWtzTjNrYXJnaWtYeWtVRDcx\
TnpQWE9VYldELWNWeFAwOCIsImlhdCI6MTc5MTI3NTg5OCwiZXhwIjoxNzkxMzYyMzU4L\
CJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiZkZXR1\
NUSDdTTjFnb2w5MTFPRXJxMXNQRlhUX0xBRzI2ekJ0TG04SXRLMCIsImFsZyI6IkVkMjU\
1MTkifX19.VOzqQQcSy3bHHoseWEpcL4NgUhYIzAcf_fe1m8KTo33d66v-cjvTSqW2O2H\
VmxSWqZkXR1p8-LhS5X-J3GYgsw"
~~~

Signature base (810 bytes, SHA-256 `eae9be40a59801fe9b95bfea7faca8f83d3437230285323418088b51ea5387f8`):

~~~
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/documents
"signature-key": sig=jkt-jwt;jwt="eyJ0eXAiOiJqa3QtczI1Nitqd3QiLCJhbGc\
iOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImhSX01Y\
OFpEcmNtTzJVS2RQa0tIeDlwaVJxN3JBYTRCamFHYlRjbERzQ3MiLCJ5Ijoia2lYOU8yc\
VN5VWd1RnlQR0NBaTBJN3RkV1A0eTJGV2tFVjR3cmE2Q3IyZyIsImFsZyI6IkVTMjU2In\
19.eyJpc3MiOiJ1cm46amt0OnNoYS0yNTY6dnVwUUZMNlV2TWtzTjNrYXJnaWtYeWtVRD\
cxTnpQWE9VYldELWNWeFAwOCIsImlhdCI6MTc5MTI3NTg5OCwiZXhwIjoxNzkxMzYyMzU\
4LCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiZkZX\
R1NUSDdTTjFnb2w5MTFPRXJxMXNQRlhUX0xBRzI2ekJ0TG04SXRLMCIsImFsZyI6IkVkM\
jU1MTkifX19.VOzqQQcSy3bHHoseWEpcL4NgUhYIzAcf_fe1m8KTo33d66v-cjvTSqW2O\
2HVmxSWqZkXR1p8-LhS5X-J3GYgsw"
"@signature-params": ("@method" "@authority" "@path" "signature-key")\
;created=1791275958
~~~

Expected headers:

~~~ http-message
Signature-Input: sig=("@method" "@authority" "@path" "signature-key")\
;created=1791275958
Signature: sig=:eh1RaHTZqqDiTOl/g/aGlf90PwOk4TV1TYYYubFoSHn1N5D7fMZUp\
mfAuzuG8q75TDovTnmCa3ThElk8xfMODQ==:
Signature-Key: sig=jkt-jwt;jwt="eyJ0eXAiOiJqa3QtczI1Nitqd3QiLCJhbGciO\
iJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImhSX01YOF\
pEcmNtTzJVS2RQa0tIeDlwaVJxN3JBYTRCamFHYlRjbERzQ3MiLCJ5Ijoia2lYOU8ycVN\
5VWd1RnlQR0NBaTBJN3RkV1A0eTJGV2tFVjR3cmE2Q3IyZyIsImFsZyI6IkVTMjU2In19\
.eyJpc3MiOiJ1cm46amt0OnNoYS0yNTY6dnVwUUZMNlV2TWtzTjNrYXJnaWtYeWtVRDcx\
TnpQWE9VYldELWNWeFAwOCIsImlhdCI6MTc5MTI3NTg5OCwiZXhwIjoxNzkxMzYyMzU4L\
CJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiZkZXR1\
NUSDdTTjFnb2w5MTFPRXJxMXNQRlhUX0xBRzI2ekJ0TG04SXRLMCIsImFsZyI6IkVkMjU\
1MTkifX19.VOzqQQcSy3bHHoseWEpcL4NgUhYIzAcf_fe1m8KTo33d66v-cjvTSqW2O2H\
VmxSWqZkXR1p8-LhS5X-J3GYgsw"
~~~

Key material (private key included so the vector can be regenerated):

~~~ json
{
  "public_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
    "alg": "Ed25519"
  },
  "private_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
    "alg": "Ed25519",
    "d": "ayuaMXaZDNNH9zOnyKYJM-AzageiMEuU_Si8nN3jvl8"
  },
  "alg": "Ed25519"
}
~~~

Delegation JWT:

~~~ json
{
  "compact": "eyJ0eXAiOiJqa3QtczI1Nitqd3QiLCJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImhSX01YOFpEcmNtTzJVS2RQa0tIeDlwaVJxN3JBYTRCamFHYlRjbERzQ3MiLCJ5Ijoia2lYOU8ycVN5VWd1RnlQR0NBaTBJN3RkV1A0eTJGV2tFVjR3cmE2Q3IyZyIsImFsZyI6IkVTMjU2In19.eyJpc3MiOiJ1cm46amt0OnNoYS0yNTY6dnVwUUZMNlV2TWtzTjNrYXJnaWtYeWtVRDcxTnpQWE9VYldELWNWeFAwOCIsImlhdCI6MTc5MTI3NTg5OCwiZXhwIjoxNzkxMzYyMzU4LCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiZkZXR1NUSDdTTjFnb2w5MTFPRXJxMXNQRlhUX0xBRzI2ekJ0TG04SXRLMCIsImFsZyI6IkVkMjU1MTkifX19.VOzqQQcSy3bHHoseWEpcL4NgUhYIzAcf_fe1m8KTo33d66v-cjvTSqW2O2HVmxSWqZkXR1p8-LhS5X-J3GYgsw",
  "header": {
    "typ": "jkt-s256+jwt",
    "alg": "ES256",
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "hR_MX8ZDrcmO2UKdPkKHx9piRq7rAa4BjaGbTclDsCs",
      "y": "kiX9O2qSyUguFyPGCAi0I7tdWP4y2FWkEV4wra6Cr2g",
      "alg": "ES256"
    }
  },
  "payload": {
    "iss": "urn:jkt:sha-256:vupQFL6UvMksN3kargikXykUD71NzPXOUbWD-cVxP08",
    "iat": 1791275898,
    "exp": 1791362358,
    "cnf": {
      "jwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
        "alg": "Ed25519"
      }
    }
  },
  "enclave_private_jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "hR_MX8ZDrcmO2UKdPkKHx9piRq7rAa4BjaGbTclDsCs",
    "y": "kiX9O2qSyUguFyPGCAi0I7tdWP4y2FWkEV4wra6Cr2g",
    "alg": "ES256",
    "d": "GEGDUh-MZhLdEKEHkRnFwbSSclsd80yVzDZyIoZ1tNA"
  },
  "thumbprint_input": "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"hR_MX8ZDrcmO2UKdPkKHx9piRq7rAa4BjaGbTclDsCs\",\"y\":\"kiX9O2qSyUguFyPGCAi0I7tdWP4y2FWkEV4wra6Cr2g\"}",
  "thumbprint_sha256": "vupQFL6UvMksN3kargikXykUD71NzPXOUbWD-cVxP08"
}
~~~

## A.4 jwks_uri-discovery-ed25519 (`jwks_uri`)

Two-hop discovery. The metadata document MUST carry issuer, and issuer MUST equal the id parameter by byte equality as presented. The alg travels only on the resolved JWKS entry, because the header conveys id, dwk and kid, which identify a key rather than describe it.

Category **3** (reproduce the bytes). Evaluate at `now = 1791275958`.

Request:

~~~ http-message
GET https://resource.example/api/documents
Signature-Key: sig=jwks_uri;id="https://client.example";dwk="example-\
configuration";kid="key-1"
~~~

Signature base (256 bytes, SHA-256 `0597978bfbb9fda46a123d102340641d5fd36093b30ba9165f07f8b8054c3300`):

~~~
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/documents
"signature-key": sig=jwks_uri;id="https://client.example";dwk="exampl\
e-configuration";kid="key-1"
"@signature-params": ("@method" "@authority" "@path" "signature-key")\
;created=1791275958
~~~

Expected headers:

~~~ http-message
Signature-Input: sig=("@method" "@authority" "@path" "signature-key")\
;created=1791275958
Signature: sig=:v44OZf+hcI9qES0EabbnkDtFXcVjIHzy0JX1Ip8ImKrELbc+uweaj\
3YOo2zp3PRRuARUPiDwDvx2sY675Pn/BQ==:
Signature-Key: sig=jwks_uri;id="https://client.example";dwk="example-\
configuration";kid="key-1"
~~~

Key material (private key included so the vector can be regenerated):

~~~ json
{
  "public_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
    "alg": "Ed25519",
    "kid": "key-1"
  },
  "private_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
    "alg": "Ed25519",
    "d": "ayuaMXaZDNNH9zOnyKYJM-AzageiMEuU_Si8nN3jvl8",
    "kid": "key-1"
  },
  "alg": "Ed25519"
}
~~~

Discovery documents:

~~~ json
{
  "metadata_url": "https://client.example/.well-known/example-configuration",
  "metadata_document": {
    "issuer": "https://client.example",
    "jwks_uri": "https://client.example/jwks.json"
  },
  "jwks_url": "https://client.example/jwks.json",
  "jwks": {
    "keys": [
      {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
        "alg": "Ed25519",
        "kid": "key-1",
        "use": "sig"
      }
    ]
  }
}
~~~

## A.5 jwks-direct-ed25519 (`jwks`)

One hop, no metadata document. The URL is both identifier and key location, compared by byte equality and never canonicalised, so any byte difference names a different signer.

Category **3** (reproduce the bytes). Evaluate at `now = 1791275958`.

Request:

~~~ http-message
GET https://resource.example/api/documents
Signature-Key: sig=jwks;url="https://client.example/keys.jwks";kid="k\
ey-1"
~~~

Signature base (235 bytes, SHA-256 `f979eaa4cd813184b8904ac6446bb13532e84f0adc48c4fbd60039f55b37bb09`):

~~~
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/documents
"signature-key": sig=jwks;url="https://client.example/keys.jwks";kid=\
"key-1"
"@signature-params": ("@method" "@authority" "@path" "signature-key")\
;created=1791275958
~~~

Expected headers:

~~~ http-message
Signature-Input: sig=("@method" "@authority" "@path" "signature-key")\
;created=1791275958
Signature: sig=:hax2E22o6oQkUArb0HXz18ozU+yAVxznnGfVeagC5efNdcrmUxAeQ\
JhW4hlV0LKab/KLuC09W38gzpVblVA4Aw==:
Signature-Key: sig=jwks;url="https://client.example/keys.jwks";kid="k\
ey-1"
~~~

Key material (private key included so the vector can be regenerated):

~~~ json
{
  "public_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
    "alg": "Ed25519",
    "kid": "key-1"
  },
  "private_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
    "alg": "Ed25519",
    "d": "ayuaMXaZDNNH9zOnyKYJM-AzageiMEuU_Si8nN3jvl8",
    "kid": "key-1"
  },
  "alg": "Ed25519"
}
~~~

Discovery documents:

~~~ json
{
  "jwks_url": "https://client.example/keys.jwks",
  "jwks": {
    "keys": [
      {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
        "alg": "Ed25519",
        "kid": "key-1",
        "use": "sig"
      }
    ]
  }
}
~~~

## A.6 jwt-cnf-ed25519 (`jwt`)

Issuer-minted assertion carrying the request key in cnf.jwk. exp is MUST, it is what bounds how long the confirmation key is accepted. No cache parameter, so no jti is required here.

Category **3** (reproduce the bytes). Evaluate at `now = 1791275958`.

Request:

~~~ http-message
GET https://resource.example/api/documents
Signature-Key: sig=jwt;jwt="eyJ0eXAiOiJhYS10b2tlbitqd3QiLCJhbGciOiJFU\
zI1NiIsImtpZCI6Imlzc3Vlci0xIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcG\
xlIiwiZHdrIjoiZXhhbXBsZS1jb25maWd1cmF0aW9uIiwic3ViIjoiaW5zdGFuY2UtMTI\
zIiwiaWF0IjoxNzkxMjc1ODk4LCJleHAiOjE3OTEyNzk1NTgsImNuZiI6eyJqd2siOnsi\
a3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJmRldHU1RIN1NOMWdvbDkxMU9Fc\
nExc1BGWFRfTEFHMjZ6QnRMbThJdEswIiwiYWxnIjoiRWQyNTUxOSJ9fX0.L6yxeGTrDj\
rtxkBL8yVyK_c3d7ZQ0Bywm6pwa0koBwkqBlQf8CxYnjX2-MgHQlLrNB6hHz03XfLQf_n\
Ml_MMqw"
~~~

Signature base (652 bytes, SHA-256 `95b3271f9cdbc0a714d2a6f56d415f14ba41d994e702aa8aa69a57c028c68c1a`):

~~~
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/documents
"signature-key": sig=jwt;jwt="eyJ0eXAiOiJhYS10b2tlbitqd3QiLCJhbGciOiJ\
FUzI1NiIsImtpZCI6Imlzc3Vlci0xIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFt\
cGxlIiwiZHdrIjoiZXhhbXBsZS1jb25maWd1cmF0aW9uIiwic3ViIjoiaW5zdGFuY2UtM\
TIzIiwiaWF0IjoxNzkxMjc1ODk4LCJleHAiOjE3OTEyNzk1NTgsImNuZiI6eyJqd2siOn\
sia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJmRldHU1RIN1NOMWdvbDkxMU9\
FcnExc1BGWFRfTEFHMjZ6QnRMbThJdEswIiwiYWxnIjoiRWQyNTUxOSJ9fX0.L6yxeGTr\
DjrtxkBL8yVyK_c3d7ZQ0Bywm6pwa0koBwkqBlQf8CxYnjX2-MgHQlLrNB6hHz03XfLQf\
_nMl_MMqw"
"@signature-params": ("@method" "@authority" "@path" "signature-key")\
;created=1791275958
~~~

Expected headers:

~~~ http-message
Signature-Input: sig=("@method" "@authority" "@path" "signature-key")\
;created=1791275958
Signature: sig=:1HxBKx3RIAZZq3kNTu5uI/t+SRIULoC9jOdDlBKWjLqNASjkVyKrb\
MAtGebndchE/5YYJkErft02o4kTVm0hCg==:
Signature-Key: sig=jwt;jwt="eyJ0eXAiOiJhYS10b2tlbitqd3QiLCJhbGciOiJFU\
zI1NiIsImtpZCI6Imlzc3Vlci0xIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcG\
xlIiwiZHdrIjoiZXhhbXBsZS1jb25maWd1cmF0aW9uIiwic3ViIjoiaW5zdGFuY2UtMTI\
zIiwiaWF0IjoxNzkxMjc1ODk4LCJleHAiOjE3OTEyNzk1NTgsImNuZiI6eyJqd2siOnsi\
a3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJmRldHU1RIN1NOMWdvbDkxMU9Fc\
nExc1BGWFRfTEFHMjZ6QnRMbThJdEswIiwiYWxnIjoiRWQyNTUxOSJ9fX0.L6yxeGTrDj\
rtxkBL8yVyK_c3d7ZQ0Bywm6pwa0koBwkqBlQf8CxYnjX2-MgHQlLrNB6hHz03XfLQf_n\
Ml_MMqw"
~~~

Key material (private key included so the vector can be regenerated):

~~~ json
{
  "public_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
    "alg": "Ed25519"
  },
  "private_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
    "alg": "Ed25519",
    "d": "ayuaMXaZDNNH9zOnyKYJM-AzageiMEuU_Si8nN3jvl8"
  },
  "alg": "Ed25519"
}
~~~

Assertion JWT:

~~~ json
{
  "compact": "eyJ0eXAiOiJhYS10b2tlbitqd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6Imlzc3Vlci0xIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiZHdrIjoiZXhhbXBsZS1jb25maWd1cmF0aW9uIiwic3ViIjoiaW5zdGFuY2UtMTIzIiwiaWF0IjoxNzkxMjc1ODk4LCJleHAiOjE3OTEyNzk1NTgsImNuZiI6eyJqd2siOnsia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJmRldHU1RIN1NOMWdvbDkxMU9FcnExc1BGWFRfTEFHMjZ6QnRMbThJdEswIiwiYWxnIjoiRWQyNTUxOSJ9fX0.L6yxeGTrDjrtxkBL8yVyK_c3d7ZQ0Bywm6pwa0koBwkqBlQf8CxYnjX2-MgHQlLrNB6hHz03XfLQf_nMl_MMqw",
  "header": {
    "typ": "aa-token+jwt",
    "alg": "ES256",
    "kid": "issuer-1"
  },
  "payload": {
    "iss": "https://issuer.example",
    "dwk": "example-configuration",
    "sub": "instance-123",
    "iat": 1791275898,
    "exp": 1791279558,
    "cnf": {
      "jwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
        "alg": "Ed25519"
      }
    }
  },
  "issuer_private_jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "FeP1mGKYah9mB84MDhWa_SVQwBJCwekoLgBwVW8KNJw",
    "y": "yeCJMBQJQSVOKU-zPNSre0zqA3iHngFJ6FyOxuLDoKI",
    "alg": "ES256",
    "d": "tShHC9KT4Yg25Gyp6ak2ZQTe6bL6kMSdVcdICrZDcyA"
  }
}
~~~

Discovery documents:

~~~ json
{
  "metadata_url": "https://issuer.example/.well-known/example-configuration",
  "metadata_document": {
    "issuer": "https://issuer.example",
    "jwks_uri": "https://issuer.example/jwks.json"
  },
  "jwks": {
    "keys": [
      {
        "kty": "EC",
        "crv": "P-256",
        "x": "FeP1mGKYah9mB84MDhWa_SVQwBJCwekoLgBwVW8KNJw",
        "y": "yeCJMBQJQSVOKU-zPNSre0zqA3iHngFJ6FyOxuLDoKI",
        "alg": "ES256",
        "kid": "issuer-1",
        "use": "sig"
      }
    ]
  }
}
~~~

## A.7 jwt-cnf-ed25519-cache-requested (`jwt`)

Same as jwt-cnf-ed25519 plus the cache parameter. Boolean true is serialised by omitting the value per RFC 9651 4.1.1.2, so it appears as 'cache' and not 'cache=?1'. A JWT presented with cache MUST carry jti; a verifier MUST NOT issue a cache identifier for one without it. The parameter sits inside the covered signature-key component, so the request signature covers the cache request itself.

Category **3** (reproduce the bytes). Evaluate at `now = 1791275958`.

Request:

~~~ http-message
GET https://resource.example/api/documents
Signature-Key: sig=jwt;jwt="eyJ0eXAiOiJhYS10b2tlbitqd3QiLCJhbGciOiJFU\
zI1NiIsImtpZCI6Imlzc3Vlci0xIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcG\
xlIiwiZHdrIjoiZXhhbXBsZS1jb25maWd1cmF0aW9uIiwic3ViIjoiaW5zdGFuY2UtMTI\
zIiwiaWF0IjoxNzkxMjc1ODk4LCJleHAiOjE3OTEyNzk1NTgsImp0aSI6IjRmMWE5Yzdl\
LTJiNjAtNGUyYS05ZjNkLTdjMWIwNWU4YTQxMiIsImNuZiI6eyJqd2siOnsia3R5IjoiT\
0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJmRldHU1RIN1NOMWdvbDkxMU9FcnExc1BGWF\
RfTEFHMjZ6QnRMbThJdEswIiwiYWxnIjoiRWQyNTUxOSJ9fX0.BIWrcFkw_98kLIQ88bZ\
WvAbGl8uzQlYbR2EIto9O5sXsaTjbF0ueFR56BTnAnSLqZNcnOTw5XEuBvWO0VZd8mg";\
cache
~~~

Signature base (718 bytes, SHA-256 `e6b4e994efc6ff5e6698e4fcf3fe45a17bf9021f1aee738b8136b26637b4cc50`):

~~~
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/documents
"signature-key": sig=jwt;jwt="eyJ0eXAiOiJhYS10b2tlbitqd3QiLCJhbGciOiJ\
FUzI1NiIsImtpZCI6Imlzc3Vlci0xIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFt\
cGxlIiwiZHdrIjoiZXhhbXBsZS1jb25maWd1cmF0aW9uIiwic3ViIjoiaW5zdGFuY2UtM\
TIzIiwiaWF0IjoxNzkxMjc1ODk4LCJleHAiOjE3OTEyNzk1NTgsImp0aSI6IjRmMWE5Yz\
dlLTJiNjAtNGUyYS05ZjNkLTdjMWIwNWU4YTQxMiIsImNuZiI6eyJqd2siOnsia3R5Ijo\
iT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJmRldHU1RIN1NOMWdvbDkxMU9FcnExc1BG\
WFRfTEFHMjZ6QnRMbThJdEswIiwiYWxnIjoiRWQyNTUxOSJ9fX0.BIWrcFkw_98kLIQ88\
bZWvAbGl8uzQlYbR2EIto9O5sXsaTjbF0ueFR56BTnAnSLqZNcnOTw5XEuBvWO0VZd8mg\
";cache
"@signature-params": ("@method" "@authority" "@path" "signature-key")\
;created=1791275958
~~~

Expected headers:

~~~ http-message
Signature-Input: sig=("@method" "@authority" "@path" "signature-key")\
;created=1791275958
Signature: sig=:G0DkIRPiTpJJals+kbFTDHr5HE+3FNYlXLDUGN3FN8C+fKLgwEjnV\
J0VSY1jL/2xJe6Q+OoUTvrLGUaYRYhFDA==:
Signature-Key: sig=jwt;jwt="eyJ0eXAiOiJhYS10b2tlbitqd3QiLCJhbGciOiJFU\
zI1NiIsImtpZCI6Imlzc3Vlci0xIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcG\
xlIiwiZHdrIjoiZXhhbXBsZS1jb25maWd1cmF0aW9uIiwic3ViIjoiaW5zdGFuY2UtMTI\
zIiwiaWF0IjoxNzkxMjc1ODk4LCJleHAiOjE3OTEyNzk1NTgsImp0aSI6IjRmMWE5Yzdl\
LTJiNjAtNGUyYS05ZjNkLTdjMWIwNWU4YTQxMiIsImNuZiI6eyJqd2siOnsia3R5IjoiT\
0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJmRldHU1RIN1NOMWdvbDkxMU9FcnExc1BGWF\
RfTEFHMjZ6QnRMbThJdEswIiwiYWxnIjoiRWQyNTUxOSJ9fX0.BIWrcFkw_98kLIQ88bZ\
WvAbGl8uzQlYbR2EIto9O5sXsaTjbF0ueFR56BTnAnSLqZNcnOTw5XEuBvWO0VZd8mg";\
cache
~~~

Key material (private key included so the vector can be regenerated):

~~~ json
{
  "public_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
    "alg": "Ed25519"
  },
  "private_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
    "alg": "Ed25519",
    "d": "ayuaMXaZDNNH9zOnyKYJM-AzageiMEuU_Si8nN3jvl8"
  },
  "alg": "Ed25519"
}
~~~

Assertion JWT:

~~~ json
{
  "compact": "eyJ0eXAiOiJhYS10b2tlbitqd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6Imlzc3Vlci0xIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiZHdrIjoiZXhhbXBsZS1jb25maWd1cmF0aW9uIiwic3ViIjoiaW5zdGFuY2UtMTIzIiwiaWF0IjoxNzkxMjc1ODk4LCJleHAiOjE3OTEyNzk1NTgsImp0aSI6IjRmMWE5YzdlLTJiNjAtNGUyYS05ZjNkLTdjMWIwNWU4YTQxMiIsImNuZiI6eyJqd2siOnsia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJmRldHU1RIN1NOMWdvbDkxMU9FcnExc1BGWFRfTEFHMjZ6QnRMbThJdEswIiwiYWxnIjoiRWQyNTUxOSJ9fX0.BIWrcFkw_98kLIQ88bZWvAbGl8uzQlYbR2EIto9O5sXsaTjbF0ueFR56BTnAnSLqZNcnOTw5XEuBvWO0VZd8mg",
  "jti": "4f1a9c7e-2b60-4e2a-9f3d-7c1b05e8a412",
  "issuer_private_jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "FeP1mGKYah9mB84MDhWa_SVQwBJCwekoLgBwVW8KNJw",
    "y": "yeCJMBQJQSVOKU-zPNSre0zqA3iHngFJ6FyOxuLDoKI",
    "alg": "ES256",
    "d": "tShHC9KT4Yg25Gyp6ak2ZQTe6bL6kMSdVcdICrZDcyA"
  }
}
~~~

## A.8 self-jwt-es256 (`self-jwt`)

Issuer and signer are the same party, so one key verifies both the JWT and the HTTP message signature. cnf MUST be absent, and a verifier MUST reject a self-jwt that carries one. No cache parameter is supported for this scheme. Both signatures are ECDSA, so neither reproduces byte for byte; compare the base and verify.

Category **2** (verify only). Evaluate at `now = 1791275958`.

Request:

~~~ http-message
GET https://resource.example/api/documents
Signature-Key: sig=self-jwt;jwt="eyJhbGciOiJFUzI1NiIsImtpZCI6InIxIiwi\
dHlwIjoiYWEtZXZlbnQrand0In0.eyJpc3MiOiJodHRwczovL3Jlc291cmNlLmV4YW1wb\
GUiLCJkd2siOiJhYXV0aC1yZXNvdXJjZS5qc29uIiwic3ViIjoicmVzb3VyY2UtaW5zdG\
FuY2UtNyIsImF1ZCI6Imh0dHBzOi8vY2xpZW50LmV4YW1wbGUiLCJpYXQiOjE3OTEyNzU\
4OTgsImV4cCI6MTc5MTI3NjI1OH0.z2SPEXnsUOoLJ-bO06SnGmyNbZNzRPePy1DK6MoD\
LppCDm501KkDd1-E-srRRAsqv9yVm4Sa9f1gMq4B9c0QZA"
~~~

Signature base (553 bytes, SHA-256 `a825885e35828998eca9d69d4ab7a559fd1665be8231ef08a6534ed4e114784e`):

~~~
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/documents
"signature-key": sig=self-jwt;jwt="eyJhbGciOiJFUzI1NiIsImtpZCI6InIxIi\
widHlwIjoiYWEtZXZlbnQrand0In0.eyJpc3MiOiJodHRwczovL3Jlc291cmNlLmV4YW1\
wbGUiLCJkd2siOiJhYXV0aC1yZXNvdXJjZS5qc29uIiwic3ViIjoicmVzb3VyY2UtaW5z\
dGFuY2UtNyIsImF1ZCI6Imh0dHBzOi8vY2xpZW50LmV4YW1wbGUiLCJpYXQiOjE3OTEyN\
zU4OTgsImV4cCI6MTc5MTI3NjI1OH0.z2SPEXnsUOoLJ-bO06SnGmyNbZNzRPePy1DK6M\
oDLppCDm501KkDd1-E-srRRAsqv9yVm4Sa9f1gMq4B9c0QZA"
"@signature-params": ("@method" "@authority" "@path" "signature-key")\
;created=1791275958
~~~

Expected headers:

~~~ http-message
Signature-Input: sig=("@method" "@authority" "@path" "signature-key")\
;created=1791275958
Signature: sig=:zBdIx9OM4aeF+tMRejtIQ+ilDF7kqPJTHM60h4i/3KfnjrSlS2o2f\
agLpzT0hhNQllb6wofFIbINuAbxYhqPaQ==:
Signature-Key: sig=self-jwt;jwt="eyJhbGciOiJFUzI1NiIsImtpZCI6InIxIiwi\
dHlwIjoiYWEtZXZlbnQrand0In0.eyJpc3MiOiJodHRwczovL3Jlc291cmNlLmV4YW1wb\
GUiLCJkd2siOiJhYXV0aC1yZXNvdXJjZS5qc29uIiwic3ViIjoicmVzb3VyY2UtaW5zdG\
FuY2UtNyIsImF1ZCI6Imh0dHBzOi8vY2xpZW50LmV4YW1wbGUiLCJpYXQiOjE3OTEyNzU\
4OTgsImV4cCI6MTc5MTI3NjI1OH0.z2SPEXnsUOoLJ-bO06SnGmyNbZNzRPePy1DK6MoD\
LppCDm501KkDd1-E-srRRAsqv9yVm4Sa9f1gMq4B9c0QZA"
~~~

Key material (private key included so the vector can be regenerated):

~~~ json
{
  "public_jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "O_YFetRBPCTH_hO_6u1i831NuiDvylj2TVur0NVMFCI",
    "y": "b5XNSg6r7m5JxUuU5JVa5n8qaCrCpTCu_SbKZRic6Ow",
    "alg": "ES256",
    "kid": "r1"
  },
  "private_jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "O_YFetRBPCTH_hO_6u1i831NuiDvylj2TVur0NVMFCI",
    "y": "b5XNSg6r7m5JxUuU5JVa5n8qaCrCpTCu_SbKZRic6Ow",
    "alg": "ES256",
    "d": "PBxVLgAOFnlY33Y-kU4FyVRfbET7sddy-tO2M3qb_Vw",
    "kid": "r1"
  },
  "alg": "ES256"
}
~~~

Assertion JWT:

~~~ json
{
  "compact": "eyJhbGciOiJFUzI1NiIsImtpZCI6InIxIiwidHlwIjoiYWEtZXZlbnQrand0In0.eyJpc3MiOiJodHRwczovL3Jlc291cmNlLmV4YW1wbGUiLCJkd2siOiJhYXV0aC1yZXNvdXJjZS5qc29uIiwic3ViIjoicmVzb3VyY2UtaW5zdGFuY2UtNyIsImF1ZCI6Imh0dHBzOi8vY2xpZW50LmV4YW1wbGUiLCJpYXQiOjE3OTEyNzU4OTgsImV4cCI6MTc5MTI3NjI1OH0.z2SPEXnsUOoLJ-bO06SnGmyNbZNzRPePy1DK6MoDLppCDm501KkDd1-E-srRRAsqv9yVm4Sa9f1gMq4B9c0QZA",
  "header": {
    "alg": "ES256",
    "kid": "r1",
    "typ": "aa-event+jwt"
  },
  "payload": {
    "iss": "https://resource.example",
    "dwk": "aauth-resource.json",
    "sub": "resource-instance-7",
    "aud": "https://client.example",
    "iat": 1791275898,
    "exp": 1791276258
  },
  "cnf_present": false
}
~~~

Discovery documents:

~~~ json
{
  "metadata_url": "https://resource.example/.well-known/aauth-resource.json",
  "metadata_document": {
    "issuer": "https://resource.example",
    "jwks_uri": "https://resource.example/jwks.json"
  },
  "jwks": {
    "keys": [
      {
        "kty": "EC",
        "crv": "P-256",
        "x": "O_YFetRBPCTH_hO_6u1i831NuiDvylj2TVur0NVMFCI",
        "y": "b5XNSg6r7m5JxUuU5JVa5n8qaCrCpTCu_SbKZRic6Ow",
        "alg": "ES256",
        "kid": "r1",
        "use": "sig"
      }
    ]
  }
}
~~~

## A.9 multi-signature-hwk-and-jwks (`hwk+jwks`)

Both labels cover signature-key, and the COMPLETE Signature-Key header was populated before either signature was made, so each signature protects both members' key material. Both labels therefore share one identical signature base. Label correlation is by equality of label name across Signature-Input, Signature and Signature-Key.

Category **3** (reproduce the bytes). Evaluate at `now = 1791275958`.

Request:

~~~ http-message
GET https://resource.example/api/documents
Signature-Key: sig1=hwk;kty="OKP";crv="Ed25519";x="fFWGSTH7SN1gol911O\
Erq1sPFXT_LAG26zBtLm8ItK0";alg="Ed25519", sig2=jwks;url="https://clie\
nt.example/keys.jwks";kid="key-1"
~~~

Signature base (332 bytes, SHA-256 `f423c698cf6119e6f868a00dd19879fd5baefedf0284bb529f17ed2ae5045664`):

~~~
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/documents
"signature-key": sig1=hwk;kty="OKP";crv="Ed25519";x="fFWGSTH7SN1gol91\
1OErq1sPFXT_LAG26zBtLm8ItK0";alg="Ed25519", sig2=jwks;url="https://cl\
ient.example/keys.jwks";kid="key-1"
"@signature-params": ("@method" "@authority" "@path" "signature-key")\
;created=1791275958
~~~

Expected headers:

~~~ http-message
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key"\
);created=1791275958, sig2=("@method" "@authority" "@path" "signature\
-key");created=1791275958
Signature: sig1=:99MzcYUGrhQKu1cFKJ1XZwHcLB6RX46znii9bmMzD6LNCH7ePFhF\
klB4ZZMj3MkjGOsx8AHdofJmcsvVF0M9CA==:, sig2=:99MzcYUGrhQKu1cFKJ1XZwHc\
LB6RX46znii9bmMzD6LNCH7ePFhFklB4ZZMj3MkjGOsx8AHdofJmcsvVF0M9CA==:
Signature-Key: sig1=hwk;kty="OKP";crv="Ed25519";x="fFWGSTH7SN1gol911O\
Erq1sPFXT_LAG26zBtLm8ItK0";alg="Ed25519", sig2=jwks;url="https://clie\
nt.example/keys.jwks";kid="key-1"
~~~

Key material (private key included so the vector can be regenerated):

~~~ json
{
  "public_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
    "alg": "Ed25519"
  },
  "private_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
    "alg": "Ed25519",
    "d": "ayuaMXaZDNNH9zOnyKYJM-AzageiMEuU_Si8nN3jvl8"
  },
  "alg": "Ed25519"
}
~~~

## A.10 mldsa-44-verify-only (`jwks`)

Verify-only, category 2. ML-DSA sits here on exactly the same footing as ECDSA and RSA-PSS: FIPS 204 specifies the hedged variant as the default, so a second run produces a different signature. Signature is 2420 bytes. Verification is deterministic, so any implementation supporting the algorithm gets a definite answer from this vector. ML-DSA-44 key, 1312 byte public value per FIPS 204, carried as the AKP key type of RFC 9964 with the algorithm named by alg rather than derivable from the key structure.

Category **2** (verify only). Evaluate at `now = 1791275958`.

Request:

~~~ http-message
GET https://resource.example/api/documents
Signature-Key: sig=jwks;url="https://client.example/pq.jwks";kid="pq-\
1"
~~~

Signature base (232 bytes, SHA-256 `b6255d6e2ad56512fe78ae6671c48fbe4fead0abf1062102b3dab5acacc7a4a1`):

~~~
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/documents
"signature-key": sig=jwks;url="https://client.example/pq.jwks";kid="p\
q-1"
"@signature-params": ("@method" "@authority" "@path" "signature-key")\
;created=1791275958
~~~

Expected headers:

~~~ http-message
Signature-Input: sig=("@method" "@authority" "@path" "signature-key")\
;created=1791275958
Signature: sig=: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\
=:
Signature-Key: sig=jwks;url="https://client.example/pq.jwks";kid="pq-\
1"
~~~

Key material (private key included so the vector can be regenerated):

~~~ json
{
  "public_jwk": {
    "kty": "AKP",
    "alg": "ML-DSA-44",
    "pub": "Nj5z9pTufI_vJzX9S2eUNrbC9D6QKfGXTUxwwlBl6w0HpZVJUs0wqXjufY1Zr_w-yNCP-aOemR3xVS70-DdKkGhTc7vKd6XZhgyzi40W2zfMbXKZDpgxCW_-eT-HDHXb6v22Uf6nN3ST_BKqrNwBExKj85Uszy5QBkS3tfxumJj2xpzl1GwnRg62sxzuo243b5pB-cuzSYKwoDUq6TTTYwXHOUSygcad8V-OC5tQsOBqF9QQVbHtrMczRrP_0B_Utq3zDsdJFSPq34SIoOkuj4lhIgaG3IC6weGV84d7sWNROA_bOXv2nKGGaqSKLwT2kZ2-OI2oYm1IoBfZaRs7W3CAMWSsBtBWyQahLuxiuvjTIWnzf6L_5J50Srmpn8500vUjLJGUHxD8XjYciqtZ6pjmmIxWESmH_NxpLDF0dfC4gAG1KkHLuYTiG9IdCbiuocMjK3WieIbTvrmOR1ZZbI5VQe2Pp326lvdWGE6MKlLRAmaJlFfB89CWdcjU0eXVaXZLjiUiyo03Duq9mFV13bh5f5VRUp2qgYrp5dv_5B8AsowIsG2fyoC5rVCUnmC2of8FF9r2BP8yrdl2hFIXbO0WStgla8dM_46qDYH5bHhKxWbQ-VYhRMOKN04AGEfesCFFjMKI7bk0g8fqR4bZs-UI88edC9q0kHN5tW3gUd9tsaYdR5Rf7Ah0GX5pIxdW5M9WesP5iW_jucj4zajs4nmLWKyBba3s-SQLbBDIhaWug68AVcCwIi8O5z6_EOERw-hT30t5wjJRsfU8ffVHsUV7362o7rJRXKTWcftHA9PP_iAOPuZSbUoTRivkgvCHY7L5ndUJ9kCtEOE_8BKA4YgH3FQtIES-OveuXGXC6hiGOTXxm-v-XVg_54CAw4TBxsAzRFgf_zfBMzikl3uusaZbjiT09qHfTYzI4zJ1zKpxEFe0ml96ggMaUtp29Ma1Ncd3I5o3Q3D0_NRRR_-XkG_WQzc4UC5e-vnjX2Err1xCGeYJS-DamgWiXbmoZroFbODuqxJw_2yho3K9Bb0aiEfQujVyYJ2a01RqUyH8h4oSlQmuHtOwDS9jNJFOQznvsSZD0FrQPqhVk7jnUTqAFBNBCuKF8KPu5DnUBiXgehC5tvcquM9KeHYwulkluB-_FVGico7Pvw_vNuY1bjDOM0avPVsCjkC0ZrgRksQmmsmL2PJjK0EhSMTl0cv4pvBz7GCHPtS9bqCxOnaPTCe23OlWiHsIol9OVNrTsE4KFQkBZait49Y0aBfjYilWwrD7RZY83Fn-g010YWc5ULROTmcwrru1hPs61Zt_biQhs4D7JVj-pL71yy7-0Flw1HfvbQMHtMES_yMcpHaGLFYunFKdYyS3BnYeWdkf6dvqCLDGnI6m25eE4T15RDfQWcGLdsld4QZVRRcu9XpjouG4iaAw0ImySCwC5cmpgB_RPAJiHRnU2JmnQj-on2CRKtRDMXvomA1WXM1Xbp_nRaEwoNFCGjhjIqb3DtSDfIrP8dCd516sw9E5uUqIrE7kzG0N9UeJCxPJT3gaGFkwvy1KDrjFCXiOq-GtrC9uEffDdvCyF1t5qfPsFpEkIAA9GxN6eUzxY5VAmzaFisjFXtw3gp5TRH1rSDMjAZdKZZaHUBsOS83An6Cgm-j1zdZpHg8rqSn7yPlMNew9RpDoJt2X7mwiMv6CgsDZQDmPbHu401yswPrZKdqO_AqKmU9kIog4Puc64VN_Bsov7p1-sC1WmQ",
    "kid": "pq-1"
  },
  "private_jwk": {
    "kty": "AKP",
    "alg": "ML-DSA-44",
    "pub": "Nj5z9pTufI_vJzX9S2eUNrbC9D6QKfGXTUxwwlBl6w0HpZVJUs0wqXjufY1Zr_w-yNCP-aOemR3xVS70-DdKkGhTc7vKd6XZhgyzi40W2zfMbXKZDpgxCW_-eT-HDHXb6v22Uf6nN3ST_BKqrNwBExKj85Uszy5QBkS3tfxumJj2xpzl1GwnRg62sxzuo243b5pB-cuzSYKwoDUq6TTTYwXHOUSygcad8V-OC5tQsOBqF9QQVbHtrMczRrP_0B_Utq3zDsdJFSPq34SIoOkuj4lhIgaG3IC6weGV84d7sWNROA_bOXv2nKGGaqSKLwT2kZ2-OI2oYm1IoBfZaRs7W3CAMWSsBtBWyQahLuxiuvjTIWnzf6L_5J50Srmpn8500vUjLJGUHxD8XjYciqtZ6pjmmIxWESmH_NxpLDF0dfC4gAG1KkHLuYTiG9IdCbiuocMjK3WieIbTvrmOR1ZZbI5VQe2Pp326lvdWGE6MKlLRAmaJlFfB89CWdcjU0eXVaXZLjiUiyo03Duq9mFV13bh5f5VRUp2qgYrp5dv_5B8AsowIsG2fyoC5rVCUnmC2of8FF9r2BP8yrdl2hFIXbO0WStgla8dM_46qDYH5bHhKxWbQ-VYhRMOKN04AGEfesCFFjMKI7bk0g8fqR4bZs-UI88edC9q0kHN5tW3gUd9tsaYdR5Rf7Ah0GX5pIxdW5M9WesP5iW_jucj4zajs4nmLWKyBba3s-SQLbBDIhaWug68AVcCwIi8O5z6_EOERw-hT30t5wjJRsfU8ffVHsUV7362o7rJRXKTWcftHA9PP_iAOPuZSbUoTRivkgvCHY7L5ndUJ9kCtEOE_8BKA4YgH3FQtIES-OveuXGXC6hiGOTXxm-v-XVg_54CAw4TBxsAzRFgf_zfBMzikl3uusaZbjiT09qHfTYzI4zJ1zKpxEFe0ml96ggMaUtp29Ma1Ncd3I5o3Q3D0_NRRR_-XkG_WQzc4UC5e-vnjX2Err1xCGeYJS-DamgWiXbmoZroFbODuqxJw_2yho3K9Bb0aiEfQujVyYJ2a01RqUyH8h4oSlQmuHtOwDS9jNJFOQznvsSZD0FrQPqhVk7jnUTqAFBNBCuKF8KPu5DnUBiXgehC5tvcquM9KeHYwulkluB-_FVGico7Pvw_vNuY1bjDOM0avPVsCjkC0ZrgRksQmmsmL2PJjK0EhSMTl0cv4pvBz7GCHPtS9bqCxOnaPTCe23OlWiHsIol9OVNrTsE4KFQkBZait49Y0aBfjYilWwrD7RZY83Fn-g010YWc5ULROTmcwrru1hPs61Zt_biQhs4D7JVj-pL71yy7-0Flw1HfvbQMHtMES_yMcpHaGLFYunFKdYyS3BnYeWdkf6dvqCLDGnI6m25eE4T15RDfQWcGLdsld4QZVRRcu9XpjouG4iaAw0ImySCwC5cmpgB_RPAJiHRnU2JmnQj-on2CRKtRDMXvomA1WXM1Xbp_nRaEwoNFCGjhjIqb3DtSDfIrP8dCd516sw9E5uUqIrE7kzG0N9UeJCxPJT3gaGFkwvy1KDrjFCXiOq-GtrC9uEffDdvCyF1t5qfPsFpEkIAA9GxN6eUzxY5VAmzaFisjFXtw3gp5TRH1rSDMjAZdKZZaHUBsOS83An6Cgm-j1zdZpHg8rqSn7yPlMNew9RpDoJt2X7mwiMv6CgsDZQDmPbHu401yswPrZKdqO_AqKmU9kIog4Puc64VN_Bsov7p1-sC1WmQ",
    "priv": "Nj5z9pTufI_vJzX9S2eUNrbC9D6QKfGXTUxwwlBl6w1caTu9cI1zgQ-4MWV7z7GBs556zkfW3k_6jOMIXaewFphMQoxy79ofuibiJQrhgI4n8mNtWZr7c0Axv8foFcjO3J204-oIdVdL5KNuFW8GQ8Jp4BsYzXC4f0e5XY4HjBcKiBFiFCCYAEzBwGyEJDCIEgFTIjGRsEkJoigkEG1ENozJAA4KRWUJhSQatoVhpC3hJowSEwjYEiFbmAjIEGHkhABYGGYhGYEZAlDDkIACOUQgpiUYISSahCACAU0aCAYEuU3ctgXUFiZipgwgky3aknBZCCyLRCTJsGHSkoxYkIAiRkUcIoqTyGQCSCGhJGSaQEEJoCEBtEnbImGUkFCIpEAjJjABk2gCQkDkQGDcxDGKMHCEtAXgJCqRphHiSEGTJIWQRCojlmkByVACl0CbJgzQAIIKyJFTFgogyS0kIomMAJIKgpGRJoYUs2jRmGxjkGWjSEgZxAwYxhDgIEgUhgQYoxEZwTGLiGUBhIQbgCgbBSUQJCQhhoSRQAaZME4QOGwgRQjYkEgAkIQREHAaFQlElAwhAAHIAgbZBEgcR42III5EFlFhwIkMqSUMQ4mLoC0ZAQ4kCIISwSQSgmyZIlEbxQwhIDIaBIWJpC2CRo3SooEkA4JhsIhKQpIBAJERiRAhGEKiiC0UQIJbpGgSR4CDMAhgQCigsoggIkghGSJZqCSMBBIBGYURtAVMEkUYwGjQBI4AsQ1TpCEbgnHUMITLBArRRgEkAiBARiUaJ0RMpGGZNkLkwhFLNizJsDEUF4zDEhLBgJDRGIyCNCBEsJCjJmJROAEkNGZTsJEikDCiAEATlZGCFFCggoRYQGmRMgWjKBFgQDDAJI5KFAQDSGITh4VTiEWYNIIDqEzQuGmKJhJDADFbMGgkMSQQkChJhEEBRUQjQ4SAJk1AtC0ABwCLEmHSOCkChQ3jkE1EwGUTmVEEs5FcKIjRGE2gMoTcxkERxilDsnESBWCZAm4DuISQKHIDkRCUMmhJkpAQmRFCIiAMuIARAS7DlhBDRoBAAmDBRgDjQIaJBC1DhmmZxHABNCQCIVCACAAkMRISwoEYSIUkoQHcKElZxBAjKUkSQiKYpjCCuGDRoomcuGkDKQ2LJgKUGERZFkiKEEDktIgSKQZLIJDjAoQUiDHgmGDcp92TKG1rPc_M_c_Krn2PZRwWBWTnbot5VkZhjzcOFnlmUTqsxwRdYeV5CkIZe1UMZKlYXqAoZMxzZN3mRIG1nESgmIQtbbBjzj97dBxfRIUTymNuRzUP7f11xzeB6D7lTsIvUA4LPxc9r1XQ8JXgqWIeOiaEol8MEel88nTm_LfPQGczFWcbzcDq_o-mvAmHk68ARyXarbV4sOwMMv0L-bEXId6D2oJPZ66hArqhooHqyx_uJzOqsZHywOYuWhromRNr0h8ZtsssOXlrtiArezLKxMKzc-rRaiYqroWqcSY7GOI1eG5Q6XhF1NCj7pszNUH_CpRG4lfwIJeI-hYX4XzPTNuVx87lKae1QU7n2nzNJxe2rmGllTL3EPSjYqIoTv9fLmVDMUpczL13RBGGhvswf_kfaPaOFm-nEtg9BmR2HkQfFbJXYQNG93qya9cpsFOc10DO-wJ_Ydzp57n3gK3r9ZfuoGmtFrujjzCyYgPJAcoBeWbVgLjOFisq0BMugZ6l7ZJzO7i5pM3iDpsouEAWajsvoq3XP4odI-coN6Wfd9uNTO8O7lJrFoJyXxmU7y15O1Y7aNdAk90MPmuWio8O4AEnQhTb2CPvgvV6QEjDz6WQSehRs9ao5f5C2l0y8pLZ4ubU--10WV_wQoQU-mvMSvDhiukUXShD1jzkTavQuCQeLJK_67o0QyEc7IHtWZvcr-cISZDZE4cN6BrciNhQm7uEjGlCk6QAQCqrOwwLqPsj5CXJscxbrICxR797Hiw87FC52Bdogkn-WUHwn9d4k6NGk0w82RlWzur9G17gCi5OWx6nEsipIPywyAGExOJ0rRapv1z7tv43U9SwleeNo7jQNrPs_CKXcQOhsLk3d3EQJVOhKjEh0zMiwCk5Ow5pHUWeOYo9ZO-_XDAncjMxiDCM4h36z2eUW3M2dLpPl5PywwjY14zwBENVXbddsryqFdRgyyNoTj8-d_SmfWz1pcC1fUijn0Zw_uU-rvS96o7pcCba5bYqT1IyNjuIBkknqdk3WM0b-gkIy-ZDDU4xeiLtxudjQ4MzDjlrecRAPVRnEdCB9R-nEpiM0-ClS7t0nzgjOWp_4qcKYWxzdA3syG7c8o7LySGmsUPT1eNzFcEQqU47xSP1lD91CGZgfRUiTep9s93iI0hWGWH_w9N1ZhKCh7b0AQB5TSlZlUu3lydYyfBmUfyWYQFHjlekudWWzYiCNzZQO4jkM3B0T-q2fouMBMqL23JaJ8GyyUO7je09jI2IFwcbcUx1ioB5ltO49DcLnGmK7tN7rx2bS4e7orLYFPNc03QPmI7YWoScK_pWXkyFtbdb1WpGJVQA7F_KURRrKw71WYJJ_aHz4nPjPrve7CcNOyodoWHGrwuCWYpRIn4gyXRjD7R780yfS3vO50I1PrsR_WiWf5hEo_t6EWJ_fMQScmp7UyrcpudwcywG8lIfrlE158ha5eCjPdge5I1QOEQutZiqTsk_aqU3MQeX03oer922Yd2fem5Q74hsEWwwXMUQ4_5Dcqr2-JO4qc_lq1q8MvaWqWlgtRUymzEXv3qoln7QApnKvunk7ZrDbV1U8gSwILD27ZWRlsJScQs8RhXbtukTqQlo9NcdNLfGgSa8dB8SUtyfwt_vGQ4VcNLbsRI9V_fk-oBMi3pQyRXz8kD0l0lyg17yer1e-Kpt8YpsKco4A0AAT2UyJj6UxkofXQzdgfpDJV7djP9zLiIhzgNTde9PaUp48GLJ644pWhvP4Jd433sirV1gKtFFg6op85-knLzHsTgfDucL_urUxMXZC2cLy9OfMpXzKafxhOMv7EUkCO5Bkm-hfXZol41j8odgooX0YoZUANiN9MqUmb7DeDJpTUZOD33gj6rAqehyKhFL1YyC-84BaykPVEeSXT_iQ0FuHluAJfi6YVX6J2c-c8eovJ_qwn2HihBd1o0oln0DAdlUJfKCoVgIhluC7M6tXxFe0PnqqTyBk-y57uv6rnM6eRJOlHWMCTHLxfcDcueoGPCeBICMo9qqID_6ROeEuFekRdxNRoxtCTGh0NhUNsEEQk7LMTLabTCoMTD9U99ldujsDfZaBsJZA3oN3XcjQWH7RYPS9n4638gdbZCCXIivgPq2Wo_LC_X2emI2BRqcJ2T5UjoSgA-cQV7L5F_mL3TXwGq61sinuL94iE-N9HvCpnpMu1caCNNg-iLsgIU5qD7PLQ",
    "kid": "pq-1"
  },
  "alg": "ML-DSA-44"
}
~~~

Discovery documents:

~~~ json
{
  "jwks_url": "https://client.example/pq.jwks",
  "jwks": {
    "keys": [
      {
        "kty": "AKP",
        "alg": "ML-DSA-44",
        "pub": "Nj5z9pTufI_vJzX9S2eUNrbC9D6QKfGXTUxwwlBl6w0HpZVJUs0wqXjufY1Zr_w-yNCP-aOemR3xVS70-DdKkGhTc7vKd6XZhgyzi40W2zfMbXKZDpgxCW_-eT-HDHXb6v22Uf6nN3ST_BKqrNwBExKj85Uszy5QBkS3tfxumJj2xpzl1GwnRg62sxzuo243b5pB-cuzSYKwoDUq6TTTYwXHOUSygcad8V-OC5tQsOBqF9QQVbHtrMczRrP_0B_Utq3zDsdJFSPq34SIoOkuj4lhIgaG3IC6weGV84d7sWNROA_bOXv2nKGGaqSKLwT2kZ2-OI2oYm1IoBfZaRs7W3CAMWSsBtBWyQahLuxiuvjTIWnzf6L_5J50Srmpn8500vUjLJGUHxD8XjYciqtZ6pjmmIxWESmH_NxpLDF0dfC4gAG1KkHLuYTiG9IdCbiuocMjK3WieIbTvrmOR1ZZbI5VQe2Pp326lvdWGE6MKlLRAmaJlFfB89CWdcjU0eXVaXZLjiUiyo03Duq9mFV13bh5f5VRUp2qgYrp5dv_5B8AsowIsG2fyoC5rVCUnmC2of8FF9r2BP8yrdl2hFIXbO0WStgla8dM_46qDYH5bHhKxWbQ-VYhRMOKN04AGEfesCFFjMKI7bk0g8fqR4bZs-UI88edC9q0kHN5tW3gUd9tsaYdR5Rf7Ah0GX5pIxdW5M9WesP5iW_jucj4zajs4nmLWKyBba3s-SQLbBDIhaWug68AVcCwIi8O5z6_EOERw-hT30t5wjJRsfU8ffVHsUV7362o7rJRXKTWcftHA9PP_iAOPuZSbUoTRivkgvCHY7L5ndUJ9kCtEOE_8BKA4YgH3FQtIES-OveuXGXC6hiGOTXxm-v-XVg_54CAw4TBxsAzRFgf_zfBMzikl3uusaZbjiT09qHfTYzI4zJ1zKpxEFe0ml96ggMaUtp29Ma1Ncd3I5o3Q3D0_NRRR_-XkG_WQzc4UC5e-vnjX2Err1xCGeYJS-DamgWiXbmoZroFbODuqxJw_2yho3K9Bb0aiEfQujVyYJ2a01RqUyH8h4oSlQmuHtOwDS9jNJFOQznvsSZD0FrQPqhVk7jnUTqAFBNBCuKF8KPu5DnUBiXgehC5tvcquM9KeHYwulkluB-_FVGico7Pvw_vNuY1bjDOM0avPVsCjkC0ZrgRksQmmsmL2PJjK0EhSMTl0cv4pvBz7GCHPtS9bqCxOnaPTCe23OlWiHsIol9OVNrTsE4KFQkBZait49Y0aBfjYilWwrD7RZY83Fn-g010YWc5ULROTmcwrru1hPs61Zt_biQhs4D7JVj-pL71yy7-0Flw1HfvbQMHtMES_yMcpHaGLFYunFKdYyS3BnYeWdkf6dvqCLDGnI6m25eE4T15RDfQWcGLdsld4QZVRRcu9XpjouG4iaAw0ImySCwC5cmpgB_RPAJiHRnU2JmnQj-on2CRKtRDMXvomA1WXM1Xbp_nRaEwoNFCGjhjIqb3DtSDfIrP8dCd516sw9E5uUqIrE7kzG0N9UeJCxPJT3gaGFkwvy1KDrjFCXiOq-GtrC9uEffDdvCyF1t5qfPsFpEkIAA9GxN6eUzxY5VAmzaFisjFXtw3gp5TRH1rSDMjAZdKZZaHUBsOS83An6Cgm-j1zdZpHg8rqSn7yPlMNew9RpDoJt2X7mwiMv6CgsDZQDmPbHu401yswPrZKdqO_AqKmU9kIog4Puc64VN_Bsov7p1-sC1WmQ",
        "kid": "pq-1",
        "use": "sig"
      }
    ]
  }
}
~~~

## A.11 mldsa-44-deterministic-optional (`jwks`)

The same base as mldsa-44-verify-only, signed with the deterministic variant of FIPS 204, where rnd is all zeros. The hedged variant degrades to exactly this when the RBG returns zeros, so an implementation that can inject rnd reproduces these bytes. Most libraries do not expose that knob, so this vector is OPTIONAL and MUST NOT be required to pass. It is published because for the implementations that can reach it, it is the only ML-DSA vector that tests a SIGNER rather than a verifier. ML-DSA-44 key, 1312 byte public value per FIPS 204, carried as the AKP key type of RFC 9964 with the algorithm named by alg rather than derivable from the key structure.

Category **3** (reproduce the bytes), **OPTIONAL**. Evaluate at `now = 1791275958`.

Request:

~~~ http-message
GET https://resource.example/api/documents
Signature-Key: sig=jwks;url="https://client.example/pq.jwks";kid="pq-\
1"
~~~

Signature base (232 bytes, SHA-256 `b6255d6e2ad56512fe78ae6671c48fbe4fead0abf1062102b3dab5acacc7a4a1`):

~~~
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/documents
"signature-key": sig=jwks;url="https://client.example/pq.jwks";kid="p\
q-1"
"@signature-params": ("@method" "@authority" "@path" "signature-key")\
;created=1791275958
~~~

Expected headers:

~~~ http-message
Signature-Input: sig=("@method" "@authority" "@path" "signature-key")\
;created=1791275958
Signature: sig=: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\
=:
Signature-Key: sig=jwks;url="https://client.example/pq.jwks";kid="pq-\
1"
~~~

Key material (private key included so the vector can be regenerated):

~~~ json
{
  "public_jwk": {
    "kty": "AKP",
    "alg": "ML-DSA-44",
    "pub": "Nj5z9pTufI_vJzX9S2eUNrbC9D6QKfGXTUxwwlBl6w0HpZVJUs0wqXjufY1Zr_w-yNCP-aOemR3xVS70-DdKkGhTc7vKd6XZhgyzi40W2zfMbXKZDpgxCW_-eT-HDHXb6v22Uf6nN3ST_BKqrNwBExKj85Uszy5QBkS3tfxumJj2xpzl1GwnRg62sxzuo243b5pB-cuzSYKwoDUq6TTTYwXHOUSygcad8V-OC5tQsOBqF9QQVbHtrMczRrP_0B_Utq3zDsdJFSPq34SIoOkuj4lhIgaG3IC6weGV84d7sWNROA_bOXv2nKGGaqSKLwT2kZ2-OI2oYm1IoBfZaRs7W3CAMWSsBtBWyQahLuxiuvjTIWnzf6L_5J50Srmpn8500vUjLJGUHxD8XjYciqtZ6pjmmIxWESmH_NxpLDF0dfC4gAG1KkHLuYTiG9IdCbiuocMjK3WieIbTvrmOR1ZZbI5VQe2Pp326lvdWGE6MKlLRAmaJlFfB89CWdcjU0eXVaXZLjiUiyo03Duq9mFV13bh5f5VRUp2qgYrp5dv_5B8AsowIsG2fyoC5rVCUnmC2of8FF9r2BP8yrdl2hFIXbO0WStgla8dM_46qDYH5bHhKxWbQ-VYhRMOKN04AGEfesCFFjMKI7bk0g8fqR4bZs-UI88edC9q0kHN5tW3gUd9tsaYdR5Rf7Ah0GX5pIxdW5M9WesP5iW_jucj4zajs4nmLWKyBba3s-SQLbBDIhaWug68AVcCwIi8O5z6_EOERw-hT30t5wjJRsfU8ffVHsUV7362o7rJRXKTWcftHA9PP_iAOPuZSbUoTRivkgvCHY7L5ndUJ9kCtEOE_8BKA4YgH3FQtIES-OveuXGXC6hiGOTXxm-v-XVg_54CAw4TBxsAzRFgf_zfBMzikl3uusaZbjiT09qHfTYzI4zJ1zKpxEFe0ml96ggMaUtp29Ma1Ncd3I5o3Q3D0_NRRR_-XkG_WQzc4UC5e-vnjX2Err1xCGeYJS-DamgWiXbmoZroFbODuqxJw_2yho3K9Bb0aiEfQujVyYJ2a01RqUyH8h4oSlQmuHtOwDS9jNJFOQznvsSZD0FrQPqhVk7jnUTqAFBNBCuKF8KPu5DnUBiXgehC5tvcquM9KeHYwulkluB-_FVGico7Pvw_vNuY1bjDOM0avPVsCjkC0ZrgRksQmmsmL2PJjK0EhSMTl0cv4pvBz7GCHPtS9bqCxOnaPTCe23OlWiHsIol9OVNrTsE4KFQkBZait49Y0aBfjYilWwrD7RZY83Fn-g010YWc5ULROTmcwrru1hPs61Zt_biQhs4D7JVj-pL71yy7-0Flw1HfvbQMHtMES_yMcpHaGLFYunFKdYyS3BnYeWdkf6dvqCLDGnI6m25eE4T15RDfQWcGLdsld4QZVRRcu9XpjouG4iaAw0ImySCwC5cmpgB_RPAJiHRnU2JmnQj-on2CRKtRDMXvomA1WXM1Xbp_nRaEwoNFCGjhjIqb3DtSDfIrP8dCd516sw9E5uUqIrE7kzG0N9UeJCxPJT3gaGFkwvy1KDrjFCXiOq-GtrC9uEffDdvCyF1t5qfPsFpEkIAA9GxN6eUzxY5VAmzaFisjFXtw3gp5TRH1rSDMjAZdKZZaHUBsOS83An6Cgm-j1zdZpHg8rqSn7yPlMNew9RpDoJt2X7mwiMv6CgsDZQDmPbHu401yswPrZKdqO_AqKmU9kIog4Puc64VN_Bsov7p1-sC1WmQ",
    "kid": "pq-1"
  },
  "private_jwk": {
    "kty": "AKP",
    "alg": "ML-DSA-44",
    "pub": "Nj5z9pTufI_vJzX9S2eUNrbC9D6QKfGXTUxwwlBl6w0HpZVJUs0wqXjufY1Zr_w-yNCP-aOemR3xVS70-DdKkGhTc7vKd6XZhgyzi40W2zfMbXKZDpgxCW_-eT-HDHXb6v22Uf6nN3ST_BKqrNwBExKj85Uszy5QBkS3tfxumJj2xpzl1GwnRg62sxzuo243b5pB-cuzSYKwoDUq6TTTYwXHOUSygcad8V-OC5tQsOBqF9QQVbHtrMczRrP_0B_Utq3zDsdJFSPq34SIoOkuj4lhIgaG3IC6weGV84d7sWNROA_bOXv2nKGGaqSKLwT2kZ2-OI2oYm1IoBfZaRs7W3CAMWSsBtBWyQahLuxiuvjTIWnzf6L_5J50Srmpn8500vUjLJGUHxD8XjYciqtZ6pjmmIxWESmH_NxpLDF0dfC4gAG1KkHLuYTiG9IdCbiuocMjK3WieIbTvrmOR1ZZbI5VQe2Pp326lvdWGE6MKlLRAmaJlFfB89CWdcjU0eXVaXZLjiUiyo03Duq9mFV13bh5f5VRUp2qgYrp5dv_5B8AsowIsG2fyoC5rVCUnmC2of8FF9r2BP8yrdl2hFIXbO0WStgla8dM_46qDYH5bHhKxWbQ-VYhRMOKN04AGEfesCFFjMKI7bk0g8fqR4bZs-UI88edC9q0kHN5tW3gUd9tsaYdR5Rf7Ah0GX5pIxdW5M9WesP5iW_jucj4zajs4nmLWKyBba3s-SQLbBDIhaWug68AVcCwIi8O5z6_EOERw-hT30t5wjJRsfU8ffVHsUV7362o7rJRXKTWcftHA9PP_iAOPuZSbUoTRivkgvCHY7L5ndUJ9kCtEOE_8BKA4YgH3FQtIES-OveuXGXC6hiGOTXxm-v-XVg_54CAw4TBxsAzRFgf_zfBMzikl3uusaZbjiT09qHfTYzI4zJ1zKpxEFe0ml96ggMaUtp29Ma1Ncd3I5o3Q3D0_NRRR_-XkG_WQzc4UC5e-vnjX2Err1xCGeYJS-DamgWiXbmoZroFbODuqxJw_2yho3K9Bb0aiEfQujVyYJ2a01RqUyH8h4oSlQmuHtOwDS9jNJFOQznvsSZD0FrQPqhVk7jnUTqAFBNBCuKF8KPu5DnUBiXgehC5tvcquM9KeHYwulkluB-_FVGico7Pvw_vNuY1bjDOM0avPVsCjkC0ZrgRksQmmsmL2PJjK0EhSMTl0cv4pvBz7GCHPtS9bqCxOnaPTCe23OlWiHsIol9OVNrTsE4KFQkBZait49Y0aBfjYilWwrD7RZY83Fn-g010YWc5ULROTmcwrru1hPs61Zt_biQhs4D7JVj-pL71yy7-0Flw1HfvbQMHtMES_yMcpHaGLFYunFKdYyS3BnYeWdkf6dvqCLDGnI6m25eE4T15RDfQWcGLdsld4QZVRRcu9XpjouG4iaAw0ImySCwC5cmpgB_RPAJiHRnU2JmnQj-on2CRKtRDMXvomA1WXM1Xbp_nRaEwoNFCGjhjIqb3DtSDfIrP8dCd516sw9E5uUqIrE7kzG0N9UeJCxPJT3gaGFkwvy1KDrjFCXiOq-GtrC9uEffDdvCyF1t5qfPsFpEkIAA9GxN6eUzxY5VAmzaFisjFXtw3gp5TRH1rSDMjAZdKZZaHUBsOS83An6Cgm-j1zdZpHg8rqSn7yPlMNew9RpDoJt2X7mwiMv6CgsDZQDmPbHu401yswPrZKdqO_AqKmU9kIog4Puc64VN_Bsov7p1-sC1WmQ",
    "priv": "Nj5z9pTufI_vJzX9S2eUNrbC9D6QKfGXTUxwwlBl6w1caTu9cI1zgQ-4MWV7z7GBs556zkfW3k_6jOMIXaewFphMQoxy79ofuibiJQrhgI4n8mNtWZr7c0Axv8foFcjO3J204-oIdVdL5KNuFW8GQ8Jp4BsYzXC4f0e5XY4HjBcKiBFiFCCYAEzBwGyEJDCIEgFTIjGRsEkJoigkEG1ENozJAA4KRWUJhSQatoVhpC3hJowSEwjYEiFbmAjIEGHkhABYGGYhGYEZAlDDkIACOUQgpiUYISSahCACAU0aCAYEuU3ctgXUFiZipgwgky3aknBZCCyLRCTJsGHSkoxYkIAiRkUcIoqTyGQCSCGhJGSaQEEJoCEBtEnbImGUkFCIpEAjJjABk2gCQkDkQGDcxDGKMHCEtAXgJCqRphHiSEGTJIWQRCojlmkByVACl0CbJgzQAIIKyJFTFgogyS0kIomMAJIKgpGRJoYUs2jRmGxjkGWjSEgZxAwYxhDgIEgUhgQYoxEZwTGLiGUBhIQbgCgbBSUQJCQhhoSRQAaZME4QOGwgRQjYkEgAkIQREHAaFQlElAwhAAHIAgbZBEgcR42III5EFlFhwIkMqSUMQ4mLoC0ZAQ4kCIISwSQSgmyZIlEbxQwhIDIaBIWJpC2CRo3SooEkA4JhsIhKQpIBAJERiRAhGEKiiC0UQIJbpGgSR4CDMAhgQCigsoggIkghGSJZqCSMBBIBGYURtAVMEkUYwGjQBI4AsQ1TpCEbgnHUMITLBArRRgEkAiBARiUaJ0RMpGGZNkLkwhFLNizJsDEUF4zDEhLBgJDRGIyCNCBEsJCjJmJROAEkNGZTsJEikDCiAEATlZGCFFCggoRYQGmRMgWjKBFgQDDAJI5KFAQDSGITh4VTiEWYNIIDqEzQuGmKJhJDADFbMGgkMSQQkChJhEEBRUQjQ4SAJk1AtC0ABwCLEmHSOCkChQ3jkE1EwGUTmVEEs5FcKIjRGE2gMoTcxkERxilDsnESBWCZAm4DuISQKHIDkRCUMmhJkpAQmRFCIiAMuIARAS7DlhBDRoBAAmDBRgDjQIaJBC1DhmmZxHABNCQCIVCACAAkMRISwoEYSIUkoQHcKElZxBAjKUkSQiKYpjCCuGDRoomcuGkDKQ2LJgKUGERZFkiKEEDktIgSKQZLIJDjAoQUiDHgmGDcp92TKG1rPc_M_c_Krn2PZRwWBWTnbot5VkZhjzcOFnlmUTqsxwRdYeV5CkIZe1UMZKlYXqAoZMxzZN3mRIG1nESgmIQtbbBjzj97dBxfRIUTymNuRzUP7f11xzeB6D7lTsIvUA4LPxc9r1XQ8JXgqWIeOiaEol8MEel88nTm_LfPQGczFWcbzcDq_o-mvAmHk68ARyXarbV4sOwMMv0L-bEXId6D2oJPZ66hArqhooHqyx_uJzOqsZHywOYuWhromRNr0h8ZtsssOXlrtiArezLKxMKzc-rRaiYqroWqcSY7GOI1eG5Q6XhF1NCj7pszNUH_CpRG4lfwIJeI-hYX4XzPTNuVx87lKae1QU7n2nzNJxe2rmGllTL3EPSjYqIoTv9fLmVDMUpczL13RBGGhvswf_kfaPaOFm-nEtg9BmR2HkQfFbJXYQNG93qya9cpsFOc10DO-wJ_Ydzp57n3gK3r9ZfuoGmtFrujjzCyYgPJAcoBeWbVgLjOFisq0BMugZ6l7ZJzO7i5pM3iDpsouEAWajsvoq3XP4odI-coN6Wfd9uNTO8O7lJrFoJyXxmU7y15O1Y7aNdAk90MPmuWio8O4AEnQhTb2CPvgvV6QEjDz6WQSehRs9ao5f5C2l0y8pLZ4ubU--10WV_wQoQU-mvMSvDhiukUXShD1jzkTavQuCQeLJK_67o0QyEc7IHtWZvcr-cISZDZE4cN6BrciNhQm7uEjGlCk6QAQCqrOwwLqPsj5CXJscxbrICxR797Hiw87FC52Bdogkn-WUHwn9d4k6NGk0w82RlWzur9G17gCi5OWx6nEsipIPywyAGExOJ0rRapv1z7tv43U9SwleeNo7jQNrPs_CKXcQOhsLk3d3EQJVOhKjEh0zMiwCk5Ow5pHUWeOYo9ZO-_XDAncjMxiDCM4h36z2eUW3M2dLpPl5PywwjY14zwBENVXbddsryqFdRgyyNoTj8-d_SmfWz1pcC1fUijn0Zw_uU-rvS96o7pcCba5bYqT1IyNjuIBkknqdk3WM0b-gkIy-ZDDU4xeiLtxudjQ4MzDjlrecRAPVRnEdCB9R-nEpiM0-ClS7t0nzgjOWp_4qcKYWxzdA3syG7c8o7LySGmsUPT1eNzFcEQqU47xSP1lD91CGZgfRUiTep9s93iI0hWGWH_w9N1ZhKCh7b0AQB5TSlZlUu3lydYyfBmUfyWYQFHjlekudWWzYiCNzZQO4jkM3B0T-q2fouMBMqL23JaJ8GyyUO7je09jI2IFwcbcUx1ioB5ltO49DcLnGmK7tN7rx2bS4e7orLYFPNc03QPmI7YWoScK_pWXkyFtbdb1WpGJVQA7F_KURRrKw71WYJJ_aHz4nPjPrve7CcNOyodoWHGrwuCWYpRIn4gyXRjD7R780yfS3vO50I1PrsR_WiWf5hEo_t6EWJ_fMQScmp7UyrcpudwcywG8lIfrlE158ha5eCjPdge5I1QOEQutZiqTsk_aqU3MQeX03oer922Yd2fem5Q74hsEWwwXMUQ4_5Dcqr2-JO4qc_lq1q8MvaWqWlgtRUymzEXv3qoln7QApnKvunk7ZrDbV1U8gSwILD27ZWRlsJScQs8RhXbtukTqQlo9NcdNLfGgSa8dB8SUtyfwt_vGQ4VcNLbsRI9V_fk-oBMi3pQyRXz8kD0l0lyg17yer1e-Kpt8YpsKco4A0AAT2UyJj6UxkofXQzdgfpDJV7djP9zLiIhzgNTde9PaUp48GLJ644pWhvP4Jd433sirV1gKtFFg6op85-knLzHsTgfDucL_urUxMXZC2cLy9OfMpXzKafxhOMv7EUkCO5Bkm-hfXZol41j8odgooX0YoZUANiN9MqUmb7DeDJpTUZOD33gj6rAqehyKhFL1YyC-84BaykPVEeSXT_iQ0FuHluAJfi6YVX6J2c-c8eovJ_qwn2HihBd1o0oln0DAdlUJfKCoVgIhluC7M6tXxFe0PnqqTyBk-y57uv6rnM6eRJOlHWMCTHLxfcDcueoGPCeBICMo9qqID_6ROeEuFekRdxNRoxtCTGh0NhUNsEEQk7LMTLabTCoMTD9U99ldujsDfZaBsJZA3oN3XcjQWH7RYPS9n4638gdbZCCXIivgPq2Wo_LC_X2emI2BRqcJ2T5UjoSgA-cQV7L5F_mL3TXwGq61sinuL94iE-N9HvCpnpMu1caCNNg-iLsgIU5qD7PLQ",
    "kid": "pq-1"
  },
  "alg": "ML-DSA-44"
}
~~~

Discovery documents:

~~~ json
{
  "jwks_url": "https://client.example/pq.jwks",
  "jwks": {
    "keys": [
      {
        "kty": "AKP",
        "alg": "ML-DSA-44",
        "pub": "Nj5z9pTufI_vJzX9S2eUNrbC9D6QKfGXTUxwwlBl6w0HpZVJUs0wqXjufY1Zr_w-yNCP-aOemR3xVS70-DdKkGhTc7vKd6XZhgyzi40W2zfMbXKZDpgxCW_-eT-HDHXb6v22Uf6nN3ST_BKqrNwBExKj85Uszy5QBkS3tfxumJj2xpzl1GwnRg62sxzuo243b5pB-cuzSYKwoDUq6TTTYwXHOUSygcad8V-OC5tQsOBqF9QQVbHtrMczRrP_0B_Utq3zDsdJFSPq34SIoOkuj4lhIgaG3IC6weGV84d7sWNROA_bOXv2nKGGaqSKLwT2kZ2-OI2oYm1IoBfZaRs7W3CAMWSsBtBWyQahLuxiuvjTIWnzf6L_5J50Srmpn8500vUjLJGUHxD8XjYciqtZ6pjmmIxWESmH_NxpLDF0dfC4gAG1KkHLuYTiG9IdCbiuocMjK3WieIbTvrmOR1ZZbI5VQe2Pp326lvdWGE6MKlLRAmaJlFfB89CWdcjU0eXVaXZLjiUiyo03Duq9mFV13bh5f5VRUp2qgYrp5dv_5B8AsowIsG2fyoC5rVCUnmC2of8FF9r2BP8yrdl2hFIXbO0WStgla8dM_46qDYH5bHhKxWbQ-VYhRMOKN04AGEfesCFFjMKI7bk0g8fqR4bZs-UI88edC9q0kHN5tW3gUd9tsaYdR5Rf7Ah0GX5pIxdW5M9WesP5iW_jucj4zajs4nmLWKyBba3s-SQLbBDIhaWug68AVcCwIi8O5z6_EOERw-hT30t5wjJRsfU8ffVHsUV7362o7rJRXKTWcftHA9PP_iAOPuZSbUoTRivkgvCHY7L5ndUJ9kCtEOE_8BKA4YgH3FQtIES-OveuXGXC6hiGOTXxm-v-XVg_54CAw4TBxsAzRFgf_zfBMzikl3uusaZbjiT09qHfTYzI4zJ1zKpxEFe0ml96ggMaUtp29Ma1Ncd3I5o3Q3D0_NRRR_-XkG_WQzc4UC5e-vnjX2Err1xCGeYJS-DamgWiXbmoZroFbODuqxJw_2yho3K9Bb0aiEfQujVyYJ2a01RqUyH8h4oSlQmuHtOwDS9jNJFOQznvsSZD0FrQPqhVk7jnUTqAFBNBCuKF8KPu5DnUBiXgehC5tvcquM9KeHYwulkluB-_FVGico7Pvw_vNuY1bjDOM0avPVsCjkC0ZrgRksQmmsmL2PJjK0EhSMTl0cv4pvBz7GCHPtS9bqCxOnaPTCe23OlWiHsIol9OVNrTsE4KFQkBZait49Y0aBfjYilWwrD7RZY83Fn-g010YWc5ULROTmcwrru1hPs61Zt_biQhs4D7JVj-pL71yy7-0Flw1HfvbQMHtMES_yMcpHaGLFYunFKdYyS3BnYeWdkf6dvqCLDGnI6m25eE4T15RDfQWcGLdsld4QZVRRcu9XpjouG4iaAw0ImySCwC5cmpgB_RPAJiHRnU2JmnQj-on2CRKtRDMXvomA1WXM1Xbp_nRaEwoNFCGjhjIqb3DtSDfIrP8dCd516sw9E5uUqIrE7kzG0N9UeJCxPJT3gaGFkwvy1KDrjFCXiOq-GtrC9uEffDdvCyF1t5qfPsFpEkIAA9GxN6eUzxY5VAmzaFisjFXtw3gp5TRH1rSDMjAZdKZZaHUBsOS83An6Cgm-j1zdZpHg8rqSn7yPlMNew9RpDoJt2X7mwiMv6CgsDZQDmPbHu401yswPrZKdqO_AqKmU9kIog4Puc64VN_Bsov7p1-sC1WmQ",
        "kid": "pq-1",
        "use": "sig"
      }
    ]
  }
}
~~~

## A.12 Negative vectors

Each of these is derived from a MUST or MUST NOT in the draft and names the section it comes from. A verifier that accepts a `must_reject` vector, or rejects the one marked MUST-ACCEPT, is non-conformant.

### A.12.1 hwk-with-kid-forbidden

**MUST REJECT** with `error=invalid_key`

Section: Header Web Key (hwk) / Constraints

The kid parameter MUST NOT be used with hwk. The key is carried inline, so there is nothing for an identifier to select, and a kid that disagrees with the inline key has no defined resolution. This is a member the document forbids: understood and rejected, not unknown and ignored.

~~~ http-message
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="fFWGSTH7SN1gol911OE\
rq1sPFXT_LAG26zBtLm8ItK0";alg="Ed25519";kid="k1"
~~~

### A.12.2 hwk-alg-absent

**MUST REJECT** with `error=unsupported_algorithm`

Section: Algorithm Determination

A verifier MUST reject a JWK whose alg member is absent, and MUST NOT select an algorithm for it by inspecting other key parameters. kty and crv would determine it here; the draft requires alg regardless.

~~~ http-message
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="fFWGSTH7SN1gol911OE\
rq1sPFXT_LAG26zBtLm8ItK0"
~~~

### A.12.3 hwk-alg-polymorphic-eddsa

**MUST REJECT** with `error=unsupported_algorithm`

Section: Algorithm Determination

The polymorphic EdDSA identifier MUST NOT be used. Use the fully-specified Ed25519 or Ed448 identifiers of RFC 9864.

~~~ http-message
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="fFWGSTH7SN1gol911OE\
rq1sPFXT_LAG26zBtLm8ItK0";alg="EdDSA"
~~~

### A.12.4 hwk-alg-kty-inconsistent

**MUST REJECT** with `error=invalid_key`

Section: Algorithm Determination

A verifier MUST verify kty and, where present, crv are consistent with alg, and MUST reject the key if they are not. alg ES256 with kty RSA is inconsistent. Rejecting on disagreement stops a key being used under either of two conflicting interpretations.

~~~ http-message
Signature-Key: sig=hwk;kty="RSA";n="0vx7agoebGcQSuuPiLJXZpt";e="AQAB"\
;alg="ES256"
~~~

### A.12.5 hwk-alg-crv-inconsistent

**MUST REJECT** with `error=invalid_key`

Section: Algorithm Determination

Same rule on the curve: alg ES256 with crv P-384 is inconsistent and MUST be rejected.

~~~ http-message
Signature-Key: sig=hwk;kty="EC";crv="P-384";x="LhnFCX9JWOQhInaap65wwL\
3rcT49WyvQSlIhMLO8lr4";y="PEr4OX8tM8oHdcYMrbeIQhl58q5XxkVG28CJQ8tS618\
";alg="ES256"
~~~

### A.12.6 hwk-symmetric-forbidden

**MUST REJECT** with `error=unsupported_algorithm`

Section: Algorithm Determination / Symmetric Algorithms

Symmetric algorithms MUST NOT be used. The oct key type and the JOSE MAC identifiers name a shared secret rather than a public key, and a verifier MUST reject a scheme that conveys or references such a key.

~~~ http-message
Signature-Key: sig=hwk;kty="oct";k="c2VjcmV0LWtleS1tYXRlcmlhbA";alg="\
HS256"
~~~

### A.12.7 unknown-scheme-selected

**MUST REJECT** with `error=unsupported_scheme`

Section: Signature-Key Header / Unknown schemes

A verifier that selects a member whose scheme token it does not implement, including any unregistered value, MUST reject with unsupported_scheme and MUST NOT fail in a scheme-specific or undefined manner. Dispatch SHOULD be a registry lookup, not a fixed set of branches.

~~~ http-message
Signature-Key: sig=quantum-widget;blob="AAAA"
~~~

### A.12.8 self-jwt-with-cnf-forbidden

**MUST REJECT** with `error=invalid_jwt`

Section: Self-Issued JWT (self-jwt) / Security Considerations

Verifiers MUST validate that cnf is absent before treating the scheme as self-issued; a JWT containing cnf MUST be rejected. A self-jwt's signing key IS its confirmation key, so a cnf claim is a different trust model wearing this scheme's name.

~~~ http-message
Signature-Key: sig=self-jwt;jwt="eyJhbGciOiJFUzI1NiIsImtpZCI6InIxIiwi\
dHlwIjoiYWEtZXZlbnQrand0In0.eyJpc3MiOiJodHRwczovL3Jlc291cmNlLmV4YW1wb\
GUiLCJkd2siOiJhYXV0aC1yZXNvdXJjZS5qc29uIiwiaWF0IjoxNzkxMjc1ODk4LCJleH\
AiOjE3OTEyNzYyNTgsImNuZiI6eyJqd2siOnsia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTU\
xOSIsIngiOiJmRldHU1RIN1NOMWdvbDkxMU9FcnExc1BGWFRfTEFHMjZ6QnRMbThJdEsw\
IiwiYWxnIjoiRWQyNTUxOSJ9fX0.NNP52V-HYGsDhSqHFp79FWToftN9cXBtuBwcqx4ok\
haCvHCmQJgNhOC5EWP8bZ5O-Hppie25Ao-6O528DVEPlg"
~~~

### A.12.9 jwks_uri-issuer-mismatch

**MUST REJECT** with `error=issuer_mismatch`

Section: JWKS URI Discovery (jwks_uri) / Discovery procedure

The metadata document's issuer MUST equal the id parameter by byte equality as presented. Without the check, a document served under id through shared hosting or subdomain takeover could point jwks_uri at keys that do not belong to id, and the verifier would attribute the request accordingly.

~~~ http-message
Signature-Key: sig=jwks_uri;id="https://mismatch.example";dwk="exampl\
e-configuration";kid="key-1"
~~~

Served at the discovery URL:

~~~ json
{
  "metadata_url": "https://mismatch.example/.well-known/example-configuration",
  "metadata_document": {
    "issuer": "https://attacker.example",
    "jwks_uri": "https://attacker.example/jwks.json"
  }
}
~~~

### A.12.10 jwks_uri-issuer-missing

**MUST REJECT** with `error=issuer_missing`

Section: JWKS URI Discovery (jwks_uri) / Discovery procedure

The document MUST contain issuer and jwks_uri. Reject with issuer_missing if issuer is absent.

~~~ http-message
Signature-Key: sig=jwks_uri;id="https://nodoc.example";dwk="example-c\
onfiguration";kid="key-1"
~~~

Served at the discovery URL:

~~~ json
{
  "metadata_url": "https://nodoc.example/.well-known/example-configuration",
  "metadata_document": {
    "jwks_uri": "https://nodoc.example/jwks.json"
  }
}
~~~

### A.12.11 label-missing-from-signature-key

**MUST REJECT** with `error=invalid_key`

Section: Label Correlation / Label Consistency

If the Signature-Key header is present and the verifier is attempting to verify a label using it, but the corresponding dictionary member is missing, verification for that signature MUST fail. Here the verifier wants label 'sig' and Signature-Key carries only 'other'.

~~~ http-message
Signature-Input: sig=("@method" "@authority" "@path" "signature-key")\
;created=1791275958
Signature: sig=:AAAA:
Signature-Key: other=hwk;kty="OKP";crv="Ed25519";x="fFWGSTH7SN1gol911\
OErq1sPFXT_LAG26zBtLm8ItK0";alg="Ed25519"
~~~

### A.12.12 unselected-member-unknown-scheme-MUST-ACCEPT

**MUST ACCEPT**

Section: Signature-Key Header / Unknown schemes + Label Consistency

A verifier MUST NOT reject a request because a member it did not select names a scheme the verifier does not implement. This is the companion to unsupported_scheme and the one a naive implementation fails: without it no signer could offer a new scheme without breaking every verifier that lacks it, so none would, and the registry would have no path into deployment. Verify label 'sig' and ignore 'future'.

~~~ http-message
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="fFWGSTH7SN1gol911OE\
rq1sPFXT_LAG26zBtLm8ItK0";alg="Ed25519", future=quantum-widget;blob="\
AAAA"
~~~

### A.12.13 akp-only-jwks-must-decline-not-throw

**MUST REJECT** with `error=unsupported_algorithm` (category 1)

Section: Algorithm Determination

A verifier that encounters a JWK whose kty it does not implement, including the AKP key type, MUST reject the key with defined error feedback and MUST NOT fail in an undefined manner. Absence of support for a key type is a reason to decline, not a parsing failure. An implementation without ML-DSA must report unsupported_algorithm here rather than throw. ML-DSA-44 key, 1312 byte public value per FIPS 204, carried as the AKP key type of RFC 9964 with the algorithm named by alg rather than derivable from the key structure.

~~~ http-message
Signature-Key: sig=jwks;url="https://client.example/pq.jwks";kid="pq-\
1"
~~~

Served at the discovery URL:

~~~ json
{
  "jwks_url": "https://client.example/pq.jwks",
  "jwks": {
    "keys": [
      {
        "kty": "AKP",
        "alg": "ML-DSA-44",
        "pub": "Nj5z9pTufI_vJzX9S2eUNrbC9D6QKfGXTUxwwlBl6w0HpZVJUs0wqXjufY1Zr_w-yNCP-aOemR3xVS70-DdKkGhTc7vKd6XZhgyzi40W2zfMbXKZDpgxCW_-eT-HDHXb6v22Uf6nN3ST_BKqrNwBExKj85Uszy5QBkS3tfxumJj2xpzl1GwnRg62sxzuo243b5pB-cuzSYKwoDUq6TTTYwXHOUSygcad8V-OC5tQsOBqF9QQVbHtrMczRrP_0B_Utq3zDsdJFSPq34SIoOkuj4lhIgaG3IC6weGV84d7sWNROA_bOXv2nKGGaqSKLwT2kZ2-OI2oYm1IoBfZaRs7W3CAMWSsBtBWyQahLuxiuvjTIWnzf6L_5J50Srmpn8500vUjLJGUHxD8XjYciqtZ6pjmmIxWESmH_NxpLDF0dfC4gAG1KkHLuYTiG9IdCbiuocMjK3WieIbTvrmOR1ZZbI5VQe2Pp326lvdWGE6MKlLRAmaJlFfB89CWdcjU0eXVaXZLjiUiyo03Duq9mFV13bh5f5VRUp2qgYrp5dv_5B8AsowIsG2fyoC5rVCUnmC2of8FF9r2BP8yrdl2hFIXbO0WStgla8dM_46qDYH5bHhKxWbQ-VYhRMOKN04AGEfesCFFjMKI7bk0g8fqR4bZs-UI88edC9q0kHN5tW3gUd9tsaYdR5Rf7Ah0GX5pIxdW5M9WesP5iW_jucj4zajs4nmLWKyBba3s-SQLbBDIhaWug68AVcCwIi8O5z6_EOERw-hT30t5wjJRsfU8ffVHsUV7362o7rJRXKTWcftHA9PP_iAOPuZSbUoTRivkgvCHY7L5ndUJ9kCtEOE_8BKA4YgH3FQtIES-OveuXGXC6hiGOTXxm-v-XVg_54CAw4TBxsAzRFgf_zfBMzikl3uusaZbjiT09qHfTYzI4zJ1zKpxEFe0ml96ggMaUtp29Ma1Ncd3I5o3Q3D0_NRRR_-XkG_WQzc4UC5e-vnjX2Err1xCGeYJS-DamgWiXbmoZroFbODuqxJw_2yho3K9Bb0aiEfQujVyYJ2a01RqUyH8h4oSlQmuHtOwDS9jNJFOQznvsSZD0FrQPqhVk7jnUTqAFBNBCuKF8KPu5DnUBiXgehC5tvcquM9KeHYwulkluB-_FVGico7Pvw_vNuY1bjDOM0avPVsCjkC0ZrgRksQmmsmL2PJjK0EhSMTl0cv4pvBz7GCHPtS9bqCxOnaPTCe23OlWiHsIol9OVNrTsE4KFQkBZait49Y0aBfjYilWwrD7RZY83Fn-g010YWc5ULROTmcwrru1hPs61Zt_biQhs4D7JVj-pL71yy7-0Flw1HfvbQMHtMES_yMcpHaGLFYunFKdYyS3BnYeWdkf6dvqCLDGnI6m25eE4T15RDfQWcGLdsld4QZVRRcu9XpjouG4iaAw0ImySCwC5cmpgB_RPAJiHRnU2JmnQj-on2CRKtRDMXvomA1WXM1Xbp_nRaEwoNFCGjhjIqb3DtSDfIrP8dCd516sw9E5uUqIrE7kzG0N9UeJCxPJT3gaGFkwvy1KDrjFCXiOq-GtrC9uEffDdvCyF1t5qfPsFpEkIAA9GxN6eUzxY5VAmzaFisjFXtw3gp5TRH1rSDMjAZdKZZaHUBsOS83An6Cgm-j1zdZpHg8rqSn7yPlMNew9RpDoJt2X7mwiMv6CgsDZQDmPbHu401yswPrZKdqO_AqKmU9kIog4Puc64VN_Bsov7p1-sC1WmQ",
        "kid": "pq-1",
        "use": "sig"
      }
    ]
  }
}
~~~

### A.12.14 mixed-jwks-ignore-unparseable-neighbour-MUST-ACCEPT

**MUST ACCEPT** (category 1)

Section: Algorithm Determination, final paragraphs

The JWKS holds an Ed25519 key and an ML-DSA-44 key, and the vector selects the Ed25519 one by kid. A verifier MUST select the member matching kid without requiring any other member to be usable, and MUST NOT fail because an unselected member names a kty or alg it does not implement. The failure mode is a library that hits the unknown kty while enumerating and abandons a perfectly good key sitting next to it. Exercising the unknown-value path routinely is what stops it rotting, in the spirit of RFC 9170. ML-DSA-44 key, 1312 byte public value per FIPS 204, carried as the AKP key type of RFC 9964 with the algorithm named by alg rather than derivable from the key structure.

~~~ http-message
Signature-Key: sig=jwks;url="https://client.example/mixed.jwks";kid="\
classic-1"
~~~

Served at the discovery URL:

~~~ json
{
  "jwks_url": "https://client.example/mixed.jwks",
  "jwks": {
    "keys": [
      {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
        "alg": "Ed25519",
        "kid": "classic-1",
        "use": "sig"
      },
      {
        "kty": "AKP",
        "alg": "ML-DSA-44",
        "pub": "Nj5z9pTufI_vJzX9S2eUNrbC9D6QKfGXTUxwwlBl6w0HpZVJUs0wqXjufY1Zr_w-yNCP-aOemR3xVS70-DdKkGhTc7vKd6XZhgyzi40W2zfMbXKZDpgxCW_-eT-HDHXb6v22Uf6nN3ST_BKqrNwBExKj85Uszy5QBkS3tfxumJj2xpzl1GwnRg62sxzuo243b5pB-cuzSYKwoDUq6TTTYwXHOUSygcad8V-OC5tQsOBqF9QQVbHtrMczRrP_0B_Utq3zDsdJFSPq34SIoOkuj4lhIgaG3IC6weGV84d7sWNROA_bOXv2nKGGaqSKLwT2kZ2-OI2oYm1IoBfZaRs7W3CAMWSsBtBWyQahLuxiuvjTIWnzf6L_5J50Srmpn8500vUjLJGUHxD8XjYciqtZ6pjmmIxWESmH_NxpLDF0dfC4gAG1KkHLuYTiG9IdCbiuocMjK3WieIbTvrmOR1ZZbI5VQe2Pp326lvdWGE6MKlLRAmaJlFfB89CWdcjU0eXVaXZLjiUiyo03Duq9mFV13bh5f5VRUp2qgYrp5dv_5B8AsowIsG2fyoC5rVCUnmC2of8FF9r2BP8yrdl2hFIXbO0WStgla8dM_46qDYH5bHhKxWbQ-VYhRMOKN04AGEfesCFFjMKI7bk0g8fqR4bZs-UI88edC9q0kHN5tW3gUd9tsaYdR5Rf7Ah0GX5pIxdW5M9WesP5iW_jucj4zajs4nmLWKyBba3s-SQLbBDIhaWug68AVcCwIi8O5z6_EOERw-hT30t5wjJRsfU8ffVHsUV7362o7rJRXKTWcftHA9PP_iAOPuZSbUoTRivkgvCHY7L5ndUJ9kCtEOE_8BKA4YgH3FQtIES-OveuXGXC6hiGOTXxm-v-XVg_54CAw4TBxsAzRFgf_zfBMzikl3uusaZbjiT09qHfTYzI4zJ1zKpxEFe0ml96ggMaUtp29Ma1Ncd3I5o3Q3D0_NRRR_-XkG_WQzc4UC5e-vnjX2Err1xCGeYJS-DamgWiXbmoZroFbODuqxJw_2yho3K9Bb0aiEfQujVyYJ2a01RqUyH8h4oSlQmuHtOwDS9jNJFOQznvsSZD0FrQPqhVk7jnUTqAFBNBCuKF8KPu5DnUBiXgehC5tvcquM9KeHYwulkluB-_FVGico7Pvw_vNuY1bjDOM0avPVsCjkC0ZrgRksQmmsmL2PJjK0EhSMTl0cv4pvBz7GCHPtS9bqCxOnaPTCe23OlWiHsIol9OVNrTsE4KFQkBZait49Y0aBfjYilWwrD7RZY83Fn-g010YWc5ULROTmcwrru1hPs61Zt_biQhs4D7JVj-pL71yy7-0Flw1HfvbQMHtMES_yMcpHaGLFYunFKdYyS3BnYeWdkf6dvqCLDGnI6m25eE4T15RDfQWcGLdsld4QZVRRcu9XpjouG4iaAw0ImySCwC5cmpgB_RPAJiHRnU2JmnQj-on2CRKtRDMXvomA1WXM1Xbp_nRaEwoNFCGjhjIqb3DtSDfIrP8dCd516sw9E5uUqIrE7kzG0N9UeJCxPJT3gaGFkwvy1KDrjFCXiOq-GtrC9uEffDdvCyF1t5qfPsFpEkIAA9GxN6eUzxY5VAmzaFisjFXtw3gp5TRH1rSDMjAZdKZZaHUBsOS83An6Cgm-j1zdZpHg8rqSn7yPlMNew9RpDoJt2X7mwiMv6CgsDZQDmPbHu401yswPrZKdqO_AqKmU9kIog4Puc64VN_Bsov7p1-sC1WmQ",
        "kid": "pq-1",
        "use": "sig"
      }
    ]
  }
}
~~~

### A.12.15 signature-key-not-covered

**MUST REJECT** with `error=invalid_input`, plus `required_input=("@method" "@authority" "@path" "signature-key")` (category 1)

Section: invalid_input / Signature-Key Integrity

Every signature MUST cover the signature-key component, so that the signature protects the key material that verifies it. Here the signer covered the first three and left signature-key out, which leaves the key material unprotected and swappable. The server SHOULD answer invalid_input with a required_input member naming the components it requires, and MAY omit that member where enumerating its requirements to an unauthenticated caller is a disclosure risk.

~~~ http-message
Signature-Input: sig=("@method" "@authority" "@path");created=1791275\
958
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="fFWGSTH7SN1gol911OE\
rq1sPFXT_LAG26zBtLm8ItK0";alg="Ed25519"
~~~

### A.12.16 jwks-kid-not-in-jwks

**MUST REJECT** with `error=unknown_key`

Section: unknown_key / Direct JWKS (jwks) discovery procedure

The kid selects no member of the fetched JWKS. The verifier rejects with unknown_key rather than falling back to another member: a JWKS with one usable key is not licence to use it for a kid that does not name it. The server SHOULD re-fetch the JWKS once before answering, to handle a key that rotated between the signer publishing and the verifier reading.

~~~ http-message
Signature-Key: sig=jwks;url="https://client.example/keys.jwks";kid="r\
otated-away"
~~~

Served at the discovery URL:

~~~ json
{
  "jwks_url": "https://client.example/keys.jwks",
  "jwks": {
    "keys": [
      {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "fFWGSTH7SN1gol911OErq1sPFXT_LAG26zBtLm8ItK0",
        "alg": "Ed25519",
        "kid": "key-1",
        "use": "sig"
      }
    ]
  },
  "kid_presented": "rotated-away",
  "kids_available": [
    "key-1"
  ]
}
~~~

### A.12.17 jwt-without-exp

**MUST REJECT** with `error=invalid_jwt` (category 1)

Section: JWT Confirmation Key (jwt) / JWT requirements

The jwt scheme requires exp. The assertion carries a confirmation key, and exp is what bounds how long that key is accepted; without it the key remains acceptable indefinitely. A missing required claim is rejected before any signature work.

~~~ http-message
Signature-Key: sig=jwt;jwt="eyJ0eXAiOiJhYS10b2tlbitqd3QiLCJhbGciOiJFU\
zI1NiIsImtpZCI6Imlzc3Vlci0xIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcG\
xlIiwiZHdrIjoiZXhhbXBsZS1jb25maWd1cmF0aW9uIiwic3ViIjoiaW5zdGFuY2UtMTI\
zIiwiaWF0IjoxNzkxMjc1ODk4LCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6\
IkVkMjU1MTkiLCJ4IjoiZkZXR1NUSDdTTjFnb2w5MTFPRXJxMXNQRlhUX0xBRzI2ekJ0T\
G04SXRLMCIsImFsZyI6IkVkMjU1MTkifX19.8B9nbcL7uapV5de-7as3cSYwikAix63Nz\
qpiWTDWqK8Tq4UYhagXtzFoqy2ocGtNCNP48eujwlyZf87MPxWddQ"
~~~

### A.12.18 jwt-expired-one-second-before-now

**MUST REJECT** with `error=expired_jwt` (category 1)

Section: expired_jwt

exp is now - 1, so the assertion expired one second before the instant this vector declares. Expiry is validated before the signature, so a verifier fails here without cryptographic work. Expressed relative to now (1791275958) rather than as a fixed past date, so the vector does not go stale.

~~~ http-message
Signature-Key: sig=jwt;jwt="eyJ0eXAiOiJhYS10b2tlbitqd3QiLCJhbGciOiJFU\
zI1NiIsImtpZCI6Imlzc3Vlci0xIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcG\
xlIiwiZHdrIjoiZXhhbXBsZS1jb25maWd1cmF0aW9uIiwic3ViIjoiaW5zdGFuY2UtMTI\
zIiwiaWF0IjoxNzkxMjcyMzU4LCJleHAiOjE3OTEyNzU5NTcsImNuZiI6eyJqd2siOnsi\
a3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJmRldHU1RIN1NOMWdvbDkxMU9Fc\
nExc1BGWFRfTEFHMjZ6QnRMbThJdEswIiwiYWxnIjoiRWQyNTUxOSJ9fX0.JAtusms7B5\
zjE3wd40Iggo-sgPaXHbUSxTooQB3KhzA6-oC3kDkXo1AX1lvudRXF_6YwYdCkSfAmJdM\
hISZpKQ"
~~~

### A.12.19 jwt-exp-300s-after-now-MUST-ACCEPT

**MUST ACCEPT** (category 1)

Section: expired_jwt

exp is now + 300, so the assertion is live at the declared instant and MUST be accepted. This is the positive control for the expiry pair: without it a verifier that rejects every assertion passes the expired case for the wrong reason.

~~~ http-message
Signature-Key: sig=jwt;jwt="eyJ0eXAiOiJhYS10b2tlbitqd3QiLCJhbGciOiJFU\
zI1NiIsImtpZCI6Imlzc3Vlci0xIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcG\
xlIiwiZHdrIjoiZXhhbXBsZS1jb25maWd1cmF0aW9uIiwic3ViIjoiaW5zdGFuY2UtMTI\
zIiwiaWF0IjoxNzkxMjc1ODk4LCJleHAiOjE3OTEyNzYyNTgsImNuZiI6eyJqd2siOnsi\
a3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJmRldHU1RIN1NOMWdvbDkxMU9Fc\
nExc1BGWFRfTEFHMjZ6QnRMbThJdEswIiwiYWxnIjoiRWQyNTUxOSJ9fX0.0e4A66d4CO\
rsRRX2MQ-HY9oxh4S5m1d_CEZke81OF0HWySkM-hrnjBo-DuzRY1Wcy70pl6Gl1YNzyy8\
oMiH3lg"
~~~

### A.12.20 jwt-iat-one-hour-after-now-is-clock-skew

**MUST REJECT** with `error=clock_skew` (category 1)

Section: clock_skew

iat is now + 3600, further ahead of the verifier's clock than any reasonable validity window. The distinct code is what the caller needs: nothing about the assertion or the signature is wrong, the issuer's clock disagrees, and a fresh assertion from the same issuer carries the same skew. A future iat becomes acceptable with time, so the sender MAY wait and present the same assertion again. This is why clock_skew is not invalid_jwt or expired_jwt.

~~~ http-message
Signature-Key: sig=jwt;jwt="eyJ0eXAiOiJhYS10b2tlbitqd3QiLCJhbGciOiJFU\
zI1NiIsImtpZCI6Imlzc3Vlci0xIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcG\
xlIiwiZHdrIjoiZXhhbXBsZS1jb25maWd1cmF0aW9uIiwic3ViIjoiaW5zdGFuY2UtMTI\
zIiwiaWF0IjoxNzkxMjc5NTU4LCJleHAiOjE3OTEyODMxNTgsImNuZiI6eyJqd2siOnsi\
a3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJmRldHU1RIN1NOMWdvbDkxMU9Fc\
nExc1BGWFRfTEFHMjZ6QnRMbThJdEswIiwiYWxnIjoiRWQyNTUxOSJ9fX0.xvviLvsLmR\
6PmwvXXY5BtH7gBLCOrSSDVMNZ_AQdfQFcHD6JCdG2_ARPdZf1gX9o7RIvmcsIuptL1Wj\
CiP4g9w"
~~~

