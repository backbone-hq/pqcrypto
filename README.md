# ![PQCrypto](./media/pqcrypto.png)

![Build Status](https://img.shields.io/github/actions/workflow/status/backbone-hq/pqcrypto/ci.yml?branch=master)
![Python Version](https://img.shields.io/pypi/pyversions/pqcrypto)
![PyPI Version](https://img.shields.io/pypi/v/pqcrypto)
![License](https://img.shields.io/github/license/backbone-hq/pqcrypto)

**Python bindings for post-quantum cryptography.** Wraps well-tested Rust
implementations of NIST-standardized and candidate KEM and signature schemes
via PyO3/maturin. All variants live in a single compiled wheel.

## Installation

```bash
pip install pqcrypto
```

Or build from source:

```bash
pip install maturin pytest
maturin develop
```

## Quick Start

The Python API mirrors the Rust crate design: `keygen`, `encaps`, `decaps`
(KEM) and `keygen`, `sign`, `verify` (signatures).

### KEM — Key Encapsulation

```python
from pqcrypto.kem.ml_kem_512 import keygen, encaps, decaps
from pqcrypto.kem.ml_kem_512 import PublicKey, SecretKey

pk, sk = keygen()
ct, ss = encaps(pk)
assert decaps(sk, ct) == ss

pk_obj = PublicKey(pk)
sk_obj = SecretKey(sk)
ct2, ss2 = pk_obj.encaps()
assert ss2 == sk_obj.decaps(ct2)
```

### Signatures

```python
from pqcrypto.sign.ml_dsa_44 import keygen, sign, verify
from pqcrypto.sign.ml_dsa_44 import PublicKey, SecretKey

pk, sk = keygen()
sig = sign(sk, b"message")
verify(pk, b"message", sig)  # returns None; raises InvalidSignatureError if invalid

# FIPS 204/205 context string:
sig = sign(sk, b"message", b"my-context")
verify(pk, b"message", sig, b"my-context")

# HashML-DSA / HashSLH-DSA pre-hash mode:
from pqcrypto import HashAlgorithm
sig = sign(sk, b"message", hash_algorithm=HashAlgorithm.Sha256)
verify(pk, b"message", sig, hash_algorithm=HashAlgorithm.Sha256)

pk_obj = PublicKey(pk)
sk_obj = SecretKey(sk)
sig_obj = sk_obj.sign(b"message")
pk_obj.verify(b"message", sig_obj)
```

### Size constants

```python
from pqcrypto.kem.ml_kem_512 import PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, CIPHERTEXT_SIZE, SHARED_SECRET_SIZE
from pqcrypto.sign.ml_dsa_44 import PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SIGNATURE_SIZE
```

## Algorithms

Modules live in `pqcrypto.kem` (KEM) and `pqcrypto.sign` (signatures).

### Key Encapsulation

- **ML-KEM** (FIPS 203)
  - `ml_kem_512`, `ml_kem_768`, `ml_kem_1024`
- **Classic McEliece**
  - `mceliece_348864`
  - `mceliece_348864f`
  - `mceliece_460896`
  - `mceliece_460896f`
  - `mceliece_6688128`
  - `mceliece_6688128f`
  - `mceliece_6960119`
  - `mceliece_6960119f`
  - `mceliece_8192128`
  - `mceliece_8192128f`
- **SNTRUP**
  - `sntrup_653`
  - `sntrup_761`
  - `sntrup_857`
  - `sntrup_953`
  - `sntrup_1013`
  - `sntrup_1277`
- **HQC** (FIPS 207)
  - `hqc_128`, `hqc_192`, `hqc_256`

### Signatures

- **ML-DSA** (FIPS 204)
  - `ml_dsa_44`, `ml_dsa_65`, `ml_dsa_87`
- **SLH-DSA** (FIPS 205)
  - `slh_dsa_sha2_128s`
  - `slh_dsa_sha2_128f`
  - `slh_dsa_sha2_192s`
  - `slh_dsa_sha2_192f`
  - `slh_dsa_sha2_256s`
  - `slh_dsa_sha2_256f`
  - `slh_dsa_shake_128s`
  - `slh_dsa_shake_128f`
  - `slh_dsa_shake_192s`
  - `slh_dsa_shake_192f`
  - `slh_dsa_shake_256s`
  - `slh_dsa_shake_256f`

## Security

The cryptographic implementations are provided by the backbone crates.
These crates have not undergone a formal security audit; third-party review is
recommended before production use. This Python wrapper is a thin shim — it
validates key lengths, maps errors to Python exceptions, and provides idiomatic
key objects.

## License

Apache-2.0. See [LICENSE](LICENSE).
