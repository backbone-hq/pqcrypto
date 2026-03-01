# ![PQCrypto](https://github.com/backbone-hq/pqcrypto/blob/master/media/pqcrypto.png?raw=true)

![PyPI Version](https://img.shields.io/pypi/v/pqcrypto)
![Build Status](https://img.shields.io/github/actions/workflow/status/backbone-hq/pqcrypto/ci.yml?branch=master)
![GitHub License](https://img.shields.io/github/license/backbone-hq/pqcrypto)
![Python Version](https://img.shields.io/pypi/pyversions/pqcrypto)

# 👻 Post-Quantum Cryptography

In recent years, there has been a substantial amount of research on quantum computers – machines that exploit quantum mechanical phenomena to solve mathematical problems that are difficult or intractable for conventional computers. If large-scale quantum computers are ever built, they will be able to break many of the public-key cryptosystems currently in use. This would seriously compromise the confidentiality and integrity of digital communications on the Internet and elsewhere. The goal of post-quantum cryptography (also called quantum-resistant cryptography) is to develop cryptographic systems that are secure against both quantum and classical computers, and can interoperate with existing communications protocols and networks.

## 🎯 Purpose

PQCrypto provides tested, ergonomic **Python 3** CFFI bindings to implementations of quantum-resistant cryptographic algorithms that were submitted to the [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization) process.

This library focuses exclusively on post-quantum cryptography for Python, adhering to the Unix philosophy of doing one thing well. The cryptographic primitives are designed to be composable with existing cryptographic libraries, enabling simple integration of post-quantum cryptography into existing applications without sacrificing security or performance.

## 💾 Installation

You can install PQCrypto using your package manager of choice.
Pre-compiled wheels are available for common platforms and Python versions.

Using `uv`:

```bash
uv add pqcrypto
```

Using `poetry`:

```bash
poetry add pqcrypto
```

Using `pip`:

```bash
pip install pqcrypto
```

## 🔐 Key Encapsulation

A Key Encapsulation Mechanism (KEM) is a cryptographic primitive used to securely establish a shared secret key between two parties over an insecure channel. Unlike traditional asymmetric encryption, which focuses on encrypting arbitrary messages, a KEM is specifically designed for the secure transmission of symmetric keys.

```python
from secrets import compare_digest
from pqcrypto.kem.mceliece8192128 import generate_keypair, encrypt, decrypt

# Alice generates a (public, secret) key pair
public_key, secret_key = generate_keypair()

# Bob derives a secret (the plaintext) and encrypts it with Alice's public key to produce a ciphertext
ciphertext, plaintext_original = encrypt(public_key)

# Alice decrypts Bob's ciphertext to derive the now shared secret
plaintext_recovered = decrypt(secret_key, ciphertext)

# Compare the original and recovered secrets in constant time
assert compare_digest(plaintext_original, plaintext_recovered)
```

## ✒️ Signing

Digital signatures are cryptographic mechanisms that provide authentication, non-repudiation, and integrity to digital messages or documents. They allow the recipient to verify that a message was created by a known sender and hasn't been altered during transmission.

```python
from pqcrypto.sign.sphincs_shake_256s_simple import generate_keypair, sign, verify

# Alice generates a (public, secret) key pair
public_key, secret_key = generate_keypair()

# Alice signs her message using her secret key
signature = sign(secret_key, b"Hello world")

# Bob uses Alice's public key to validate her signature
assert verify(public_key, b"Hello world", signature)
```

## 🔒 Hybrid Encryption (KEM + Symmetric Cipher)

A KEM alone only establishes a shared secret — it does not encrypt arbitrary messages. To encrypt data, combine the KEM with a symmetric cipher in a hybrid scheme. The KEM bootstraps a shared key and the symmetric cipher uses the key to encrypt the plaintext.

This example uses [`mceliece8192128`](https://classic.mceliece.org/) for key encapsulation and [`ChaCha20-Poly1305`](https://cr.yp.to/chacha.html) for authenticated symmetric encryption.

> **Note:** This example requires the [`cryptography`](https://pypi.org/project/cryptography/) package (`pip install cryptography`).

```python
import os
from pqcrypto.kem.mceliece8192128 import generate_keypair, encrypt, decrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Alice generates a (public, secret) key pair
public_key, secret_key = generate_keypair()

# Alice encrypts a message using Bob's public key
message = b"Hello, post-quantum world!"

# Alice encapsulates a fresh shared secret using Bob's public key.
# `kem_ciphertext` is sent to Bob
# `shared_secret` never leaves Alice's memory
kem_ciphertext, shared_secret = encrypt(public_key)

# Alice uses the shared secret as a ChaCha20-Poly1305 key.
# A random 96-bit nonce is generated for each message
# It is IMPORTANT to never reuse a nonce.
nonce = os.urandom(12)
chacha = ChaCha20Poly1305(shared_secret)
ciphertext = chacha.encrypt(nonce, message, associated_data=None)

# Alice sends (kem_ciphertext, nonce, ciphertext) to Bob.

# Bob decapsulates the shared secret using his secret key
shared_secret_recovered = decrypt(secret_key, kem_ciphertext)

# Bob decrypts the message using the recovered shared secret
chacha = ChaCha20Poly1305(shared_secret_recovered)
message_recovered = chacha.decrypt(nonce, ciphertext, associated_data=None)

assert message_recovered == message
```

## 📋 Available Algorithms

### Key Encapsulation Mechanisms

```
- hqc_128
- hqc_192
- hqc_256
- mceliece348864
- mceliece348864f
- mceliece460896
- mceliece460896f
- mceliece6688128
- mceliece6688128f
- mceliece6960119
- mceliece6960119f
- mceliece8192128
- mceliece8192128f
- ml_kem_1024
- ml_kem_512
- ml_kem_768
```

### Signature Algorithms

```
- falcon_1024
- falcon_512
- falcon_padded_1024
- falcon_padded_512
- ml_dsa_44
- ml_dsa_65
- ml_dsa_87
- sphincs_sha2_128f_simple
- sphincs_sha2_128s_simple
- sphincs_sha2_192f_simple
- sphincs_sha2_192s_simple
- sphincs_sha2_256f_simple
- sphincs_sha2_256s_simple
- sphincs_shake_128f_simple
- sphincs_shake_128s_simple
- sphincs_shake_192f_simple
- sphincs_shake_192s_simple
- sphincs_shake_256f_simple
- sphincs_shake_256s_simple
```

## 🙏 Credits

The C implementations used herein are derived from the [PQClean](https://github.com/pqclean/pqclean/) project.

---

Built with ❤️ by [Backbone](https://backbone.dev)
