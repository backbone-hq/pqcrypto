import pytest
import pkgutil
import importlib
import pqcrypto.kem
from secrets import compare_digest

finders = [
    finder
    for finder in pkgutil.iter_modules(pqcrypto.kem.__path__)
    if not finder.name.startswith("_")
]
modules = [importlib.import_module(f"pqcrypto.kem.{module.name}") for module in finders]


@pytest.mark.parametrize("variant", modules)
def test_generate_keypair(variant):
    variant.generate_keypair()


@pytest.mark.parametrize("variant", modules)
def test_integration(variant):
    # Alice generates a public key
    public_key, secret_key = variant.generate_keypair()

    # Bob derives a secret (the plaintext) and encrypts it with Alice's public key to produce a ciphertext
    ciphertext, plaintext_original = variant.encrypt(public_key)

    # Alice decrypts Bob's ciphertext to derive the now shared secret
    plaintext_recovered = variant.decrypt(secret_key, ciphertext)

    # Compare the original and recovered secrets in constant time
    assert compare_digest(plaintext_original, plaintext_recovered)
