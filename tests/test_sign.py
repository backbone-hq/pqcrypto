import pytest
import pkgutil
import importlib
import pqcrypto.sign

finders = [
    finder
    for finder in pkgutil.iter_modules(pqcrypto.sign.__path__)
    if not finder.name.startswith("_")
]
modules = [
    importlib.import_module(f"pqcrypto.sign.{module.name}")
    for module in finders
    if module.name != "common"
]


@pytest.mark.parametrize("variant", modules)
def test_generate_keypair(variant):
    variant.generate_keypair()


@pytest.mark.parametrize("variant", modules)
def test_integration(variant):
    # Alice generates a public key
    public_key, secret_key = variant.generate_keypair()

    # Bob derives a secret (the plaintext) and encrypts it with Alice's public key to produce a ciphertext
    message = b"Hello World"
    signature = variant.sign(secret_key, message)

    # Alice decrypts Bob's ciphertext to derive the now shared secret
    assert variant.verify(public_key, message, signature)
