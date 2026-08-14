"""Roundtrip tests for all PQC algorithm variants.

Run with:
    pip install maturin pytest
    maturin develop
    pytest tests/test_roundtrip.py -v
"""

import pytest

KEM_VARIANTS = [
    ("ml_kem_512", 800, 1632, 768, 32),
    ("ml_kem_768", 1184, 2400, 1088, 32),
    ("ml_kem_1024", 1568, 3168, 1568, 32),
    ("mceliece_348864", 261120, 6492, 96, 32),
    ("mceliece_348864f", 261120, 6492, 96, 32),
    ("mceliece_460896", 524160, 13608, 156, 32),
    ("mceliece_460896f", 524160, 13608, 156, 32),
    ("mceliece_6688128", 1044992, 13932, 208, 32),
    ("mceliece_6688128f", 1044992, 13932, 208, 32),
    ("mceliece_6960119", 1047319, 13948, 194, 32),
    ("mceliece_6960119f", 1047319, 13948, 194, 32),
    ("mceliece_8192128", 1357824, 14120, 208, 32),
    ("mceliece_8192128f", 1357824, 14120, 208, 32),
    ("sntrup_653", 994, 1518, 897, 32),
    ("sntrup_761", 1158, 1763, 1039, 32),
    ("sntrup_857", 1322, 1999, 1184, 32),
    ("sntrup_953", 1505, 2254, 1349, 32),
    ("sntrup_1013", 1623, 2417, 1455, 32),
    ("sntrup_1277", 2067, 3059, 1847, 32),
    ("hqc_128", 2241, 2321, 4433, 32),
    ("hqc_192", 4514, 4602, 8978, 32),
    ("hqc_256", 7237, 7333, 14421, 32),
]

SIGN_VARIANTS = [
    ("ml_dsa_44", 1312, 2560, 2420),
    ("ml_dsa_65", 1952, 4032, 3309),
    ("ml_dsa_87", 2592, 4896, 4627),
    ("slh_dsa_sha2_128s", 32, 64, 7856),
    ("slh_dsa_sha2_128f", 32, 64, 17088),
    ("slh_dsa_sha2_192s", 48, 96, 16224),
    ("slh_dsa_sha2_192f", 48, 96, 35664),
    ("slh_dsa_sha2_256s", 64, 128, 29792),
    ("slh_dsa_sha2_256f", 64, 128, 49856),
    ("slh_dsa_shake_128s", 32, 64, 7856),
    ("slh_dsa_shake_128f", 32, 64, 17088),
    ("slh_dsa_shake_192s", 48, 96, 16224),
    ("slh_dsa_shake_192f", 48, 96, 35664),
    ("slh_dsa_shake_256s", 64, 128, 29792),
    ("slh_dsa_shake_256f", 64, 128, 49856),
]

# Fast smoke-test subsets (ML-KEM / ML-DSA only).
FAST_KEM = [v[0] for v in KEM_VARIANTS[:3]]
FAST_SIGN = [v[0] for v in SIGN_VARIANTS[:3]]


def _import_kem(name):
    """Dynamically import a KEM submodule."""
    return __import__(f"pqcrypto.kem.{name}", fromlist=["keygen"])


def _import_sign(name):
    """Dynamically import a sign submodule."""
    return __import__(f"pqcrypto.sign.{name}", fromlist=["keygen"])


@pytest.mark.parametrize("name,ek_len,dk_len,ct_len,ss_len", KEM_VARIANTS)
def test_kem_key_sizes(name, ek_len, dk_len, ct_len, ss_len):
    mod = _import_kem(name)
    assert ek_len == mod.PUBLIC_KEY_SIZE, f"{name}: PUBLIC_KEY_SIZE"
    assert dk_len == mod.SECRET_KEY_SIZE, f"{name}: SECRET_KEY_SIZE"
    assert ct_len == mod.CIPHERTEXT_SIZE, f"{name}: CIPHERTEXT_SIZE"
    assert ss_len == mod.SHARED_SECRET_SIZE, f"{name}: SHARED_SECRET_SIZE"


@pytest.mark.parametrize("name,ek_len,dk_len,ct_len,ss_len", KEM_VARIANTS)
def test_kem_roundtrip(name, ek_len, dk_len, ct_len, ss_len):
    mod = _import_kem(name)
    pk, sk = mod.keygen()
    assert len(pk) == ek_len, f"{name}: PK length"
    assert len(sk) == dk_len, f"{name}: SK length"
    ct, ss1 = mod.encaps(pk)
    assert len(ct) == ct_len, f"{name}: CT length"
    assert len(ss1) == ss_len, f"{name}: SS length"
    ss2 = mod.decaps(sk, ct)
    assert ss1 == ss2, f"{name}: shared secret mismatch"


@pytest.mark.parametrize("name,pk_size,sk_size,sig_size", SIGN_VARIANTS)
def test_sign_key_sizes(name, pk_size, sk_size, sig_size):
    mod = _import_sign(name)
    assert pk_size == mod.PUBLIC_KEY_SIZE, f"{name}: PUBLIC_KEY_SIZE"
    assert sk_size == mod.SECRET_KEY_SIZE, f"{name}: SECRET_KEY_SIZE"
    assert sig_size == mod.SIGNATURE_SIZE, f"{name}: SIGNATURE_SIZE"


@pytest.mark.parametrize("name,pk_size,sk_size,sig_size", SIGN_VARIANTS)
def test_sign_roundtrip(name, pk_size, sk_size, sig_size):
    mod = _import_sign(name)
    pk, sk = mod.keygen()
    assert len(pk) == pk_size, f"{name}: PK length"
    assert len(sk) == sk_size, f"{name}: SK length"
    msg = b"Hello, PQCrypto!"
    sig = mod.sign(sk, msg)
    assert len(sig) == sig_size, f"{name}: signature length"
    assert mod.verify(pk, msg, sig) is None, f"{name}: verify should return None"
    with pytest.raises(ValueError):
        mod.verify(pk, b"wrong", sig)


@pytest.mark.parametrize("name", FAST_KEM)
def test_kem_objects(name):
    mod = _import_kem(name)
    pk, sk = mod.keygen()
    pk_obj = mod.PublicKey(pk)
    sk_obj = mod.SecretKey(sk)
    enc = pk_obj.encaps()
    ss = sk_obj.decaps(enc.ciphertext)
    assert enc.shared_secret == ss


@pytest.mark.parametrize("name", FAST_SIGN)
def test_sign_objects(name):
    mod = _import_sign(name)
    pk, sk = mod.keygen()
    pk_obj = mod.PublicKey(pk)
    sk_obj = mod.SecretKey(sk)
    sig = sk_obj.sign(b"test")
    assert pk_obj.verify(b"test", sig) is None
    with pytest.raises(ValueError):
        pk_obj.verify(b"wrong", sig)


# -- Variant-specific tests (not covered by parametrized roundtrips) --


def test_sign_context_param():
    """sign/verify with a context string roundtrip."""
    mod = _import_sign("ml_dsa_44")
    pk, sk = mod.keygen()
    sig = mod.sign(sk, b"msg", b"mycontext")
    assert mod.verify(pk, b"msg", sig, b"mycontext") is None
    with pytest.raises(ValueError):
        mod.verify(pk, b"msg", sig, b"wrong")


def test_verify_invalid_signature_error():
    """Bad signature raises InvalidSignatureError (a ValueError subclass);
    malformed input raises plain ValueError."""
    from pqcrypto import InvalidSignatureError  # type: ignore[attr-defined]

    mod = _import_sign("ml_dsa_44")
    pk, sk = mod.keygen()
    msg = b"msg"
    sig = bytearray(mod.sign(sk, msg))
    sig[0] ^= 0xFF

    with pytest.raises(InvalidSignatureError):
        mod.verify(pk, msg, bytes(sig))
    with pytest.raises(ValueError) as exc:
        mod.verify(pk, msg, b"")  # malformed: wrong length
    assert not isinstance(exc.value, InvalidSignatureError)


@pytest.mark.parametrize("name", ["ml_dsa_44", "slh_dsa_shake_128s"])
def test_sign_hash_algorithm_roundtrip(name):
    """HashML-DSA / HashSLH-DSA pre-hash mode: sign and verify with the
    same hash algorithm."""
    from pqcrypto import HashAlgorithm  # type: ignore[attr-defined]

    mod = _import_sign(name)
    pk, sk = mod.keygen()
    msg = b"msg"
    sig = mod.sign(sk, msg, hash_algorithm=HashAlgorithm.Sha256)
    assert mod.verify(pk, msg, sig, hash_algorithm=HashAlgorithm.Sha256) is None, (
        f"{name}: pre-hash roundtrip must verify"
    )


@pytest.mark.parametrize("name", ["ml_dsa_44", "slh_dsa_shake_128s"])
def test_sign_hash_algorithm_mismatch(name):
    """Pre-hash mode rejects the wrong hash algorithm and refuses to mix
    with pure mode."""
    from pqcrypto import HashAlgorithm  # type: ignore[attr-defined]

    mod = _import_sign(name)
    pk, sk = mod.keygen()
    msg = b"msg"

    prehashed = mod.sign(sk, msg, hash_algorithm=HashAlgorithm.Sha256)
    with pytest.raises(ValueError):
        mod.verify(pk, msg, prehashed, hash_algorithm=HashAlgorithm.Sha384)
    with pytest.raises(ValueError):
        mod.verify(pk, msg, prehashed)  # pure verify of a pre-hash signature

    pure = mod.sign(sk, msg)
    with pytest.raises(ValueError):
        mod.verify(pk, msg, pure, hash_algorithm=HashAlgorithm.Sha256)


class TestKEMNegative:
    """Edge cases for KEM operations."""

    @pytest.mark.parametrize("name", ["ml_kem_512", "mceliece_348864", "sntrup_761"])
    def test_wrong_size_pk(self, name):
        mod = _import_kem(name)
        with pytest.raises(ValueError, match="public key must be"):
            mod.PublicKey(b"")
        with pytest.raises(ValueError, match="public key must be"):
            mod.PublicKey(b"x" * (mod.PUBLIC_KEY_SIZE + 1))

    @pytest.mark.parametrize("name", ["ml_kem_512", "mceliece_348864", "sntrup_761"])
    def test_wrong_size_sk(self, name):
        mod = _import_kem(name)
        with pytest.raises(ValueError, match="secret key must be"):
            mod.SecretKey(b"")
        with pytest.raises(ValueError, match="secret key must be"):
            mod.SecretKey(b"x" * (mod.SECRET_KEY_SIZE + 1))

    @pytest.mark.parametrize("name", ["ml_kem_512", "mceliece_348864", "sntrup_761"])
    def test_wrong_size_ct(self, name):
        mod = _import_kem(name)
        pk, sk = mod.keygen()
        with pytest.raises(ValueError):
            mod.decaps(sk, b"")
        with pytest.raises(ValueError):
            mod.decaps(sk, b"x" * (mod.CIPHERTEXT_SIZE + 1))

    @pytest.mark.parametrize("name", ["ml_kem_512", "mceliece_348864", "sntrup_761"])
    def test_encaps_with_sk(self, name):
        """Using a secret key where a public key is expected should fail."""
        mod = _import_kem(name)
        _, sk = mod.keygen()
        with pytest.raises(ValueError):
            mod.encaps(sk)

    @pytest.mark.parametrize("name", ["ml_kem_512", "mceliece_348864", "sntrup_761"])
    def test_decaps_wrong_key(self, name):
        """Decapsulating with an unrelated key yields a different shared secret."""
        mod = _import_kem(name)
        pk_a, sk_a = mod.keygen()
        _, sk_b = mod.keygen()
        ct, ss = mod.encaps(pk_a)
        assert mod.decaps(sk_a, ct) == ss, f"{name}: correct key must recover ss"
        result = mod.decaps(sk_b, ct)
        assert isinstance(result, bytes), f"{name}: wrong-key decaps must return bytes"
        assert len(result) == mod.SHARED_SECRET_SIZE, f"{name}: ss length"
        assert result != ss, f"{name}: wrong key must produce a different ss"


class TestSignNegative:
    """Edge cases for signature operations."""

    @pytest.mark.parametrize("name", ["ml_dsa_44", "slh_dsa_shake_128s"])
    def test_wrong_size_pk(self, name):
        mod = _import_sign(name)
        with pytest.raises(ValueError, match="public key must be"):
            mod.PublicKey(b"")
        with pytest.raises(ValueError, match="public key must be"):
            mod.PublicKey(b"x" * (mod.PUBLIC_KEY_SIZE + 1))

    @pytest.mark.parametrize("name", ["ml_dsa_44", "slh_dsa_shake_128s"])
    def test_wrong_size_sk(self, name):
        mod = _import_sign(name)
        with pytest.raises(ValueError, match="secret key must be"):
            mod.SecretKey(b"")
        with pytest.raises(ValueError, match="secret key must be"):
            mod.SecretKey(b"x" * (mod.SECRET_KEY_SIZE + 1))

    @pytest.mark.parametrize("name", ["ml_dsa_44", "slh_dsa_shake_128s"])
    def test_garbage_signature(self, name):
        """Verifying with a garbage signature raises ValueError."""
        mod = _import_sign(name)
        pk, sk = mod.keygen()
        with pytest.raises(ValueError):
            mod.verify(pk, b"msg", b"")
        with pytest.raises(ValueError):
            mod.verify(pk, b"msg", b"\xff" * (mod.SIGNATURE_SIZE + 10))

    @pytest.mark.parametrize("name", ["ml_dsa_44", "slh_dsa_shake_128s"])
    def test_sign_with_pk(self, name):
        """Using a public key where a secret key is expected should fail.

        Both crates validate key lengths, so a wrong-length key raises.
        """
        mod = _import_sign(name)
        pk, _ = mod.keygen()
        with pytest.raises(ValueError):
            mod.sign(pk, b"msg")

    @pytest.mark.parametrize("name", ["ml_dsa_44", "slh_dsa_shake_128s"])
    def test_tampered_signature(self, name):
        """A valid signature with one byte flipped fails verification."""
        mod = _import_sign(name)
        pk, sk = mod.keygen()
        msg = b"message"
        sig = bytearray(mod.sign(sk, msg))
        sig[0] ^= 0xFF  # flip all bits in first byte
        with pytest.raises(ValueError):
            mod.verify(pk, msg, bytes(sig))
