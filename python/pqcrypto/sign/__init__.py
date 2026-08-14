"""Digital Signature Algorithms.

Each signature algorithm is available as a submodule mirroring the Rust crate API::

    from pqcrypto.sign.ml_dsa_44 import keygen, sign, verify

Each submodule exposes:

    === Flat functions ===
    keygen()                                  → (pk: bytes, sk: bytes)
    sign(sk, msg, context=None, hash_algorithm=None)  → signature: bytes
    verify(pk, msg, sig, context=None, hash_algorithm=None) → None, or raises
                                                      InvalidSignatureError

    `context` is the FIPS 204/205 domain-separation string (max 255 bytes);
    `hash_algorithm` selects HashML-DSA / HashSLH-DSA pre-hash mode
    (see ``pqcrypto.HashAlgorithm``). Both default to None = pure mode.

    === Constants ===
    PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SIGNATURE_SIZE

    === Object API ===
    PublicKey(pk_bytes)  — .verify(msg, sig, context=None, hash_algorithm=None)
    SecretKey(sk_bytes)  — .sign(msg, context=None, hash_algorithm=None)
    Signature(sig_bytes) — signature wrapper
"""

from pqcrypto._base import _make_sign_pk, _make_sign_sk, _setup_submodules

_NAME_OVERRIDES: dict[str, str] = {
    "Mldsa44": "ml_dsa_44",
    "Mldsa65": "ml_dsa_65",
    "Mldsa87": "ml_dsa_87",
    "SlhDsaSha2_128s": "slh_dsa_sha2_128s",
    "SlhDsaSha2_128f": "slh_dsa_sha2_128f",
    "SlhDsaSha2_192s": "slh_dsa_sha2_192s",
    "SlhDsaSha2_192f": "slh_dsa_sha2_192f",
    "SlhDsaSha2_256s": "slh_dsa_sha2_256s",
    "SlhDsaSha2_256f": "slh_dsa_sha2_256f",
    "SlhDsaShake_128s": "slh_dsa_shake_128s",
    "SlhDsaShake_128f": "slh_dsa_shake_128f",
    "SlhDsaShake_192s": "slh_dsa_shake_192s",
    "SlhDsaShake_192f": "slh_dsa_shake_192f",
    "SlhDsaShake_256s": "slh_dsa_shake_256s",
    "SlhDsaShake_256f": "slh_dsa_shake_256f",
}

_setup_submodules(
    parent_package_name=__name__,
    detector_attr="sign",
    name_overrides=_NAME_OVERRIDES,
    function_bindings=[
        ("keygen", "keygen"),
        ("sign", "sign"),
        ("verify", "verify"),
    ],
    const_bindings=[
        ("PUBLIC_KEY_SIZE", "PK_SIZE"),
        ("SECRET_KEY_SIZE", "SK_SIZE"),
        ("SIGNATURE_SIZE", "SIG_SIZE"),
    ],
    make_pk=_make_sign_pk,
    make_sk=_make_sign_sk,
)
