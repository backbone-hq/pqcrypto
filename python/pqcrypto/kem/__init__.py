"""Key Encapsulation Mechanisms (KEM).

Each KEM algorithm is available as a submodule mirroring the Rust crate API::

    from pqcrypto.kem.ml_kem_512 import keygen, encaps, decaps

Each submodule exposes:

    keygen()                       → (pk: bytes, sk: bytes)
    encaps(pk)                     → (ciphertext: bytes, shared_secret: bytes)
    decaps(sk, ct)                 → shared_secret: bytes
    PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, CIPHERTEXT_SIZE, SHARED_SECRET_SIZE  — constants

    PublicKey(pk_bytes)  — key object with ``.encaps()``
    SecretKey(sk_bytes)  — key object with ``.decaps(ct)``
"""

from pqcrypto._base import _make_kem_pk, _make_kem_sk, _setup_submodules

_NAME_OVERRIDES: dict[str, str] = {
    "MlKem512": "ml_kem_512",
    "MlKem768": "ml_kem_768",
    "MlKem1024": "ml_kem_1024",
    "McEliece348864": "mceliece_348864",
    "McEliece348864f": "mceliece_348864f",
    "McEliece460896": "mceliece_460896",
    "McEliece460896f": "mceliece_460896f",
    "McEliece6688128": "mceliece_6688128",
    "McEliece6688128f": "mceliece_6688128f",
    "McEliece6960119": "mceliece_6960119",
    "McEliece6960119f": "mceliece_6960119f",
    "McEliece8192128": "mceliece_8192128",
    "McEliece8192128f": "mceliece_8192128f",
    "Sntrup653": "sntrup_653",
    "Sntrup761": "sntrup_761",
    "Sntrup857": "sntrup_857",
    "Sntrup953": "sntrup_953",
    "Sntrup1013": "sntrup_1013",
    "Sntrup1277": "sntrup_1277",
    "Hqc128": "hqc_128",
    "Hqc192": "hqc_192",
    "Hqc256": "hqc_256",
}

_setup_submodules(
    parent_package_name=__name__,
    detector_attr="encaps",
    name_overrides=_NAME_OVERRIDES,
    function_bindings=[
        ("keygen", "keygen"),
        ("encaps", "encaps"),
        ("decaps", "decaps"),
    ],
    const_bindings=[
        ("PUBLIC_KEY_SIZE", "EK_LEN"),
        ("SECRET_KEY_SIZE", "DK_LEN"),
        ("CIPHERTEXT_SIZE", "CT_LEN"),
        ("SHARED_SECRET_SIZE", "SS_LEN"),
    ],
    make_pk=_make_kem_pk,
    make_sk=_make_kem_sk,
)
