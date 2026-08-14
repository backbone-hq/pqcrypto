"""PQCrypto — post-quantum cryptographic primitives.

Usage
-----

    from pqcrypto import ml_kem_512
    ml_kem_512.keygen()
    ml_kem_512.encaps(pk)

All algorithms are available as top-level submodules, grouped under
``pqcrypto.kem`` and ``pqcrypto.sign`` for discovery::

    from pqcrypto.kem import ml_kem_512
    from pqcrypto.sign import ml_dsa_44

Each submodule mirrors the Rust crate API (``keygen``, ``encaps``,
``decaps``, ``sign``, ``verify``, …). ``HashAlgorithm`` selects
pre-hash mode for HashML-DSA / HashSLH-DSA::

    from pqcrypto import HashAlgorithm
    sig = ml_dsa_44.sign(sk, msg, hash_algorithm=HashAlgorithm.Sha256)
"""

import types as _types

__version__ = "1.0.0"

# Trigger submodule discovery, then re-export every algorithm submodule
# at the top level so users can write ``from pqcrypto import ml_kem_512``.

from pqcrypto import kem as _kem
from pqcrypto import sign as _sign
from pqcrypto.pqcrypto import HashAlgorithm, InvalidSignatureError

__all__ = ["HashAlgorithm", "InvalidSignatureError"]
for _pkg in (_kem, _sign):
    for _name in dir(_pkg):
        if _name.startswith("_"):
            continue
        _obj = getattr(_pkg, _name)
        if isinstance(_obj, _types.ModuleType):
            globals()[_name] = _obj
            __all__.append(_name)
