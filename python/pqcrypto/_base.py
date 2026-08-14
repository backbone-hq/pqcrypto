"""Base classes for PQCrypto Python key object wrappers and shared submodule discovery.

Each algorithm submodule dynamically creates algorithm-specific subclasses
via factory functions below — this module provides the shared method logic
to avoid duplicating it per-algorithm.

The :func:`_setup_submodules` function is the shared engine that
``pqcrypto.kem`` and ``pqcrypto.sign`` call to auto-discover algorithm
classes from the compiled Rust module and wrap them as Python submodules.
"""

import re
from hmac import compare_digest


_ALGORITHM_NAME_RE = re.compile(r"(?<=[a-z])(?=[A-Z])|(?<=[a-zA-Z])(?=\d)")


def _to_module_name(cls_name, name_overrides):
    """Convert a Rust pyclass name (e.g. ``MlKem512``) to a Python module
    name (e.g. ``ml_kem_512``), consulting *name_overrides* first."""
    if cls_name in name_overrides:
        return name_overrides[cls_name]
    return _ALGORITHM_NAME_RE.sub("_", cls_name).lower()


def _setup_submodules(
    parent_package_name,
    detector_attr,
    name_overrides,
    function_bindings,
    const_bindings,
    make_pk,
    make_sk,
):
    """Discover algorithm pyclasses in the compiled Rust module and create
    a Python submodule for each one.

    Parameters
    ----------
    parent_package_name : str
        The dotted package name, e.g. ``"pqcrypto.kem"``.
    detector_attr : str
        Attribute that identifies an algorithm pyclass, e.g. ``"encaps"``.
    name_overrides : dict[str, str]
        Manual class-name → module-name mappings for names the regex can't handle.
    function_bindings : list[(str, str)]
        Pairs of ``(python_name, rust_method_name)`` to expose as module-level
        functions.
    const_bindings : list[(str, str)]
        Pairs of ``(python_name, rust_classattr_name)`` to expose as module-level
        integer constants.
    make_pk : (ModuleType) -> type
        Factory that returns a ``PublicKey`` subclass for the given module.
    make_sk : (ModuleType) -> type
        Factory that returns a ``SecretKey`` subclass for the given module.
    """
    import sys
    import types
    import pqcrypto.pqcrypto as _rust_mod

    for _candidate in dir(_rust_mod):
        _cls = getattr(_rust_mod, _candidate)
        if not (isinstance(_cls, type) and hasattr(_cls, detector_attr)):
            continue

        _sub_name = _to_module_name(_candidate, name_overrides)
        _fqn = f"{parent_package_name}.{_sub_name}"

        if _fqn in sys.modules:
            continue

        _mod = types.ModuleType(_fqn)
        _mod.__package__ = parent_package_name
        _mod.__doc__ = (_cls.__doc__ or "").strip()

        for py_name, rust_attr in function_bindings:
            attr = getattr(_cls, rust_attr, None)
            if attr is not None:
                setattr(_mod, py_name, attr)

        for py_name, rust_attr in const_bindings:
            setattr(_mod, py_name, int(getattr(_cls, rust_attr)))

        _mod.ALGORITHM = _candidate

        _mod.PublicKey = make_pk(_mod)
        _mod.PublicKey.__qualname__ = f"{_candidate}.PublicKey"
        _mod.PublicKey.__module__ = _fqn

        _mod.SecretKey = make_sk(_mod)
        _mod.SecretKey.__qualname__ = f"{_candidate}.SecretKey"
        _mod.SecretKey.__module__ = _fqn

        _mod.PublicKey.__name__ = f"{_candidate}.PublicKey"
        _mod.SecretKey.__name__ = f"{_candidate}.SecretKey"

        sys.modules[_fqn] = _mod
        setattr(sys.modules[parent_package_name], _sub_name, _mod)


def _make_key_factory(size_attr, base_cls):
    """Return a ``(mod) -> KeyClass`` factory for the given size attribute
    and base class."""
    key_type = "public" if size_attr == "PUBLIC_KEY_SIZE" else "secret"

    def _factory(mod):
        size = getattr(mod, size_attr)

        class Key(base_cls):
            def __new__(cls, key_bytes):
                if len(key_bytes) != size:
                    raise ValueError(
                        f"{key_type} key must be {size} bytes, got {len(key_bytes)}"
                    )
                instance = super().__new__(cls)
                instance._bytes = bytes(key_bytes)
                instance._alg = mod
                return instance

        return Key

    return _factory


class _KeyMixin:
    """Shared dunder methods for all key and signature types."""

    __slots__ = ()

    def __bytes__(self):
        return self._bytes

    def __len__(self):
        return len(self._bytes)

    def __repr__(self):
        return f"{self.__class__.__qualname__}({len(self)} bytes)"

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return compare_digest(self._bytes, other._bytes)

    def __hash__(self):
        return hash(self._bytes)


class KEMPublicKey(_KeyMixin):
    """Base for KEM public keys with an idiomatic ``.encaps()`` method."""

    __slots__ = ("_bytes", "_alg")

    def encaps(self):
        """Encapsulate a shared secret under this public key.

        Returns
        -------
        KEMEncapsulation
            A result object with ``.ciphertext`` and ``.shared_secret``.
        """
        ct, ss = self._alg.encaps(self._bytes)
        return KEMEncapsulation(ct, ss)

class KEMSecretKey(_KeyMixin):
    """Base for KEM secret keys with an idiomatic ``.decaps()`` method."""

    __slots__ = ("_bytes", "_alg")

    def decaps(self, ct):
        """Decapsulate a shared secret from a ciphertext.

        Parameters
        ----------
        ct : bytes
            The ciphertext to decaps.

        Returns
        -------
        bytes
            The shared secret.
        """
        return self._alg.decaps(self._bytes, ct)


class KEMEncapsulation:
    """Result of a KEM encapsulation."""

    __slots__ = ("ciphertext", "shared_secret")

    def __init__(self, ciphertext, shared_secret):
        self.ciphertext = bytes(ciphertext)
        self.shared_secret = bytes(shared_secret)

    def __iter__(self):
        return iter((self.ciphertext, self.shared_secret))

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"ciphertext={len(self.ciphertext)}B, "
            f"shared_secret={len(self.shared_secret)}B)"
        )

    def __eq__(self, other):
        if not isinstance(other, KEMEncapsulation):
            return NotImplemented
        return compare_digest(self.ciphertext, other.ciphertext) and compare_digest(
            self.shared_secret, other.shared_secret
        )


class SignPublicKey(_KeyMixin):
    """Base for signature public keys with an idiomatic ``.verify()`` method."""

    __slots__ = ("_bytes", "_alg")

    def _resolve_sig(self, sig):
        return bytes(sig) if isinstance(sig, Signature) else sig

    def verify(self, msg, sig, context=None, hash_algorithm=None):
        """Verify a signature on a message.

        Parameters
        ----------
        msg : bytes
            The message that was signed.
        sig : bytes | Signature
            The signature (raw bytes or ``Signature`` wrapper).
        context : bytes, optional
            The FIPS 204/205 domain-separation context (max 255 bytes).
        hash_algorithm : HashAlgorithm, optional
            Pre-hash mode selection for HashML-DSA / HashSLH-DSA.

        Raises
        ------
        InvalidSignatureError
            If the signature is invalid.
        ValueError
            If the key or signature is malformed.
        """
        return self._alg.verify(
            self._bytes,
            msg,
            self._resolve_sig(sig),
            context,
            hash_algorithm,
        )


class SignSecretKey(_KeyMixin):
    """Base for signature secret keys with an idiomatic ``.sign()`` method."""

    __slots__ = ("_bytes", "_alg")

    def sign(self, msg, context=None, hash_algorithm=None):
        """Sign a message.

        Parameters
        ----------
        msg : bytes
            The message to sign.
        context : bytes, optional
            The FIPS 204/205 domain-separation context (max 255 bytes).
        hash_algorithm : HashAlgorithm, optional
            Pre-hash mode selection for HashML-DSA / HashSLH-DSA.
        """
        raw = self._alg.sign(self._bytes, msg, context, hash_algorithm)
        return Signature(raw)

class Signature(_KeyMixin):
    """A digital signature."""

    __slots__ = ("_bytes",)

    def __init__(self, sig_bytes):
        self._bytes = bytes(sig_bytes)


_make_kem_pk = _make_key_factory("PUBLIC_KEY_SIZE", KEMPublicKey)
_make_kem_sk = _make_key_factory("SECRET_KEY_SIZE", KEMSecretKey)
_make_sign_pk = _make_key_factory("PUBLIC_KEY_SIZE", SignPublicKey)
_make_sign_sk = _make_key_factory("SECRET_KEY_SIZE", SignSecretKey)
