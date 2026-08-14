//! Signing bindings: ML-DSA, SLH-DSA (SPHINCS+).
//!
//! Uses the published backbone-* crates (v0.2.0) from crates.io.
//! The Python API mirrors the Rust design: `keygen` and a unified
//! `sign`/`verify` taking `context` and `hash_algorithm`.
//! FN-DSA (Falcon) has been removed — no backbone-fn-dsa published.

use crate::register_classes;
use pyo3::exceptions::PyValueError as PyValErr;
use pyo3::prelude::*;

/// Hash algorithms for HashML-DSA / HashSLH-DSA pre-hash mode (FIPS 204/205).
///
/// Mirrors `backbone_pqcrypto_internals::oid::HashAlgorithm`.
#[pyclass(eq, eq_int, from_py_object, name = "HashAlgorithm")]
#[derive(Clone, Copy, PartialEq)]
pub enum HashAlgorithm {
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA-512/224.
    Sha512_224,
    /// SHA-512/256.
    Sha512_256,
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// SHAKE-128.
    Shake128,
    /// SHAKE-256.
    Shake256,
}

impl From<HashAlgorithm> for backbone_ml_dsa::HashAlgorithm {
    fn from(h: HashAlgorithm) -> Self {
        match h {
            HashAlgorithm::Sha224 => Self::Sha224,
            HashAlgorithm::Sha256 => Self::Sha256,
            HashAlgorithm::Sha384 => Self::Sha384,
            HashAlgorithm::Sha512 => Self::Sha512,
            HashAlgorithm::Sha512_224 => Self::Sha512_224,
            HashAlgorithm::Sha512_256 => Self::Sha512_256,
            HashAlgorithm::Sha3_224 => Self::Sha3_224,
            HashAlgorithm::Sha3_256 => Self::Sha3_256,
            HashAlgorithm::Sha3_384 => Self::Sha3_384,
            HashAlgorithm::Sha3_512 => Self::Sha3_512,
            HashAlgorithm::Shake128 => Self::Shake128,
            HashAlgorithm::Shake256 => Self::Shake256,
        }
    }
}

// ---------------------------------------------------------------------------
// ML-DSA (FIPS 204) and SLH-DSA / SPHINCS+ (FIPS 205)
//
// Both crates expose the same 0.2 API shape, so one macro generates
// every variant; `$sign_crate` picks the backbone crate.
// ---------------------------------------------------------------------------

macro_rules! sign_variant {
    ($cls:ident, $sign_crate:ident, $mod:ident, $pk:literal, $sk:literal, $sig:literal, $doc:expr) => {
        #[pyclass]
        #[doc = $doc]
        pub struct $cls;
        #[pymethods]
        impl $cls {
            #[staticmethod]
            fn keygen() -> PyResult<(Vec<u8>, Vec<u8>)> {
                let (pk, sk) =
                    $sign_crate::$mod::keygen().map_err(|e| PyValErr::new_err(e.to_string()))?;
                Ok((pk.pk.to_vec(), sk.as_ref().to_vec()))
            }

            #[staticmethod]
            #[pyo3(signature = (sk, msg, context=None, hash_algorithm=None))]
            fn sign(
                sk: &[u8],
                msg: &[u8],
                context: Option<&[u8]>,
                hash_algorithm: Option<HashAlgorithm>,
            ) -> PyResult<Vec<u8>> {
                let key = $sign_crate::$mod::SecretKey::from_bytes(sk)
                    .map_err(|e| PyValErr::new_err(e.to_string()))?;
                let hash = hash_algorithm.map(Into::into);
                let sig = $sign_crate::$mod::sign(&key, msg, context, hash)
                    .map_err(|e| PyValErr::new_err(e.to_string()))?;
                Ok(sig.sig.to_vec())
            }

            #[staticmethod]
            #[pyo3(signature = (pk, msg, sig, context=None, hash_algorithm=None))]
            fn verify(
                pk: &[u8],
                msg: &[u8],
                sig: &[u8],
                context: Option<&[u8]>,
                hash_algorithm: Option<HashAlgorithm>,
            ) -> PyResult<()> {
                let pk_key = $sign_crate::$mod::PublicKey::from_bytes(pk)
                    .map_err(|e| PyValErr::new_err(e.to_string()))?;
                let sig_obj = $sign_crate::$mod::Signature::from_bytes(sig)
                    .map_err(|e| PyValErr::new_err(e.to_string()))?;
                let hash = hash_algorithm.map(Into::into);
                match $sign_crate::$mod::verify(&pk_key, msg, &sig_obj, context, hash) {
                    Ok(()) => Ok(()),
                    Err($sign_crate::error::Error::InvalidSignature) => Err(
                        crate::InvalidSignatureError::new_err("signature verification failed"),
                    ),
                    Err(e) => Err(PyValErr::new_err(e.to_string())),
                }
            }

            #[classattr]
            const PK_SIZE: u32 = $pk;
            #[classattr]
            const SK_SIZE: u32 = $sk;
            #[classattr]
            const SIG_SIZE: u32 = $sig;
        }
    };
}

sign_variant!(
    Mldsa44,
    backbone_ml_dsa,
    mldsa44,
    1312,
    2560,
    2420,
    "ML-DSA-44 (SL1)."
);
sign_variant!(
    Mldsa65,
    backbone_ml_dsa,
    mldsa65,
    1952,
    4032,
    3309,
    "ML-DSA-65 (SL3)."
);
sign_variant!(
    Mldsa87,
    backbone_ml_dsa,
    mldsa87,
    2592,
    4896,
    4627,
    "ML-DSA-87 (SL5)."
);

sign_variant!(
    SlhDsaSha2_128s,
    backbone_sphincs,
    sha2_128s,
    32,
    64,
    7856,
    "SLH-DSA SHA2-128s."
);
sign_variant!(
    SlhDsaSha2_128f,
    backbone_sphincs,
    sha2_128f,
    32,
    64,
    17088,
    "SLH-DSA SHA2-128f."
);
sign_variant!(
    SlhDsaSha2_192s,
    backbone_sphincs,
    sha2_192s,
    48,
    96,
    16224,
    "SLH-DSA SHA2-192s."
);
sign_variant!(
    SlhDsaSha2_192f,
    backbone_sphincs,
    sha2_192f,
    48,
    96,
    35664,
    "SLH-DSA SHA2-192f."
);
sign_variant!(
    SlhDsaSha2_256s,
    backbone_sphincs,
    sha2_256s,
    64,
    128,
    29792,
    "SLH-DSA SHA2-256s."
);
sign_variant!(
    SlhDsaSha2_256f,
    backbone_sphincs,
    sha2_256f,
    64,
    128,
    49856,
    "SLH-DSA SHA2-256f."
);
sign_variant!(
    SlhDsaShake_128s,
    backbone_sphincs,
    shake128s,
    32,
    64,
    7856,
    "SLH-DSA SHAKE-128s."
);
sign_variant!(
    SlhDsaShake_128f,
    backbone_sphincs,
    shake128f,
    32,
    64,
    17088,
    "SLH-DSA SHAKE-128f."
);
sign_variant!(
    SlhDsaShake_192s,
    backbone_sphincs,
    shake192s,
    48,
    96,
    16224,
    "SLH-DSA SHAKE-192s."
);
sign_variant!(
    SlhDsaShake_192f,
    backbone_sphincs,
    shake192f,
    48,
    96,
    35664,
    "SLH-DSA SHAKE-192f."
);
sign_variant!(
    SlhDsaShake_256s,
    backbone_sphincs,
    shake256s,
    64,
    128,
    29792,
    "SLH-DSA SHAKE-256s."
);
sign_variant!(
    SlhDsaShake_256f,
    backbone_sphincs,
    shake256f,
    64,
    128,
    49856,
    "SLH-DSA SHAKE-256f."
);

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<HashAlgorithm>()?;
    register_classes!(
        m,
        Mldsa44,
        Mldsa65,
        Mldsa87,
        SlhDsaSha2_128s,
        SlhDsaSha2_128f,
        SlhDsaSha2_192s,
        SlhDsaSha2_192f,
        SlhDsaSha2_256s,
        SlhDsaSha2_256f,
        SlhDsaShake_128s,
        SlhDsaShake_128f,
        SlhDsaShake_192s,
        SlhDsaShake_192f,
        SlhDsaShake_256s,
        SlhDsaShake_256f,
    );
    Ok(())
}
