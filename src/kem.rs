//! KEM bindings: ML-KEM, Classic McEliece, SNTRUP, HQC.
//!
//! Uses the published backbone-* crates (v0.2.0) from crates.io.
//! The Python API mirrors the Rust design: `keygen`, `encaps`, `decaps`.
//! All four KEM crates share the same API shape, so a single macro
//! generates every variant.

use crate::register_classes;
use pyo3::exceptions::PyValueError as PyValErr;
use pyo3::prelude::*;

macro_rules! kem_variant {
    ($cls:ident, $kem_crate:ident, $mod:ident, $ek:literal, $dk:literal, $ct:literal, $doc:expr) => {
        #[pyclass]
        #[doc = $doc]
        pub struct $cls;
        #[pymethods]
        impl $cls {
            #[staticmethod]
            fn keygen() -> PyResult<(Vec<u8>, Vec<u8>)> {
                let (pk, sk) =
                    $kem_crate::$mod::keygen().map_err(|e| PyValErr::new_err(e.to_string()))?;
                Ok((pk.pk.to_vec(), sk.as_ref().to_vec()))
            }
            #[staticmethod]
            fn encaps(pk_bytes: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
                let pk = $kem_crate::$mod::PublicKey::from_bytes(pk_bytes)
                    .map_err(|e| PyValErr::new_err(e.to_string()))?;
                let enc =
                    $kem_crate::$mod::encaps(&pk).map_err(|e| PyValErr::new_err(e.to_string()))?;
                Ok((enc.ciphertext.clone(), enc.shared_secret.to_vec()))
            }
            #[staticmethod]
            fn decaps(sk_bytes: &[u8], ct_bytes: &[u8]) -> PyResult<Vec<u8>> {
                let sk = $kem_crate::$mod::SecretKey::from_bytes(sk_bytes)
                    .map_err(|e| PyValErr::new_err(e.to_string()))?;
                let ss = $kem_crate::$mod::decaps(&sk, ct_bytes)
                    .map_err(|e| PyValErr::new_err(e.to_string()))?;
                Ok(ss.to_vec())
            }
            #[classattr]
            const EK_LEN: u32 = $ek;
            #[classattr]
            const DK_LEN: u32 = $dk;
            #[classattr]
            const CT_LEN: u32 = $ct;
            #[classattr]
            const SS_LEN: u32 = 32;
        }
    };
}

// ---------------------------------------------------------------------------
// ML-KEM (FIPS 203) — keygen seed 64 (d‖z), encaps seed 32 (m)
// ---------------------------------------------------------------------------

kem_variant!(
    MlKem512,
    backbone_ml_kem,
    mlkem512,
    800,
    1632,
    768,
    "ML-KEM-512 (SL1)."
);
kem_variant!(
    MlKem768,
    backbone_ml_kem,
    mlkem768,
    1184,
    2400,
    1088,
    "ML-KEM-768 (SL3)."
);
kem_variant!(
    MlKem1024,
    backbone_ml_kem,
    mlkem1024,
    1568,
    3168,
    1568,
    "ML-KEM-1024 (SL5)."
);

// ---------------------------------------------------------------------------
// Classic McEliece — keygen/encaps seed 48 (AES-256-CTR DRBG)
// ---------------------------------------------------------------------------

kem_variant!(
    McEliece348864,
    backbone_mceliece,
    mceliece348864,
    261120,
    6492,
    96,
    "McEliece 348864."
);
kem_variant!(
    McEliece348864f,
    backbone_mceliece,
    mceliece348864f,
    261120,
    6492,
    96,
    "McEliece 348864f (fast)."
);
kem_variant!(
    McEliece460896,
    backbone_mceliece,
    mceliece460896,
    524160,
    13608,
    156,
    "McEliece 460896."
);
kem_variant!(
    McEliece460896f,
    backbone_mceliece,
    mceliece460896f,
    524160,
    13608,
    156,
    "McEliece 460896f (fast)."
);
kem_variant!(
    McEliece6688128,
    backbone_mceliece,
    mceliece6688128,
    1044992,
    13932,
    208,
    "McEliece 6688128."
);
kem_variant!(
    McEliece6688128f,
    backbone_mceliece,
    mceliece6688128f,
    1044992,
    13932,
    208,
    "McEliece 6688128f (fast)."
);
kem_variant!(
    McEliece6960119,
    backbone_mceliece,
    mceliece6960119,
    1047319,
    13948,
    194,
    "McEliece 6960119."
);
kem_variant!(
    McEliece6960119f,
    backbone_mceliece,
    mceliece6960119f,
    1047319,
    13948,
    194,
    "McEliece 6960119f (fast)."
);
kem_variant!(
    McEliece8192128,
    backbone_mceliece,
    mceliece8192128,
    1357824,
    14120,
    208,
    "McEliece 8192128."
);
kem_variant!(
    McEliece8192128f,
    backbone_mceliece,
    mceliece8192128f,
    1357824,
    14120,
    208,
    "McEliece 8192128f (fast)."
);

// ---------------------------------------------------------------------------
// Streamlined NTRU Prime — keygen/encaps seed 48 (AES-256-CTR DRBG)
// ---------------------------------------------------------------------------

kem_variant!(
    Sntrup653,
    backbone_sntrup,
    sntrup653,
    994,
    1518,
    897,
    "SNTRUP-653 (SL1)."
);
kem_variant!(
    Sntrup761,
    backbone_sntrup,
    sntrup761,
    1158,
    1763,
    1039,
    "SNTRUP-761 (SL2)."
);
kem_variant!(
    Sntrup857,
    backbone_sntrup,
    sntrup857,
    1322,
    1999,
    1184,
    "SNTRUP-857 (SL3)."
);
kem_variant!(
    Sntrup953,
    backbone_sntrup,
    sntrup953,
    1505,
    2254,
    1349,
    "SNTRUP-953 (SL4)."
);
kem_variant!(
    Sntrup1013,
    backbone_sntrup,
    sntrup1013,
    1623,
    2417,
    1455,
    "SNTRUP-1013 (SL5)."
);
kem_variant!(
    Sntrup1277,
    backbone_sntrup,
    sntrup1277,
    2067,
    3059,
    1847,
    "SNTRUP-1277 (SL5)."
);

// ---------------------------------------------------------------------------
// HQC (FIPS 207) — keygen/encaps seed 48 (SHAKE-256)
// ---------------------------------------------------------------------------

kem_variant!(
    Hqc128,
    backbone_hqc,
    hqc128,
    2241,
    2321,
    4433,
    "HQC-128 (SL1) — FIPS 207."
);
kem_variant!(
    Hqc192,
    backbone_hqc,
    hqc192,
    4514,
    4602,
    8978,
    "HQC-192 (SL3) — FIPS 207."
);
kem_variant!(
    Hqc256,
    backbone_hqc,
    hqc256,
    7237,
    7333,
    14421,
    "HQC-256 (SL5) — FIPS 207."
);

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    register_classes!(
        m,
        MlKem512,
        MlKem768,
        MlKem1024,
        McEliece348864,
        McEliece348864f,
        McEliece460896,
        McEliece460896f,
        McEliece6688128,
        McEliece6688128f,
        McEliece6960119,
        McEliece6960119f,
        McEliece8192128,
        McEliece8192128f,
        Sntrup653,
        Sntrup761,
        Sntrup857,
        Sntrup953,
        Sntrup1013,
        Sntrup1277,
        Hqc128,
        Hqc192,
        Hqc256,
    );
    Ok(())
}
