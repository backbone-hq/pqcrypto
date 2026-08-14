//! Python bindings for post-quantum cryptographic primitives.

mod kem;
mod sign;

use pyo3::create_exception;
use pyo3::prelude::*;

// Raised when a signature is cryptographically invalid (as opposed to
// malformed input, which raises plain ValueError). Mirrors the crates'
// Error::InvalidSignature variant.
create_exception!(
    pqcrypto,
    InvalidSignatureError,
    pyo3::exceptions::PyValueError
);

#[macro_export]
macro_rules! register_classes {
    ($m:expr, $($cls:ty),+ $(,)?) => {
        $( $m.add_class::<$cls>()?; )+
    };
}

#[pymodule]
fn pqcrypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add(
        "InvalidSignatureError",
        m.py().get_type::<InvalidSignatureError>(),
    )?;
    kem::register(m)?;
    sign::register(m)?;
    Ok(())
}
