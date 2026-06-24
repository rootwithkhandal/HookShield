use pyo3::prelude::*;
use pyo3::exceptions::PyIOError;
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{Read, BufReader};

#[pyfunction]
fn sha256(file_path: &str) -> PyResult<Option<String>> {
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => return Err(PyIOError::new_err(format!("Failed to open file: {}", e))),
    };

    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];

    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(PyIOError::new_err(format!("Failed to read file: {}", e))),
        };
        hasher.update(&buffer[..count]);
    }

    let result = hasher.finalize();
    Ok(Some(format!("{:x}", result)))
}

#[pymodule]
fn fast_hasher(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sha256, m)?)?;
    Ok(())
}
