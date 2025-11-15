// Since we did not inject a DLL into the target process, I did not use GetProcAddress.

use crate::error::{PyInjectorError, Result};
use goblin::pe::PE;
use std::fs;

pub fn get_export_address(dll_path: &str, function_name: &str) -> Result<usize> {
    let data = fs::read(dll_path).map_err(|e| {
        PyInjectorError::WindowsApi(
            format!("Failed to read DLL file '{}': {}", dll_path, e),
            0,
        )
    })?;

    let pe = PE::parse(&data).map_err(|e| {
        PyInjectorError::WindowsApi(
            format!("Failed to parse PE file '{}': {}", dll_path, e),
            0,
        )
    })?;

    if pe.exports.is_empty() {
        return Err(PyInjectorError::WindowsApi(
            "No export table found".to_string(),
            0,
        ));
    }

    for export in pe.exports.iter() {
        if let Some(name) = export.name {
            if name == function_name {
                return Ok(export.rva as usize);
            }
        }
    }

    Err(PyInjectorError::PythonApiFunctionNotFound(
        function_name.to_string(),
    ))
}
