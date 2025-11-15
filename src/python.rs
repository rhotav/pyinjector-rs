/// Python DLL detection and API resolution
use crate::error::{PyInjectorError, Result};
use crate::pe_parser::get_export_address;
use crate::process_ops::{enum_modules, ModuleInfo};


/// Supported Python versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonVersion {
    Python27,
    Python3(u8),
}

impl PythonVersion {
    pub fn dll_name(&self) -> String {
        match self {
            PythonVersion::Python27 => "python27.dll".to_string(),
            PythonVersion::Python3(minor) => format!("python3{}.dll", minor),
        }
    }
}

impl std::fmt::Display for PythonVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PythonVersion::Python27 => write!(f, "Python 2.7"),
            PythonVersion::Python3(minor) => write!(f, "Python 3.{}", minor),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PythonApi {
    pub version: PythonVersion,
    pub _module_base: usize,
    pub py_gil_state_ensure: usize,
    pub py_gil_state_release: usize,
    pub py_run_simple_string: usize,
}

pub fn detect_python_dll(pid: u32, force_version: Option<PythonVersion>) -> Result<ModuleInfo> {
    let modules = enum_modules(pid)?;

    if let Some(version) = force_version {
        let dll_name = version.dll_name();
        if let Some(module) = modules.iter().find(|m| m.name.contains(&dll_name)) {
            return Ok(module.clone());
        }
        return Err(PyInjectorError::PythonNotLoaded);
    }

    for minor in (6..=13).rev() {
        let dll_name = format!("python3{}.dll", minor);
        if let Some(module) = modules.iter().find(|m| m.name.contains(&dll_name)) {
            return Ok(module.clone());
        }
    }

    if let Some(module) = modules.iter().find(|m| m.name.contains("python27.dll")) {
        return Ok(module.clone());
    }

    Err(PyInjectorError::PythonNotLoaded)
}

pub fn version_from_dll_name(dll_name: &str) -> Option<PythonVersion> {
    let dll_lower = dll_name.to_lowercase();

    if dll_lower.contains("python27.dll") {
        return Some(PythonVersion::Python27);
    }

    for minor in 6..=13 {
        let pattern = format!("python3{}.dll", minor);
        if dll_lower.contains(&pattern) {
            return Some(PythonVersion::Python3(minor));
        }
    }

    None
}

pub fn resolve_python_api(module_info: &ModuleInfo) -> Result<PythonApi> {
    let version = version_from_dll_name(&module_info.name)
        .ok_or_else(|| PyInjectorError::InvalidPythonVersion(module_info.name.clone()))?;

    // Parse the PE file from disk to get export RVAs (relative virtual addresses)
    // Then calculate actual addresses in target process using: base_address + RVA
    let py_gil_state_ensure_rva = get_export_address(&module_info.path, "PyGILState_Ensure")?;
    let py_gil_state_release_rva = get_export_address(&module_info.path, "PyGILState_Release")?;
    let py_run_simple_string_rva = get_export_address(&module_info.path, "PyRun_SimpleString")?;

    let target_base = module_info.base_address;

    Ok(PythonApi {
        version,
        _module_base: target_base,
        // Calculate actual addresses in target process: base + RVA
        py_gil_state_ensure: target_base + py_gil_state_ensure_rva,
        py_gil_state_release: target_base + py_gil_state_release_rva,
        py_run_simple_string: target_base + py_run_simple_string_rva,
    })
}
