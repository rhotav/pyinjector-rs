
use std::fmt;

#[derive(Debug)]
pub enum PyInjectorError {
    WindowsApi(String, u32),
    ProcessNotFound(u32),
    PythonNotLoaded,
    PythonApiFunctionNotFound(String),
    MemoryAllocationFailed,
    MemoryWriteFailed,
    ThreadCreationFailed,
    InvalidPythonVersion(String),
    IoError(std::io::Error),
    InvalidArgument(String),
}

impl fmt::Display for PyInjectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PyInjectorError::WindowsApi(msg, code) => {
                write!(f, "Windows API error: {} (error code: {})", msg, code)
            }
            PyInjectorError::ProcessNotFound(pid) => {
                write!(f, "Process with PID {} not found or inaccessible", pid)
            }
            PyInjectorError::PythonNotLoaded => {
                write!(
                    f,
                    "Python DLL is not loaded in the target process. \
                     PyInjector only works with processes that already have Python initialized. \
                     Make sure the target process has loaded python27.dll or python3x.dll."
                )
            }
            PyInjectorError::PythonApiFunctionNotFound(func) => {
                write!(f, "Failed to find Python API function: {}", func)
            }
            PyInjectorError::MemoryAllocationFailed => {
                write!(f, "Failed to allocate memory in target process")
            }
            PyInjectorError::MemoryWriteFailed => {
                write!(f, "Failed to write to target process memory")
            }
            PyInjectorError::ThreadCreationFailed => {
                write!(f, "Failed to create remote thread in target process")
            }
            PyInjectorError::InvalidPythonVersion(ver) => {
                write!(f, "Invalid Python version: {}", ver)
            }
            PyInjectorError::IoError(err) => {
                write!(f, "I/O error: {}", err)
            }
            PyInjectorError::InvalidArgument(msg) => {
                write!(f, "Invalid argument: {}", msg)
            }
        }
    }
}

impl std::error::Error for PyInjectorError {}

impl From<std::io::Error> for PyInjectorError {
    fn from(err: std::io::Error) -> Self {
        PyInjectorError::IoError(err)
    }
}

pub type Result<T> = std::result::Result<T, PyInjectorError>;
