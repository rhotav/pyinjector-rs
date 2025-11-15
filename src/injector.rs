/// Main injection logic
use crate::error::{PyInjectorError, Result};
use crate::process_ops::ProcessHandle;
use crate::python::{detect_python_dll, resolve_python_api, PythonVersion};
use crate::shellcode::generate_shellcode;
use std::ffi::CString;
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;

struct RemoteMemory {
    process: HANDLE,
    address: *mut std::ffi::c_void,
    _size: usize,
}

impl RemoteMemory {
    fn allocate(process: HANDLE, size: usize, executable: bool) -> Result<Self> {
        let protection = if executable {
            PAGE_EXECUTE_READWRITE
        } else {
            PAGE_READWRITE
        };

        unsafe {
            let address = VirtualAllocEx(
                process,
                ptr::null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                protection,
            );

            if address.is_null() {
                return Err(PyInjectorError::MemoryAllocationFailed);
            }

            Ok(RemoteMemory {
                process,
                address,
                _size: size,
            })
        }
    }

    fn write(&self, data: &[u8]) -> Result<()> {
        unsafe {
            let mut bytes_written = 0;
            let success = WriteProcessMemory(
                self.process,
                self.address,
                data.as_ptr() as *const std::ffi::c_void,
                data.len(),
                &mut bytes_written,
            );

            if success == 0 || bytes_written != data.len() {
                return Err(PyInjectorError::MemoryWriteFailed);
            }

            Ok(())
        }
    }

    fn address(&self) -> usize {
        self.address as usize
    }
}

impl Drop for RemoteMemory {
    fn drop(&mut self) {
        unsafe {
            VirtualFreeEx(self.process, self.address, 0, MEM_RELEASE);
        }
    }
}

/// Execute shellcode using CreateRemoteThread
fn execute_with_remote_thread(process: HANDLE, shellcode_addr: usize) -> Result<()> {
    println!("[*] Executing shellcode with CreateRemoteThread...");
    
    unsafe {
        let thread_handle = CreateRemoteThread(
            process,
            ptr::null(),
            0,
            Some(std::mem::transmute(shellcode_addr)),
            ptr::null(),
            0,
            ptr::null_mut(),
        );

        if thread_handle.is_null() {
            return Err(PyInjectorError::ThreadCreationFailed);
        }

        println!("[+] Remote thread created successfully");
        println!("[*] Waiting for thread to complete...");

        WaitForSingleObject(thread_handle, INFINITE);

        println!("[+] Thread execution completed");
        CloseHandle(thread_handle);
    }

    Ok(())
}


pub fn inject_python_code(
    pid: u32,
    python_code: &str,
    force_version: Option<PythonVersion>,
) -> Result<()> {
    println!("[*] Opening process with PID: {}", pid);
    let process = ProcessHandle::open(pid)?;

    // Detect arch
    let is_32bit = process.is_32bit()?;
    println!("[*] Target process architecture: {}", if is_32bit { "32-bit" } else { "64-bit" });

    let python_module = detect_python_dll(pid, force_version)?;
    println!(
        "[+] Found Python DLL : {} at base address 0x{:X}",
        python_module.name, python_module.base_address
    );

    println!("[*] Resolving...");
    let python_api = resolve_python_api(&python_module)?;
    println!("[+] Python version detected: {}", python_api.version);
    println!(
        "    PyGILState_Ensure: 0x{:X}",
        python_api.py_gil_state_ensure
    );
    println!(
        "    PyGILState_Release: 0x{:X}",
        python_api.py_gil_state_release
    );
    println!(
        "    PyRun_SimpleString: 0x{:X}",
        python_api.py_run_simple_string
    );

    println!("[*] Allocating...");
    let code_cstring = CString::new(python_code).map_err(|_| {
        PyInjectorError::InvalidArgument("Python code contains null bytes".to_string())
    })?;
    let code_bytes = code_cstring.as_bytes_with_nul();
    let code_memory = RemoteMemory::allocate(process.as_raw(), code_bytes.len(), false)?;
    code_memory.write(code_bytes)?;
    println!("[+] written at: 0x{:X}", code_memory.address());

    let shellcode = generate_shellcode(&python_api, code_memory.address(), is_32bit);
    println!("[+] Shellcode size: {} bytes", shellcode.len());

    println!("[*] Allocating memory for shellcode...");
    let shellcode_memory = RemoteMemory::allocate(process.as_raw(), shellcode.len(), true)?;
    shellcode_memory.write(&shellcode)?;
    println!(
        "[+] Shellcode written at: 0x{:X}",
        shellcode_memory.address()
    );
    
    execute_with_remote_thread(process.as_raw(), shellcode_memory.address())?;

    println!("[+] Python code injection completed successfully");
    Ok(())
}

pub struct InjectionConfig {
    pub pid: u32,
    pub python_code: String,
    pub python_version: Option<PythonVersion>,
}

impl InjectionConfig {
    pub fn execute(&self) -> Result<()> {
        inject_python_code(self.pid, &self.python_code, self.python_version)
    }
}
