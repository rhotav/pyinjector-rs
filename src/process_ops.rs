use crate::error::{PyInjectorError, Result};
use std::mem;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, BOOL};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32First, Module32Next, MODULEENTRY32, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS, IsWow64Process};

pub struct ProcessHandle {
    handle: HANDLE,
}

impl ProcessHandle {
    pub fn open(pid: u32) -> Result<Self> {
        unsafe {
            let handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(PyInjectorError::ProcessNotFound(pid));
            }

            Ok(ProcessHandle { handle })
        }
    }

    pub fn as_raw(&self) -> HANDLE {
        self.handle
    }

    pub fn is_32bit(&self) -> Result<bool> {
        unsafe {
            let mut is_wow64: BOOL = 0;
            let result = IsWow64Process(self.handle, &mut is_wow64);
            
            if result == 0 {
                return Err(PyInjectorError::WindowsApi(
                    "Failed to determine process architecture".to_string(),
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32,
                ));
            }

            Ok(is_wow64 != 0)
        }
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base_address: usize,
    pub _size: u32,
}

pub fn enum_modules(pid: u32) -> Result<Vec<ModuleInfo>> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

        if snapshot == INVALID_HANDLE_VALUE {
            return Err(PyInjectorError::WindowsApi(
                "Failed to create module snapshot".to_string(),
                0,
            ));
        }

        let mut modules = Vec::new();
        let mut module_entry: MODULEENTRY32 = mem::zeroed();
        module_entry.dwSize = mem::size_of::<MODULEENTRY32>() as u32;

        if Module32First(snapshot, &mut module_entry) != 0 {
            loop {
                let null_pos = module_entry
                    .szModule
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(module_entry.szModule.len());
                let name_bytes: Vec<u8> = module_entry.szModule[..null_pos]
                    .iter()
                    .map(|&c| c as u8)
                    .collect();
                let name = String::from_utf8_lossy(&name_bytes).to_lowercase();

                let path_null_pos = module_entry
                    .szExePath
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(module_entry.szExePath.len());
                let path_bytes: Vec<u8> = module_entry.szExePath[..path_null_pos]
                    .iter()
                    .map(|&c| c as u8)
                    .collect();
                let path = String::from_utf8_lossy(&path_bytes).to_string();

                modules.push(ModuleInfo {
                    name,
                    path,
                    base_address: module_entry.modBaseAddr as usize,
                    _size: module_entry.modBaseSize,
                });

                if Module32Next(snapshot, &mut module_entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        Ok(modules)
    }
}
