/// Shellcode generation for Python code execution
use crate::python::PythonApi;

pub fn generate_shellcode(api: &PythonApi, code_address: usize, is_32bit: bool) -> Vec<u8> {
    if is_32bit {
        generate_shellcode_x86(api, code_address)
    } else {
        generate_shellcode_x64(api, code_address)
    }
}

fn generate_shellcode_x86(api: &PythonApi, code_address: usize) -> Vec<u8> {
    let mut shellcode = Vec::new();

    // Prologue - setup proper stack frame with alignment
    shellcode.extend_from_slice(&[
        0x55,             // push ebp
        0x89, 0xE5,       // mov ebp, esp
        0x83, 0xE4, 0xF0, // and esp, 0xFFFFFFF0  ; 16-byte align stack
        0x83, 0xEC, 0x10, // sub esp, 0x10        ; allocate 16 bytes
        0x53,             // push ebx
    ]);

    // Call PyGILState_Ensure()
    shellcode.extend_from_slice(&[
        0xB8, // mov eax, imm32
    ]);
    shellcode.extend_from_slice(&(api.py_gil_state_ensure as u32).to_le_bytes());
    shellcode.extend_from_slice(&[
        0xFF, 0xD0, // call eax
    ]);

    // Save GIL state return
    shellcode.extend_from_slice(&[
        0x89, 0xC3, // mov ebx, eax
    ]);

    // PyRun_SimpleString(code_address)
    shellcode.extend_from_slice(&[
        0x68, // push imm32
    ]);
    shellcode.extend_from_slice(&(code_address as u32).to_le_bytes());  // little endian

    // PyRun_SimpleString(code_address)
    shellcode.extend_from_slice(&[
        0xB8, // mov eax, imm32
    ]);
    shellcode.extend_from_slice(&(api.py_run_simple_string as u32).to_le_bytes());
    shellcode.extend_from_slice(&[
        0xFF, 0xD0, // call eax
        0x83, 0xC4, 0x04, // add esp, 4
    ]);

    // Call PyGILState_Release(state)
    // Push GIL state
    shellcode.extend_from_slice(&[
        0x53, // push ebx
    ]);

    // Call function
    shellcode.extend_from_slice(&[
        0xB8, // mov eax, imm32
    ]);
    shellcode.extend_from_slice(&(api.py_gil_state_release as u32).to_le_bytes());
    shellcode.extend_from_slice(&[
        0xFF, 0xD0, // call eax
        0x83, 0xC4, 0x04, // add esp, 4 (clean up stack)
    ]);

    // Epilogue
    // Note: CreateRemoteThread expects WINAPI (__stdcall) calling convention on 32-bit
    // which means the callee must clean up the stack (lpParameter = 4 bytes)
    shellcode.extend_from_slice(&[
        0x5B,             // pop ebx
        0x89, 0xEC,       // mov esp, ebp  ; restore stack pointer
        0x5D,             // pop ebp
        0xC2, 0x04, 0x00, // ret 4 (clean up lpParameter from stack - stdcall convention)
    ]);

    shellcode
}

fn generate_shellcode_x64(api: &PythonApi, code_address: usize) -> Vec<u8> {
    let mut shellcode = Vec::new();


    // Prologue
    shellcode.extend_from_slice(&[
        0x55, // push rbp
        0x48, 0x89, 0xE5, // mov rbp, rsp
        0x53, // push rbx
        0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
    ]);

    // Call PyGILState_Ensure()
    shellcode.extend_from_slice(&[
        0x48, 0xB8, // movabs rax, imm64
    ]);
    shellcode.extend_from_slice(&api.py_gil_state_ensure.to_le_bytes());
    shellcode.extend_from_slice(&[
        0xFF, 0xD0, // call rax
    ]);

    // Save GIL state return
    shellcode.extend_from_slice(&[
        0x48, 0x89, 0xC3, // mov rbx, rax
    ]);

    // PyRun_SimpleString(code_address)
    shellcode.extend_from_slice(&[
        0x48, 0xB9, // movabs rcx, imm64
    ]);
    shellcode.extend_from_slice(&code_address.to_le_bytes());

    // PyRun_SimpleString(code_address)
    shellcode.extend_from_slice(&[
        0x48, 0xB8, // movabs rax, imm64
    ]);
    shellcode.extend_from_slice(&api.py_run_simple_string.to_le_bytes());
    shellcode.extend_from_slice(&[
        0xFF, 0xD0, // call rax
    ]);

    // Call PyGILState_Release(state)
    shellcode.extend_from_slice(&[
        0x48, 0x89, 0xD9, // mov rcx, rbx
    ]);

    // Call function
    shellcode.extend_from_slice(&[
        0x48, 0xB8, // movabs rax, imm64
    ]);
    shellcode.extend_from_slice(&api.py_gil_state_release.to_le_bytes());
    shellcode.extend_from_slice(&[
        0xFF, 0xD0, // call rax
    ]);

    // Epilogue
    shellcode.extend_from_slice(&[
        0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
        0x5B, // pop rbx
        0x5D, // pop rbp
        0xC3, // ret
    ]);

    shellcode
}
