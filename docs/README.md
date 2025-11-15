# How pyinjector-rs Works?

## Overview

pyinjector-rs is a Windows process injector written in Rust that injects and executes Python code in running processes that already have a Python runtime loaded.

It does not install a new Python environment on the target process (it does not inject pythonX.dll). It uses the existing environment. Therefore, pythonX.dll must be present in the target process for it to work.

## Execution Flow

The injection process follows these steps:

1. Open Target Process
2. Detect Process Architecture (32-bit or 64-bit)
3. Enumerate Loaded Modules & Find Python DLL
4. Parse Python DLL's PE Export Table
5. Resolve Python API Functions (PyGILState_Ensure etc.)
6. Allocate Memory for Python Code
7. Generate Architecture-Specific Shellcode
8. Allocate Memory for Shellcode (RWX)
9. Execute Shellcode via CreateRemoteThread method
10. Shellcode Executes Python Code

## Python API Resolution

### Used Python Functions

pyinjector-rs needs three Python C API functions to safely execute code:

1. ``PyGILState_Ensure``: Acquire the Global Interpreter Lock (GIL)
2. ``PyRun_SimpleString``: Execute Python code from a string
3. ``PyGILState_Release``: Release the GIL

### Resolution Process

1. Read Python DLL from disk (using module path)
2. Parse PE headers and locate Export Directory
3. Find function names in export table
4. Get RVA (Relative Virtual Address) for each function
5. Calculate actual address: DLL_Base_Address + RVA


### Why Parse from Disk?

The tool parses the PE file from disk rather than reading from process memory because It does not inject any DLL into the target application. Therefore, it can't use the GetProcAddress function.

## Shellcode Generation

The shellcode is dynamically generated based on the target architecture and resolved API addresses.

### x64 Shellcode Structure

```assembly
; Prologue
push rbp
mov rbp, rsp
push rbx
sub rsp, 0x28  ; (shadow space)

; Acquire GIL
mov rax, [PyGILState_Ensure_Address]
call rax
mov rbx, rax  ; Save GIL state

; Execute with PyRun_SimpleString
mov rcx, [Python_Code_Address]  ; First parameter (x64 fastcall)
mov rax, [PyRun_SimpleString_Address]
call rax

; Release GIL
mov rcx, rbx  ; GIL state as parameter
mov rax, [PyGILState_Release_Address]
call rax

; Epilogue
add rsp, 0x28
pop rbx
pop rbp
ret
```

### x86 Shellcode Structure

```assembly
; Prologue
push ebp
mov ebp, esp
and esp, 0xFFFFFFF0  ; 16-byte stack alignment
sub esp, 0x10
push ebx

; Acquire GIL
mov eax, [PyGILState_Ensure_Address]
call eax
mov ebx, eax  ; Save GIL state

; Execute
push [Python_Code_Address]
mov eax, [PyRun_SimpleString_Address]
call eax
add esp, 4  ; Stack claenup

; Release GIL
push ebx  ; Push GIL state
mov eax, [PyGILState_Release_Address]
call eax
add esp, 4

; Epilogue
pop ebx
mov esp, ebp
pop ebp
ret 4  ; because of __stdcall
```

## Python's GIL (Global Interpreter Lock) Management

Python's GIL must be acquired before executing Python code in a multi-threaded environment. Since we're creating a new thread in the target process

### Execution Sequence

1. Thread Created
2. PyGILState_Ensure() → Acquires GIL + initializes thread state
3. PyRun_SimpleString() → Executes Python code (GIL held)
4. PyGILState_Release() → Releases GIL + cleanup
5. Thread Exits