# pyinjector-rs

A Windows process injector written in Rust that can inject and execute Python scripts in running processes.

> [!NOTE]  
> This injector uses the pythonX.dll file that is already loaded on the process. It does not inject an additional Python DLL onto the process!

## Docs

For detailed technical explanation, see the [Technical Documentation](docs/README.md).

## Usage

Execute a Python command:

```bash
pyinjector.exe --pid <PID> --command "print('Hello from injected code!')"
```

Inject a Python script file:

```bash
pyinjector.exe --pid <PID> --script script.py
```

### Examples

#### Simple Message Box

```bash
pyinjector.exe --pid 1234 --command "import ctypes; ctypes.windll.user32.MessageBoxW(0, 'Injected!', 'PyInjector', 0)"
```

#### Execute Script File

Create `test.py`:
```python
import sys
import os
print(f"Python {sys.version} running in PID {os.getpid()}")
```

Inject it:
```bash
pyinjector.exe --pid 1234 --script test.py
```

## Building

### On Windows

```bash
cargo build --release
```

### Cross-compilation from Linux/macOS

Install the Windows target:

```bash
rustup target add x86_64-pc-windows-gnu
```

Build for Windows:

```bash
cargo build --release --target x86_64-pc-windows-gnu
```
