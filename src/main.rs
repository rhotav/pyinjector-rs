mod error;
mod injector;
mod pe_parser;
mod process_ops;
mod python;
mod shellcode;

use clap::Parser;
use error::Result;
use injector::InjectionConfig;
use python::PythonVersion;
use std::fs;
use std::process;

#[derive(Parser, Debug)]
#[command(name = "pyinjector")]
#[command(version = "0.1.0")]
#[command(about = "Inject Python code into processes with existing Python runtime")]
struct Args {
    #[arg(short, long)]
    pid: u32,
    #[arg(short, long, conflicts_with = "command")]
    script: Option<String>,
    #[arg(short, long, conflicts_with = "script")]
    command: Option<String>,
    #[arg(short = 'v', long, value_parser = parse_python_version)]
    python_version: Option<PythonVersion>,
}

fn parse_python_version(s: &str) -> std::result::Result<PythonVersion, String> {
    match s {
        "2" | "2.7" => Ok(PythonVersion::Python27),
        "3" => {
            Ok(PythonVersion::Python3(11))
        }
        version if version.starts_with("3.") => {
            let minor = version
                .strip_prefix("3.")
                .and_then(|v| v.parse::<u8>().ok())
                .ok_or_else(|| format!("Invalid Python 3.x version: {}", version))?;

            if (6..=13).contains(&minor) {
                Ok(PythonVersion::Python3(minor))
            } else {
                Err(format!(
                    "Unsupported Python 3.{} version (supported: 3.6-3.13)",
                    minor
                ))
            }
        }
        _ => Err(format!(
            "Invalid Python version: {} (use 2, 2.7, 3, or 3.x where x is 6-13)",
            s
        )),
    }
}

fn run_program() -> Result<()> {
    let banner = r#"              _                 _                           
             | |               | |                          
  _ __  _   _| | ___   __ _  __| | ___ _ __ ______ _ __ ___ 
 | '_ \| | | | |/ _ \ / _` |/ _` |/ _ \ '__|______| '__/ __|
 | |_) | |_| | | (_) | (_| | (_| |  __/ |         | |  \__ \
 | .__/ \__, |_|\___/ \__,_|\__,_|\___|_|         |_|  |___/
 | |     __/ |                                              
 |_|    |___/                                               "#; 
    println!("{}", banner);
    println!("Author: Utku (Rhotav) Corbaci <utku@rhotav.com>");
    println!("GitHub: https://github.com/rhotav/pyinjector-rs");

    let args = Args::parse();

    if args.script.is_none() && args.command.is_none() {
        eprintln!("\n[!] Error: Either --script or --command must be specified\n");
        eprintln!("Usage: pyinjector --pid <PID> [--script <SCRIPT> | --command <COMMAND>] [OPTIONS]\n");
        eprintln!("Options:");
        eprintln!("  -p, --pid <PID>                    Target process ID");
        eprintln!("  -s, --script <SCRIPT>              Python script file to inject");
        eprintln!("  -c, --command <COMMAND>            Python code to execute directly");
        eprintln!("  -v, --python-version <VERSION>     Python version (2, 2.7, 3, or 3.6-3.13)");
        eprintln!("  -h, --help                         Print help");
        eprintln!("  -V, --version                      Print version\n");
        eprintln!("Examples:");
        eprintln!("  pyinjector --pid 1234 --script script.py");
        eprintln!("  pyinjector --pid 1234 --command \"print('Hello from injected code!')\"");
        eprintln!("  pyinjector --pid 1234 --script script.py --python-version 3.11");
        process::exit(1);
    }

    let python_code = if let Some(script_path) = args.script {
        fs::read_to_string(&script_path).map_err(|e| {
            error::PyInjectorError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read script file '{}': {}", script_path, e),
            ))
        })?
    } else if let Some(cmd) = args.command {
        cmd
    } else {
        unreachable!()
    };

    if python_code.trim().is_empty() {
        eprintln!("[!] Python code is empty");
        process::exit(1);
    }

    let config = InjectionConfig {
        pid: args.pid,
        python_code,
        python_version: args.python_version,
    };

    config.execute()?;

    Ok(())
}

fn main() {
    if let Err(e) = run_program() {
        eprintln!("\n[!] Error: {}", e);
        process::exit(1);
    }
}