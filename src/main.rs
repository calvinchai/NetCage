mod profile;
mod trace;

extern crate clap;
extern crate nix;
extern crate serde_yaml;
extern crate syscalls;

use clap::Parser;
use nix::sys::ptrace;
use nix::unistd::ForkResult;
use nix::unistd::{execvp, fork};
use std::ffi::{CStr, CString};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about)]
struct Args {
    #[arg(
        short,
        long,
        value_name = "PROFILE",
        help = "Path to the profile to use"
    )]
    profile: Option<PathBuf>,

    #[arg(name = "COMMAND", required = true)]
    command: Vec<String>,
}

fn main() {
    let args = Args::parse();
    let profile = profile::Profile::load_from_path(args.profile);

    match unsafe { fork() }.expect("Failed to fork") {
        ForkResult::Child => {
            ptrace::traceme().expect("Failed to set ptrace on child");
            std::thread::sleep(std::time::Duration::from_millis(100));

            let c_args: Vec<CString> = args
                .command
                .iter()
                .map(|arg| CString::new(arg.as_str()).expect("Failed to convert to CString"))
                .collect();

            let c_args_ref: Vec<&CStr> = c_args.iter().map(AsRef::as_ref).collect();

            execvp(c_args[0].as_c_str(), &c_args_ref).unwrap_or_else(|_| {
                eprintln!("Failed to execute {}", args.command[0]);
                std::process::exit(1);
            });
        }
        ForkResult::Parent { child } => {
            std::thread::sleep(std::time::Duration::from_millis(100));
            trace::trace_child(child, profile);
        }
    }
}
