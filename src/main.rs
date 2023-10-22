extern crate nix;
extern crate syscalls;
extern crate clap;
extern crate serde_yaml;

use std::collections::HashMap;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork};
use nix::unistd::{ForkResult};
use std::ffi::{CStr, CString};
use std::fmt::Debug;
use std::path::PathBuf;
use std::fs;
use syscalls::Sysno;
use clap::{Parser};
use libc::{pid_t, ptrace};
use serde::{Serialize, Deserialize};

#[derive(Parser)]
#[command(author, version, about, long_about)]
struct Args {
    #[arg(short, long, value_name = "PROFILE", help = "Path to the profile to use")]
    profile: Option<PathBuf>,

    #[arg(name = "COMMAND", required = true)]
    command: Vec<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Profile {
    allowed_ips: Vec<String>,
}


fn main() {
    let args = Args::parse();
    // println!("args: {:?}", args.command);
    //load the profile
    let profile = match args.profile {
        Some(path) => {
            let contents = fs::read_to_string(path).expect("Failed to read YAML file");
            serde_yaml::from_str(&contents).expect("Failed to parse YAML file")
        }
        None => Profile {
            allowed_ips: vec!["127.0.0.1".to_string()],
        },
    };

    match unsafe { fork() }.expect("Failed to fork") {
        ForkResult::Child => {
            ptrace::traceme().expect("Failed to set ptrace on child");
            std::thread::sleep(std::time::Duration::from_millis(100)); // Allow time for parent to start tracing
            let c_args: Vec<CString> = args.command
                .iter()
                .map(|arg| CString::new(arg.as_str()).unwrap())
                .collect();
            let c_args_ref: Vec<&CStr> = c_args.iter().map(AsRef::as_ref).collect();
            let command = CString::new(args.command[0].as_str()).unwrap();
            execvp(command.as_c_str(), &c_args_ref).unwrap_or_else(|_| {
                eprintln!("Failed to execute {}", args.command[0]);
                std::process::exit(1);
            });
        }
        ForkResult::Parent { child } => {
            std::thread::sleep(std::time::Duration::from_millis(100));

            trace_child(child, profile);
        }
    }
}

fn trace_child(child: nix::unistd::Pid, profile: Profile) {
    let mut children: HashMap<pid_t, bool> = HashMap::new();
    children.insert(child.as_raw(), false);
    std::thread::sleep(std::time::Duration::from_millis(100));
    waitpid(nix::unistd::Pid::from_raw(-1), None).expect("Failed to waitpid");
    ptrace::setoptions(
        child,
        ptrace::Options::PTRACE_O_TRACEFORK |
            ptrace::Options::PTRACE_O_TRACEVFORK |
            ptrace::Options::PTRACE_O_TRACECLONE |
            ptrace::Options::PTRACE_O_EXITKILL
            | ptrace::Options::PTRACE_O_TRACESYSGOOD,
    ).expect("setoptions failed.");
    ptrace::syscall(child, None).expect("Failed to ptrace::syscall");
    loop {
        let status = waitpid(nix::unistd::Pid::from_raw(-1), None).expect("Failed to waitpid");
        //


        if let WaitStatus::Stopped(pid, sig) = status {
            // not in the child map means it is a new child
            if !children.contains_key(&pid.as_raw()) {
                children.insert(pid.as_raw(), false);
                ptrace::setoptions(
                    pid,
                    ptrace::Options::PTRACE_O_TRACEFORK |
                        ptrace::Options::PTRACE_O_TRACEVFORK |
                        ptrace::Options::PTRACE_O_TRACECLONE
                        |ptrace::Options::PTRACE_O_TRACESYSGOOD,
                ).expect("setoptions failed.");
                ptrace::syscall(pid, None).expect("Failed to ptrace::syscall");
                continue;
            }
        }
        // if let nix::sys::wait::WaitStatus::Stopped(pid, Signal::SIGTRAP) = status {
        // if let nix::sys::wait::WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, _) = status {
        if let WaitStatus::PtraceSyscall(pid) = status {
            if children.contains_key(&pid.as_raw()) && *children.get(&pid.as_raw()).unwrap() {
                children.insert(pid.as_raw(), false);
            } else {
                children.insert(pid.as_raw(), true);
                let regs = ptrace::getregs(pid).expect("Failed to getregs");
                if regs.orig_rax == Sysno::connect as u64 {
                    // Additional logic to check the arguments when the child makes the `connect` syscall
                    let sockaddr_ptr = regs.rsi;

                    // Depending on the specific sockaddr structure you're dealing with (e.g., sockaddr_in or sockaddr_in6),
                    // you might need to adjust the amount of data you read. For this example, I'll assume sockaddr_in:
                    let mut sockaddr_data: [u8; std::mem::size_of::<libc::sockaddr_in>()] =
                        [0; std::mem::size_of::<libc::sockaddr_in>()];
                    for i in 0..(sockaddr_data.len() / std::mem::size_of::<u64>()) {
                        let data =
                            ptrace::read(
                                pid,
                                (sockaddr_ptr as usize + i * std::mem::size_of::<u64>()) as *mut _,
                            ).expect("Failed to read data");
                        sockaddr_data
                            [i * std::mem::size_of::<u64>()..(i + 1) * std::mem::size_of::<u64>()]
                            .copy_from_slice(&data.to_ne_bytes());
                    }
                    // print the address and port
                    let sockaddr_in =
                        unsafe { std::mem::transmute::<_, libc::sockaddr_in>(sockaddr_data) };
                    let addr = unsafe { std::mem::transmute::<_, [u8; 4]>(sockaddr_in.sin_addr) };
                    let port = sockaddr_in.sin_port.to_be();
                    // block if the address is not localhost
                    let addr_str = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
                    if !profile.allowed_ips.contains(&addr_str) {
                        println!("block connect to {:?}:{}", addr, port);
                        let mut regs = ptrace::getregs(pid).expect("Failed to getregs");
                        regs.rax = -1i64 as u64;
                        ptrace::setregs(pid, regs).expect("Failed to setregs");
                    }
                }
            }

            ptrace::syscall(pid, None).expect("Failed to ptrace::syscall");
            // ptrace::cont(pid, None).expect("Failed to ptrace::cont");
        } else {
            println!("status: {:?}", status);
            if let nix::sys::wait::WaitStatus::Exited(pid, _) = status {
                if pid == child {
                    break;
                }
            }
            if let WaitStatus::PtraceEvent(pid, _, _) = status {
                ptrace::syscall(pid, None).expect("Failed to ptrace::cont");
                continue;
            }
            if let WaitStatus::Stopped(pid, Signal::SIGTRAP) = status {
                ptrace::syscall(pid, None).expect("Failed to ptrace::syscall");
                continue;
            }
            if let WaitStatus::Stopped(pid, sig) = status {
                ptrace::syscall(pid, sig).expect("Failed to ptrace::syscall");
                continue;
            }

            // if let nix::sys::wait::WaitStatus::Signaled(pid, _, _) = status  {
            //     // if pid == child{
            //     //     break;
            //     // }
            //     break;
            // }
            // if let nix::sys::wait::WaitStatus::PtraceEvent(pid, _, _) = status  {
            //     ptrace::cont(pid, None).expect("Failed to ptrace::cont");
            // }
            match ptrace::syscall(status.pid().unwrap(), None) {
                Ok(_) => {}
                Err(_) => {
                    // println!("waitpid");
                    // let status = waitpid(nix::unistd::Pid::from_raw(-1), None).expect("Failed to waitpid");
                    // println!("status: {:?}", status);
                    // ptrace::cont(status.pid().unwrap(), None).expect("Failed to ptrace::cont");
                }
            }
        }
    }
}
