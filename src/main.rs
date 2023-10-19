extern crate nix;
extern crate syscalls;

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::waitpid;
use nix::unistd::{execvp, fork};
use nix::unistd::{ForkResult, Pid};
use std::ffi::{CStr, CString};
use syscalls::Sysno;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <command> [args...]", args[0]);
        return;
    }

    match unsafe { fork() }.expect("Failed to fork") {
        ForkResult::Child => {
            ptrace::traceme().expect("Failed to set ptrace on child");
            std::thread::sleep(std::time::Duration::from_millis(100)); // Allow time for parent to start tracing

            let command = CString::new(args[1].as_str()).unwrap();
            let c_args: Vec<CString> = args[1..]
                .iter()
                .map(|arg| CString::new(arg.as_str()).unwrap())
                .collect();
            let c_args_ref: Vec<&CStr> = c_args.iter().map(AsRef::as_ref).collect();

            let _ = execvp(&command, &c_args_ref);
        }
        ForkResult::Parent { child } => {
            trace_child(child);
        }
    }
}

fn trace_child(child: nix::unistd::Pid) {
    let mut in_syscall = false;
    loop {
        let status = waitpid(child, None).expect("Failed to waitpid");

        if let nix::sys::wait::WaitStatus::Stopped(_, Signal::SIGTRAP) = status {
            if in_syscall {
                in_syscall = false;
            } else {
                let regs = ptrace::getregs(child).expect("Failed to getregs");
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
                                child,
                                (sockaddr_ptr as usize + i * std::mem::size_of::<u64>()) as *mut _,
                            )
                                .expect("Failed to read data")
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
                    if addr != [127, 0, 0, 1] {
                        println!("block connect to {:?}:{}", addr, port);
                        let mut regs = ptrace::getregs(child).expect("Failed to getregs");
                        regs.rax = -1i64 as u64;
                        ptrace::setregs(child, regs).expect("Failed to setregs");
                    }
                }

                in_syscall = true;
            }

            ptrace::syscall(child, None).expect("Failed to ptrace::syscall");
        } else {
            if let nix::sys::wait::WaitStatus::Exited(_, _) = status {
                break;
            }
            ptrace::cont(child, None).expect("Failed to ptrace::cont");
        }
    }
}
