use crate::profile::Profile;
use libc::pid_t;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use std::collections::HashMap;
use nix::unistd::Pid;
use syscalls::Sysno;

pub fn trace_child(child: Pid, profile: Profile) {
    let mut children: HashMap<pid_t, bool> = HashMap::new();
    loop {
        let status = waitpid(nix::unistd::Pid::from_raw(-1), None).expect("Failed to waitpid");

        match status {
            WaitStatus::Stopped(pid, Signal::SIGTRAP) => {
                let is_new_child = !children.contains_key(&pid.as_raw());

                if is_new_child {
                    children.insert(pid.as_raw(), false);
                    set_trace_options(pid).expect("setoptions failed.");
                    ptrace::syscall(pid, None).expect("Failed to ptrace::syscall");
                    continue;
                }
                let is_syscall_entry = !children.get(&pid.as_raw()).unwrap();
                if is_syscall_entry {
                    children.insert(pid.as_raw(), true);
                    inspect_syscall(&profile, pid);
                } else {
                    children.insert(pid.as_raw(), false);
                }

                ptrace::syscall(pid, None).expect("Failed to ptrace::syscall");
            },
            // A child exits
            WaitStatus::Exited(pid, _) | WaitStatus::Signaled(pid, _, _) => {
                children.remove(&pid.as_raw());
                if pid == child {
                    break;
                }
            },
            // A forked or cloned child is created
            WaitStatus::PtraceEvent(pid, _, _) => {
                ptrace::syscall(pid, None).expect("Failed to ptrace::syscall");
                continue;
            },
            // A child is stopped by a signal that is not related to tracing, pass the signal to the child
            WaitStatus::Stopped(pid, sig) => {
                ptrace::syscall(pid, sig).expect("Failed to ptrace::syscall");
                continue;
            },
            _ => {
                ptrace::syscall(status.pid().unwrap(), None).expect("Failed to ptrace::syscall");
            }
        }
    }
}

fn inspect_syscall(profile: &Profile, pid: Pid) {
    let regs = ptrace::getregs(pid).expect("Failed to getregs");
    if regs.orig_rax == Sysno::connect as u64 {
        // Additional logic to check the arguments when the child makes the `connect` syscall
        let sockaddr_ptr = regs.rsi;

        let mut sockaddr_data: [u8; std::mem::size_of::<libc::sockaddr_in>()] =
            [0; std::mem::size_of::<libc::sockaddr_in>()];
        for i in 0..(sockaddr_data.len() / std::mem::size_of::<u64>()) {
            let data = ptrace::read(
                pid,
                (sockaddr_ptr as usize + i * std::mem::size_of::<u64>()) as *mut _,
            )
                .expect("Failed to read data");
            sockaddr_data
                [i * std::mem::size_of::<u64>()..(i + 1) * std::mem::size_of::<u64>()]
                .copy_from_slice(&data.to_ne_bytes());
        }
        // print the address and port
        let sockaddr_in =
            unsafe { std::mem::transmute::<_, libc::sockaddr_in>(sockaddr_data) };
        let addr = unsafe { std::mem::transmute::<_, [u8; 4]>(sockaddr_in.sin_addr) };
        let port = sockaddr_in.sin_port.to_be();

        let addr_str = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
        if !profile.allowed_ips.contains(&addr_str) {
            println!("block connect to {:?}:{}", addr, port);
            let mut regs = ptrace::getregs(pid).expect("Failed to getregs");
            regs.rax = -1i64 as u64;
            ptrace::setregs(pid, regs).expect("Failed to setregs");
        }
    }
}

fn set_trace_options(child: Pid) -> Result<(), nix::Error> {
    ptrace::setoptions(
        child,
        ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEVFORK
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_EXITKILL, // | ptrace::Options::PTRACE_O_TRACESYSGOOD,
    )
}
