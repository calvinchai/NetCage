use crate::profile::Profile;
use libc::{AF_INET, AF_INET6};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::SystemTime;
use syscalls::Sysno;

pub fn trace_child(child: Pid, profile: Profile) {
    let mut children_birth = HashMap::new();

    loop {
        let status = waitpid(Pid::from_raw(-1), None).expect("Failed to waitpid");

        #[cfg(debug_assertions)]
        {
            // print the status if it is not sigtrap
            match status {
                WaitStatus::PtraceSyscall(_) => {},
                _ => println!("status: {:?}", status),
            }
        }

        let is_new_child = !children_birth.contains_key(&status.pid().unwrap().as_raw());
        if is_new_child {
            children_birth.insert(status.pid().unwrap().as_raw(), SystemTime::now());
            set_trace_options(status.pid().unwrap()).expect("setoptions failed.");
            ptrace::syscall(status.pid().unwrap(), None).expect("Failed to ptrace::syscall");
            continue;
        }
        match status {
            WaitStatus::PtraceSyscall(pid) => {
                inspect_syscall(&profile, pid);
                ptrace::syscall(pid, None).expect("Failed to ptrace::syscall");
            }
            WaitStatus::Stopped(pid, sig) => {
                if sig == Signal::SIGTRAP {
                    // within 1 second, we ignore SIGTRAP
                    let recent_new_process = SystemTime::now()
                        .duration_since(children_birth.get(&pid.as_raw()).unwrap().clone())
                        .unwrap()
                        .as_secs()
                        < 1;
                    if recent_new_process {
                        ptrace::syscall(pid, None).expect("Failed to ptrace::syscall");
                        continue;
                    }
                }
                // A child is stopped by a signal that is not related to tracing, pass the signal to the child
                ptrace::syscall(pid, sig).expect("Failed to ptrace::syscall");
            }
            // A child exits
            WaitStatus::Exited(pid, _) | WaitStatus::Signaled(pid, _, _) => {
                children_birth.remove(&pid.as_raw());
                if pid == child {
                    break;
                }
            }
            // A forked or cloned child is created
            WaitStatus::PtraceEvent(pid, _, _) => {
                ptrace::syscall(pid, None).expect("Failed to ptrace::syscall");
                continue;
            }
            _ => {
                ptrace::syscall(status.pid().unwrap(), None).expect("Failed to ptrace::syscall");
            }
        }
    }
}

fn inspect_syscall(profile: &Profile, pid: Pid) {
    let regs = ptrace::getregs(pid).expect("Failed to getregs");
    if regs.orig_rax == Sysno::connect as u64 {
        let sockaddr_ptr = regs.rsi;
        #[cfg(debug_assertions)]
        println!("sockaddr_ptr: {:?}", sockaddr_ptr);
        // Read the sa_family field to determine if it's IPv4 or IPv6
        let sa_family: u16 =
            ptrace::read(pid, sockaddr_ptr as *mut _).expect("Failed to read sa_family") as u16;
        #[cfg(debug_assertions)]
        println!("sa_family: {:?}", sa_family);
        match sa_family as i32 {
            AF_INET => {
                let mut sockaddr_data: [u8; std::mem::size_of::<libc::sockaddr_in>()] =
                    [0; std::mem::size_of::<libc::sockaddr_in>()];
                read_memory(pid, sockaddr_ptr, &mut sockaddr_data);

                let sockaddr_in =
                    unsafe { std::mem::transmute::<_, libc::sockaddr_in>(sockaddr_data) };
                let addr = unsafe { std::mem::transmute::<_, [u8; 4]>(sockaddr_in.sin_addr) };
                let port = sockaddr_in.sin_port.to_be();
                let addr_str = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);

                if !profile.allowed_ips.contains(&addr_str) {
                    #[cfg(debug_assertions)]
                    println!("block connect to {:?}:{}", addr_str, port);
                    block_connection(pid);
                }
            }
            AF_INET6 => {
                let mut sockaddr_data: [u8; std::mem::size_of::<libc::sockaddr_in6>()] =
                    [0; std::mem::size_of::<libc::sockaddr_in6>()];
                read_memory(pid, sockaddr_ptr, &mut sockaddr_data);

                let sockaddr_in6 =
                    unsafe { std::mem::transmute::<_, libc::sockaddr_in6>(sockaddr_data) };

                // Using Rust's standard library to handle the IPv6 representation
                let addr: Ipv6Addr = Ipv6Addr::from(sockaddr_in6.sin6_addr.s6_addr);
                let port = sockaddr_in6.sin6_port.to_be();

                if !profile.allowed_ips.contains(&addr.to_string()) {
                    #[cfg(debug_assertions)]
                    println!("block connect to {:?}:{}", addr, port);
                    block_connection(pid);
                }
            }
            _ => {
                // Handle other address families or ignore
            }
        }
    }
}
fn read_memory(pid: Pid, sockaddr_ptr: u64, sockaddr_data: &mut [u8]) {
    for i in 0..(sockaddr_data.len() / std::mem::size_of::<u64>()) {
        let data = ptrace::read(
            pid,
            (sockaddr_ptr as usize + i * std::mem::size_of::<u64>()) as *mut _,
        )
        .expect("Failed to read data");
        sockaddr_data[i * std::mem::size_of::<u64>()..(i + 1) * std::mem::size_of::<u64>()]
            .copy_from_slice(&data.to_ne_bytes());
    }
}

// Helper function to block the connection
fn block_connection(pid: Pid) {
    // println!("block connect to {:?}:{}", addr, port);
    let mut regs = ptrace::getregs(pid).expect("Failed to getregs");
    regs.rax = -1i64 as u64;
    ptrace::setregs(pid, regs).expect("Failed to setregs");
}
fn set_trace_options(child: Pid) -> Result<(), nix::Error> {
    ptrace::setoptions(
        child,
        ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEVFORK
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_EXITKILL
            | ptrace::Options::PTRACE_O_TRACESYSGOOD,
    )
}
