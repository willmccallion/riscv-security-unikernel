//! Confining the daemon once its sockets and files are open.
//!
//! After setup the monitor only reads packets it is already capturing and
//! writes reports, so anything else is refused for good: Landlock removes
//! all filesystem access (and TCP binds and connects where the kernel
//! supports it), and a seccomp filter allows only the system calls that
//! work needs. Even code running inside a compromised process cannot open
//! files, start programs, make sockets, write to the capture socket (which
//! would transmit forged frames) or create executable memory.

#![allow(unsafe_code)]

use anyhow::{Context, Result, bail};
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};

/// Rejected system calls fail with "operation not permitted".
const DENY: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
/// A filter built for another architecture's system call numbers must
/// not run at all.
const KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;

/// `AUDIT_ARCH_*`: the ELF machine (`EM_X86_64` = 62, `EM_AARCH64` =
/// 183) marked 64-bit and little-endian.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0x3E | 0x8000_0000 | 0x4000_0000;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xB7 | 0x8000_0000 | 0x4000_0000;

/// Offsets into the kernel's `struct seccomp_data`.
const NR_OFFSET: u32 = 0;
const ARCH_OFFSET: u32 = 4;
const ARGS_OFFSET: u32 = 16;

const STDOUT: u32 = 1;
const STDERR: u32 = 2;
const PROT_EXEC: u32 = libc::PROT_EXEC as u32;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;
const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// What [`confine`] put in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Confinement {
    /// The Landlock ABI version the kernel offered.
    pub landlock_abi: u32,
}

/// Which descriptors a confined process may write to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAccess {
    /// Only stdout and stderr.
    StdioOnly,
    /// Stdout, stderr, and every descriptor numbered `fds_from` or above,
    /// where viewers' connections are; accepting connections is allowed
    /// too. Everything below must be safe to leave unwritable, in
    /// particular every capture socket, where a write would transmit.
    StdioAndViewers {
        /// The lowest descriptor number writes are allowed to.
        fds_from: u32,
    },
}

/// Confines this process for the rest of its life.
///
/// Call once setup is done and before reading any untrusted input. The
/// restrictions apply to the calling thread and anything it later starts,
/// so call it before starting threads.
pub fn confine(writes: WriteAccess) -> Result<Confinement> {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        bail!("prctl(PR_SET_NO_NEW_PRIVS): {}", io::Error::last_os_error());
    }
    let landlock_abi = landlock_abi()?;
    restrict_with_landlock(landlock_abi)?;
    install_seccomp_filter(&seccomp_filter(writes))?;
    Ok(Confinement { landlock_abi })
}

fn landlock_abi() -> Result<u32> {
    // SAFETY: a version query passes a null attribute and size zero.
    let version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if version < 1 {
        bail!(
            "this kernel does not offer Landlock ({}); rerun with --no-sandbox to run unconfined",
            io::Error::last_os_error()
        );
    }
    u32::try_from(version).context("Landlock ABI version out of range")
}

/// Handles every filesystem right the kernel knows, with no rule granting
/// any, so all filesystem access is refused; likewise TCP and, where
/// supported, abstract Unix sockets and signals to other processes.
fn restrict_with_landlock(abi: u32) -> Result<()> {
    let filesystem_rights_known: u32 = match abi {
        1 => 13,
        2 => 14,
        3 | 4 => 15,
        _ => 16,
    };
    let attr = RulesetAttr {
        handled_access_fs: (1u64 << filesystem_rights_known) - 1,
        handled_access_net: if abi >= 4 { LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP } else { 0 },
        scoped: if abi >= 6 { LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL } else { 0 },
    };
    let attr_size: usize = match abi {
        1..=3 => 8,
        4 | 5 => 16,
        _ => 24,
    };
    // SAFETY: attr is a live landlock_ruleset_attr of at least attr_size
    // bytes, the size the kernel's ABI version reads.
    let fd = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &raw const attr, attr_size, 0u32) };
    if fd < 0 {
        bail!("landlock_create_ruleset: {}", io::Error::last_os_error());
    }
    let fd = libc::c_int::try_from(fd).context("ruleset descriptor out of range")?;
    // SAFETY: fd is a fresh descriptor that nothing else owns.
    let ruleset = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: restrict_self takes the ruleset descriptor and zero flags.
    let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd, 0u32) };
    drop(ruleset);
    if rc != 0 {
        bail!("landlock_restrict_self: {}", io::Error::last_os_error());
    }
    Ok(())
}

fn install_seccomp_filter(filter: &[libc::sock_filter]) -> Result<()> {
    let program = libc::sock_fprog {
        len: u16::try_from(filter.len()).context("seccomp filter too long")?,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: program points at `filter`, which outlives the call; the
    // kernel copies it before returning.
    let rc = unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0u32, &raw const program) };
    if rc != 0 {
        bail!("seccomp: {}", io::Error::last_os_error());
    }
    Ok(())
}

/// System calls allowed with any arguments: reading already-open
/// descriptors, waiting on them, memory management, time, randomness for
/// hash tables, and what a panic needs to report and abort.
fn unrestricted_syscalls() -> Vec<libc::c_long> {
    let mut calls = vec![
        libc::SYS_read,
        libc::SYS_close,
        libc::SYS_ppoll,
        libc::SYS_getsockopt,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_getrandom,
        libc::SYS_sched_yield,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_gettid,
        libc::SYS_getpid,
        libc::SYS_tgkill,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    #[cfg(target_arch = "x86_64")]
    calls.push(libc::SYS_poll);
    calls
}

/// The seccomp program: refuse other architectures outright, allow the
/// unrestricted calls, allow `write` and `writev` only where `writes`
/// says, allow `mmap` only without `PROT_EXEC`, refuse everything else.
fn seccomp_filter(writes: WriteAccess) -> Vec<libc::sock_filter> {
    let mut filter = vec![
        load(ARCH_OFFSET),
        jump_if_equal(AUDIT_ARCH, 1, 0),
        ret(KILL),
        load(NR_OFFSET),
    ];
    for call in unrestricted_syscalls() {
        filter.extend(allow(call));
    }
    for call in [libc::SYS_write, libc::SYS_writev] {
        match writes {
            WriteAccess::StdioOnly => filter.extend(allow_if_argument_in(call, 0, &[STDOUT, STDERR])),
            WriteAccess::StdioAndViewers { fds_from } => filter.extend(allow_stdio_or_from(call, fds_from)),
        }
    }
    if let WriteAccess::StdioAndViewers { .. } = writes {
        filter.extend(allow(libc::SYS_accept4));
    }
    filter.extend(allow_unless_argument_has(libc::SYS_mmap, 2, PROT_EXEC));
    filter.push(ret(DENY));
    filter
}

const fn syscall_number(call: libc::c_long) -> u32 {
    call as u32
}

const fn load(offset: u32) -> libc::sock_filter {
    statement((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, offset)
}

const fn ret(action: u32) -> libc::sock_filter {
    statement((libc::BPF_RET | libc::BPF_K) as u16, action)
}

const fn statement(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k }
}

const fn jump_if_equal(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    }
}

const fn jump_if_at_least(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    }
}

const fn jump_if_any_bit(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    }
}

/// Offset of the low 32 bits of argument `index`; both supported
/// architectures are little-endian.
const fn argument_offset(index: u32) -> u32 {
    ARGS_OFFSET + 8 * index
}

const fn allow(call: libc::c_long) -> [libc::sock_filter; 2] {
    [jump_if_equal(syscall_number(call), 0, 1), ret(ALLOW)]
}

/// Allows `call` when argument `index` is one of `values`, refusing it
/// otherwise.
fn allow_if_argument_in(call: libc::c_long, index: u32, values: &[u32]) -> Vec<libc::sock_filter> {
    let count = u8::try_from(values.len()).unwrap_or(u8::MAX);
    let mut block = vec![jump_if_equal(syscall_number(call), 0, count + 3), load(argument_offset(index))];
    for (i, &value) in (0u8..).zip(values) {
        block.push(jump_if_equal(value, count - i, 0));
    }
    block.push(ret(DENY));
    block.push(ret(ALLOW));
    block
}

/// Allows `call` when its first argument, a descriptor, is stdout,
/// stderr, or numbered `fds_from` or above; refuses it otherwise.
const fn allow_stdio_or_from(call: libc::c_long, fds_from: u32) -> [libc::sock_filter; 7] {
    [
        jump_if_equal(syscall_number(call), 0, 6),
        load(argument_offset(0)),
        jump_if_equal(STDOUT, 3, 0),
        jump_if_equal(STDERR, 2, 0),
        jump_if_at_least(fds_from, 1, 0),
        ret(DENY),
        ret(ALLOW),
    ]
}

/// Allows `call` unless argument `index` has any of `bits` set.
const fn allow_unless_argument_has(call: libc::c_long, index: u32, bits: u32) -> [libc::sock_filter; 5] {
    [
        jump_if_equal(syscall_number(call), 0, 4),
        load(argument_offset(index)),
        jump_if_any_bit(bits, 1, 0),
        ret(ALLOW),
        ret(DENY),
    ]
}

/// Confines this process one layer at a time and tries what each layer
/// should prevent.
///
/// Landlock alone must refuse files and programs; with seccomp added,
/// sockets and executable memory must be refused too. Fails if anything
/// got through.
pub fn check() -> Result<()> {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        bail!("prctl(PR_SET_NO_NEW_PRIVS): {}", io::Error::last_os_error());
    }
    let abi = landlock_abi()?;
    restrict_with_landlock(abi)?;
    println!("sandbox-check: Landlock ABI v{abi} applied");
    let mut allowed = attempt(&[
        ("read /etc/passwd", std::fs::read("/etc/passwd").map(drop)),
        ("run a program", std::process::Command::new("true").status().map(drop)),
    ]);
    install_seccomp_filter(&seccomp_filter(WriteAccess::StdioOnly))?;
    println!("sandbox-check: seccomp filter added");
    allowed.extend(attempt(&[
        ("read /etc/passwd", std::fs::read("/etc/passwd").map(drop)),
        ("run a program", std::process::Command::new("true").status().map(drop)),
        ("open a network socket", open_socket()),
        ("create executable memory", map_executable_memory()),
    ]));
    if !allowed.is_empty() {
        bail!("the sandbox let through: {}", allowed.join(", "));
    }
    println!("sandbox-check: everything above was refused, as it should be");
    Ok(())
}

/// Reports each attempt's outcome; returns those that were allowed.
fn attempt(attempts: &[(&'static str, io::Result<()>)]) -> Vec<&'static str> {
    let mut allowed = Vec::new();
    for (what, outcome) in attempts {
        if let Err(e) = outcome {
            println!("  blocked: {what} ({e})");
        } else {
            println!("  ALLOWED: {what}");
            allowed.push(*what);
        }
    }
    allowed
}

fn open_socket() -> io::Result<()> {
    // SAFETY: socket(2) takes no pointers; a descriptor it returns is
    // owned and closed below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor that nothing else owns.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
    Ok(())
}

fn map_executable_memory() -> io::Result<()> {
    const LEN: usize = 4096;
    // SAFETY: an anonymous private mapping touches no existing memory; a
    // mapping it returns is unmapped below.
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            LEN,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if address == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: address is the mapping just made, of LEN bytes.
    let _ = unsafe { libc::munmap(address, LEN) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs a classic BPF program over a `seccomp_data` made of a system
    /// call number, architecture and arguments; supports exactly the
    /// instructions [`seccomp_filter`] emits.
    fn evaluate(filter: &[libc::sock_filter], nr: libc::c_long, arch: u32, args: [u64; 6]) -> u32 {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&syscall_number(nr).to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        for (i, arg) in args.iter().enumerate() {
            data[16 + 8 * i..24 + 8 * i].copy_from_slice(&arg.to_le_bytes());
        }
        let mut accumulator = 0u32;
        let mut pc = 0usize;
        loop {
            let instruction = filter[pc];
            let code = u32::from(instruction.code);
            pc += 1;
            if code == libc::BPF_LD | libc::BPF_W | libc::BPF_ABS {
                let at = instruction.k as usize;
                accumulator = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
            } else if code == libc::BPF_RET | libc::BPF_K {
                return instruction.k;
            } else {
                let taken = if code == libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K {
                    accumulator == instruction.k
                } else if code == libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K {
                    accumulator & instruction.k != 0
                } else if code == libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K {
                    accumulator >= instruction.k
                } else {
                    panic!("unexpected instruction {code:#x}");
                };
                pc += usize::from(if taken { instruction.jt } else { instruction.jf });
            }
        }
    }

    fn verdict(nr: libc::c_long, args: [u64; 6]) -> u32 {
        evaluate(&seccomp_filter(WriteAccess::StdioOnly), nr, AUDIT_ARCH, args)
    }

    fn verdict_serving(nr: libc::c_long, args: [u64; 6]) -> u32 {
        let writes = WriteAccess::StdioAndViewers { fds_from: 7 };
        evaluate(&seccomp_filter(writes), nr, AUDIT_ARCH, args)
    }

    #[test]
    fn reading_and_waiting_are_allowed() {
        assert_eq!(verdict(libc::SYS_read, [3, 0, 0, 0, 0, 0]), ALLOW);
        assert_eq!(verdict(libc::SYS_ppoll, [0; 6]), ALLOW);
        assert_eq!(verdict(libc::SYS_exit_group, [0; 6]), ALLOW);
    }

    #[test]
    fn writing_is_allowed_only_to_stdout_and_stderr() {
        assert_eq!(verdict(libc::SYS_write, [1, 0, 0, 0, 0, 0]), ALLOW);
        assert_eq!(verdict(libc::SYS_writev, [2, 0, 0, 0, 0, 0]), ALLOW);
        assert_eq!(verdict(libc::SYS_write, [3, 0, 0, 0, 0, 0]), DENY, "the capture socket");
        assert_eq!(verdict(libc::SYS_write, [0, 0, 0, 0, 0, 0]), DENY);
    }

    #[test]
    fn serving_viewers_allows_writes_only_above_the_capture_sockets() {
        assert_eq!(verdict_serving(libc::SYS_write, [1, 0, 0, 0, 0, 0]), ALLOW);
        assert_eq!(verdict_serving(libc::SYS_write, [7, 0, 0, 0, 0, 0]), ALLOW);
        assert_eq!(verdict_serving(libc::SYS_writev, [9, 0, 0, 0, 0, 0]), ALLOW);
        assert_eq!(verdict_serving(libc::SYS_write, [3, 0, 0, 0, 0, 0]), DENY, "a capture socket");
        assert_eq!(verdict_serving(libc::SYS_write, [6, 0, 0, 0, 0, 0]), DENY, "the highest capture socket");
        assert_eq!(verdict_serving(libc::SYS_accept4, [8, 0, 0, 0, 0, 0]), ALLOW);
        assert_eq!(verdict_serving(libc::SYS_sendto, [9, 0, 0, 0, 0, 0]), DENY);
    }

    #[test]
    fn only_a_serving_monitor_may_accept_connections() {
        assert_eq!(verdict(libc::SYS_accept4, [3, 0, 0, 0, 0, 0]), DENY);
    }

    #[test]
    fn executable_memory_is_refused() {
        let read_write = u64::from((libc::PROT_READ | libc::PROT_WRITE) as u32);
        let executable = u64::from((libc::PROT_READ | libc::PROT_EXEC) as u32);

        assert_eq!(verdict(libc::SYS_mmap, [0, 4096, read_write, 0, 0, 0]), ALLOW);
        assert_eq!(verdict(libc::SYS_mmap, [0, 4096, executable, 0, 0, 0]), DENY);
        assert_eq!(verdict(libc::SYS_mprotect, [0, 4096, executable, 0, 0, 0]), DENY);
    }

    #[test]
    fn files_programs_and_sockets_are_refused() {
        for call in [
            libc::SYS_openat,
            libc::SYS_execve,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_socket,
            libc::SYS_sendto,
            libc::SYS_setsockopt,
            libc::SYS_ptrace,
        ] {
            assert_eq!(verdict(call, [0; 6]), DENY, "system call {call}");
        }
    }

    #[test]
    fn another_architecture_is_killed() {
        assert_eq!(evaluate(&seccomp_filter(WriteAccess::StdioOnly), libc::SYS_read, AUDIT_ARCH ^ 1, [0; 6]), KILL);
    }

    #[test]
    fn every_jump_lands_inside_the_filter() {
        let filter = seccomp_filter(WriteAccess::StdioAndViewers { fds_from: 7 });
        let jumps = filter
            .iter()
            .enumerate()
            .filter(|(_, instruction)| u32::from(instruction.code) & 0x07 == libc::BPF_JMP);
        for (i, instruction) in jumps {
            let furthest = i + 1 + usize::from(instruction.jt.max(instruction.jf));
            assert!(furthest < filter.len(), "instruction {i} jumps past the end");
        }
        assert_eq!(filter.last().map(|last| last.k), Some(DENY), "the filter ends by refusing");
    }
}
