//! Implements partially the `strace` tool's functionality.
#![warn(missing_docs)]
#[macro_use]
extern crate num_derive;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;

use std::io::Error;
use std::ptr;
use std::{collections::HashMap, ffi::CString};

use anyhow::{anyhow, bail, Result};
use libc::{self};
use nix::{
    sys::{signal::Signal, wait::WaitStatus},
    unistd::Pid,
};
use tracing::{debug, trace, warn};

use crate::{
    cuda_sniff::sniff_ioctl,
    info::{FmtSpec, SYSCALL_MAP},
};
#[allow(dead_code, non_upper_case_globals)]
#[cfg(feature = "cuda_sniff")]
mod cuda_sniff;
pub mod info;
pub mod ptrace;

/// Timestamp options for tracing.
/// Copies the -t{tt} flags from strace.
#[derive(Debug, Clone, Copy, Default)]
pub enum TimestampOption {
    /// No timestamps.
    #[default]
    None,
    /// Absolute timestamps.
    Absolute,
    /// Absolute timestamp with usecs
    AbsoluteUsecs,
    /// Absolute UNIX epoch time and usecs
    AbsoluteUNIXUsecs,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Default)]
pub enum SummaryOption {
    #[default]
    None,
    SummaryOnly,
    SummaryJSON,
}

/// Options for statistics.
#[allow(missing_docs)]
#[derive(Debug, Clone, Default)]
pub struct StatisticsOptions {
    /// Count time, calls, and errors for each syscall and report summary
    pub summary: SummaryOption,
}

/// Options for tracing.
#[allow(missing_docs)]
#[derive(Debug, Clone, Default)]
pub struct TraceOptions {
    pub t: TimestampOption,
    pub stats: StatisticsOptions,
}

/// Struct to hold statistics for a single syscall.
#[derive(Debug, Default, Clone)]
pub struct SyscallStat {
    /// The number of times the syscall was called.
    pub calls: u64,
    /// The total time spent in the syscall.
    pub latency: std::time::Duration,
    /// The number of errors encountered during the syscall.
    pub errors: u64,
}

unsafe fn do_child<T>(args: T) -> Result<()>
where
    T: IntoIterator<Item = String>,
{
    let cstrings: Vec<CString> = args
        .into_iter()
        .map(|arg| CString::new(arg.as_str()).expect("CString::new failed"))
        .collect();

    let child_prog = cstrings.get(0).unwrap().clone();
    debug!(?child_prog, "starting child");

    let child_prog = child_prog.into_raw();
    let mut c_pointers: Vec<*const libc::c_char> =
        cstrings.iter().map(|cstr| cstr.as_ptr()).collect();
    // Ensure null termination for C-style argv array
    c_pointers.push(ptr::null());

    let argv: *const *const libc::c_char = c_pointers.as_ptr();

    // If a child knows that it wants to be traced, it can make the PTRACE_TRACEME
    // ptrace request, which starts tracing. In addition, it means that the next
    // signal sent to this process will stop it and notify the parent (via
    // wait), so that the parent knows to start tracing.
    ptrace::traceme().map_err(|errno| anyhow!("failed TRACEME. errno {}", errno))?;
    // After doing a TRACEME, we SIGSTOP ourselves so that the parent can continue
    // this child's execution. This assures that the tracer does not miss the
    // early syscalls made by the child.
    let result = libc::raise(libc::SIGSTOP);
    if result != 0 {
        bail!(
            "child failed to SIGSTOP itself. errno {}",
            Error::last_os_error()
        );
    }

    libc::execvp(child_prog, argv);

    // If execution continued to here there was an error.
    let errno: i32 = Error::last_os_error().raw_os_error().unwrap();
    let error_name = nix::errno::Errno::from_raw(errno).desc();
    bail!("errno = {} ({})", errno, error_name)
}

// Run the child until either entry to or exit from a system call.
// If it returns false, the child has exited.
fn wait_for_syscall(child: i32) -> Result<bool> {
    loop {
        _ = ptrace::syscall(child)
            .map_err(|errno| anyhow!("SINGLESTEP failed. errno {}", errno))?;
        let status = nix::sys::wait::waitpid(Pid::from_raw(child), None)
            .map_err(|errno| anyhow!("waitpid had error. errno {}", errno))?;
        match status {
            WaitStatus::Exited(_, code) => {
                debug!("{} signalled exited. exit code: {:?}", child, code);
                return Ok(true);
            }
            WaitStatus::PtraceSyscall(_) => {
                debug!("{} syscall stopped", child);
                return Ok(false);
            }
            WaitStatus::Stopped(_, signal) if signal != Signal::SIGTRAP => {
                debug!("{} syscall stopped SIGTRAP", child);
                return Ok(false);
            }
            WaitStatus::PtraceEvent(_, _, _) => {
                debug!("{} ignoring syscall ptrace event", child);
            }
            other => {
                trace!("{} ignoring wait status {:?}", child, other);
            }
        }
    }
}

fn do_trace(child: i32, output: &mut dyn std::io::Write, options: TraceOptions) -> Result<()> {
    debug!(%child, "starting trace of child");
    let _ = child;
    // Wait until child has sent itself the SIGSTOP above, and is ready to be
    // traced.
    let status = nix::sys::wait::waitpid(Pid::from_raw(child), None)?;
    if let WaitStatus::Stopped(_, _) = status {
        debug!("child {} is ready for tracing", child);
    } else {
        bail!("child unexpected signal during trace setup: {:?}", status);
    }

    if let Err(errno) = ptrace::setoptions(child, ptrace::Options::SysGood) {
        bail!(
            "failed to ptrace child with PTRACE_O_TRACESYSGOOD. errno={}",
            errno
        );
    }

    let _summary_stats: HashMap<u64, SyscallStat> = HashMap::new();

    loop {
        if wait_for_syscall(child)? {
            break;
        }
        let registers =
            ptrace::getregs(child).map_err(|errno| anyhow!("ptrace failed errno {}", errno))?;
        let syscall_num = registers.orig_rax;

        let syscall_arg_registers = vec![
            registers.rdi,
            registers.rsi,
            registers.rdx,
            registers.r10,
            registers.r8,
            registers.r9,
        ];

        let t: String = match options.t {
            TimestampOption::None => String::new(),
            TimestampOption::Absolute => {
                let format = time::format_description::parse("[hour]:[minute]:[second]")?;
                let now = time::OffsetDateTime::now_local()
                    .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
                format!("{} ", now.format(&format).unwrap())
            }
            TimestampOption::AbsoluteUsecs => {
                let format = time::format_description::parse(
                    "[hour]:[minute]:[second].[subsecond digits:6]",
                )?;
                let now = time::OffsetDateTime::now_local()
                    .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
                format!("{} ", now.format(&format).unwrap())
            }
            TimestampOption::AbsoluteUNIXUsecs => todo!(),
        };

        if let Some((name, arg_fmts)) = SYSCALL_MAP.get(&syscall_num) {
            let _ = arg_fmts;
            let mut args_str = String::new();
            let zipped = syscall_arg_registers
                .iter()
                .zip(arg_fmts.iter())
                .enumerate();
            for (i, (register, fmt)) in zipped {
                let fmtd_arg = match fmt {
                    // TODO(Jonathon): escape tabs, newlines
                    //
                    // TODO(Jonathon): on syscall entry the pointer in a read syscall is not present
                    // so the `dump` shows nothing. The dump should be populated
                    // on exit of the syscall.
                    FmtSpec::ReadBuffer => {
                        let size = syscall_arg_registers
                            .get(2)
                            .expect("TODO: don't assume this is read syscall");
                        let contents = dump(child, register, *size as usize, 36, true)?;
                        format!("\"{}\"", contents)
                    }
                    FmtSpec::FD => format!("{}", register), // TODO: resolve to path
                    FmtSpec::Hex => format!("{:#x}", register),
                    // TODO(Jonathon): escape tabs, newlines
                    FmtSpec::WriteBuffer => {
                        let size = syscall_arg_registers
                            .get(2)
                            .expect("TODO: don't assume this is write syscall");
                        let contents = dump(child, register, *size as usize, 36, true)?;
                        format!("\"{}\"", contents)
                    }
                    _ => format!("{:#x}", register),
                };
                args_str.push_str(fmtd_arg.as_str());
                if (i + 1) < arg_fmts.len() {
                    args_str.push_str(", ");
                }
            }

            #[cfg(feature = "cuda_sniff")]
            {
                if syscall_num == 16 {
                    let fd = syscall_arg_registers.get(0).expect("must exist for ioctl");
                    let request = syscall_arg_registers.get(1).expect("must exist for ioctl");
                    let argp = syscall_arg_registers.get(2).expect("must exist for ioctl")
                        as *const u64 as *mut libc::c_void;
                    if let Some(o) = sniff_ioctl(*fd as i32, *request, argp)? {
                        writeln!(output, "{}SNIFF {}", t, o)?;
                    }
                }
            }

            write!(output, "{}{}({}) = ", t, name, args_str)?;
        } else {
            warn!("unknown syscall number {}", syscall_num);
            // TODO(Jonathon): emit with 'unknown' formatting.
            write!(output, "{}syscall({}) = ", t, syscall_num)?;
        }
        if wait_for_syscall(child)? {
            break;
        }
        let registers =
            ptrace::getregs(child).map_err(|errno| anyhow!("ptrace failed errno {}", errno))?;
        let retval = registers.rax;
        writeln!(output, "{}", retval)?;
    }

    Ok(())
}

// Dump out parts of a buffer as a human-readable string.
// Inspiration: gvisor/pkg/sentry/strace/strace.go
fn dump(
    pid: libc::pid_t,
    addr: &u64,
    size: usize,
    max_blob_size: usize,
    print_content: bool,
) -> Result<String> {
    if !print_content {
        return Ok(format!("{{base={:#x}, len={}}}", addr, size));
    }
    let reader = ptrace::Reader::new(pid);
    let read_size = size.min(max_blob_size);
    let s = reader
        .read_string(*addr, read_size)
        .map_err(|errno| anyhow!("peekdata read string failed errno {}", errno))?;
    Ok(String::from_utf8_lossy(s.as_slice()).to_string())
}

/// Takes an iterable of arguments to create a traced process.
pub unsafe fn trace_command<T, W>(args: T, mut output: W, options: TraceOptions) -> Result<()>
where
    T: IntoIterator<Item = String>,
    W: std::io::Write + 'static,
{
    // We’ll start with the entry point. We check that we were passed a command,
    // and then we fork() to create two processes –
    // one to execute the program to be traced, and
    // the other to trace it.
    unsafe {
        let child = libc::fork();
        debug!(?child, "after fork");
        if child == 0 {
            do_child(args)
        } else {
            do_trace(child, &mut output, options)
        }
    }
}
