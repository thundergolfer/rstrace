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
use info::{IOCTL_N, OPENAT_N};
use libc::{self, AT_FDCWD};
use nix::errno::Errno;
use nix::{
    sys::{signal::Signal, wait::WaitStatus},
    unistd::Pid,
};
use statistics::summary_to_table;
use terminal::{render_cuda, render_syscall};
use tracing::{debug, trace, warn};

use crate::{
    info::{FmtSpec, SYSCALL_MAP},
    statistics::SyscallStat,
};
#[allow(dead_code, non_upper_case_globals)]
pub mod info;
pub mod ptrace;
pub mod statistics;
mod tef;
mod terminal;

#[cfg(feature = "cuda_sniff")]
use rstrace_cuda_sniff::sniff_ioctl;

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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SummaryOption {
    #[default]
    None,
    SummaryOnly,
    SummaryJSON,
    Summary,
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
    /// How to format timestamps.
    pub t: TimestampOption,
    /// Whether to include statistics (summary mode).
    pub stats: StatisticsOptions,
    /// Whether to include CUDA-related output.
    pub cuda_sniff: bool,
    /// Whether to only show CUDA-related output.
    pub cuda_only: bool,
    /// Whether to emit colored output.
    pub colored_output: bool,
    /// Whether to emit TEF trace data.
    pub tef: bool,
}

unsafe fn do_child<T, S>(args: T) -> Result<()>
where
    T: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let cstrings: Vec<CString> = args
        .into_iter()
        .map(|arg| CString::new(arg.as_ref()).expect("CString::new failed"))
        .collect();

    let child_prog = cstrings.first().unwrap().clone();
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
    let trace_start = std::time::Instant::now();
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

    let mut summary_stats: HashMap<u64, SyscallStat> = HashMap::new();
    let mut tef = if options.tef {
        Some(tef::TefWriter::new())
    } else {
        None
    };

    loop {
        if wait_for_syscall(child)? {
            break;
        }
        let registers =
            ptrace::getregs(child).map_err(|errno| anyhow!("ptrace failed errno {}", errno))?;
        let syscall_num = registers.orig_rax;

        let syscall_arg_registers = [
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

        if options.stats.summary != SummaryOption::None {
            let stat = summary_stats.entry(syscall_num).or_default();
            stat.calls += 1;
        }

        let show_syscalls =
            (options.stats.summary != SummaryOption::SummaryOnly) && !options.cuda_only;
        let show_cuda = show_syscalls || options.cuda_only;

        let name = if let Some((name, arg_fmts)) = SYSCALL_MAP.get(&syscall_num) {
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
                        let contents = dump(child, register, *size as usize, 36, true)
                            .unwrap_or("READ FAILED".into());
                        format!("\"{}\"", contents)
                    }
                    FmtSpec::FD => {
                        if i == 0 && syscall_num == OPENAT_N && *register as i32 == AT_FDCWD {
                            "AT_FDCWD".to_string()
                        } else {
                            // TODO: resolve to path
                            format!("{}", register)
                        }
                    }
                    FmtSpec::Hex => {
                        format!("{:#x}", register)
                    }
                    // TODO(Jonathon): escape tabs, newlines
                    FmtSpec::WriteBuffer => {
                        let size = syscall_arg_registers
                            .get(2)
                            .expect("TODO: don't assume this is write syscall");
                        let contents = dump(child, register, *size as usize, 36, true)
                            .unwrap_or("DUMP FAILED".into());
                        format!("\"{}\"", contents)
                    }
                    FmtSpec::Path => {
                        // TODO: this doesn't handle paths longer than 1024 bytes
                        let s =
                            read_path_from_child(child, register).unwrap_or("READ FAILED".into());
                        format!("\"{}\"", s)
                    }
                    _ => format!("{:#x}", register),
                };
                args_str.push_str(fmtd_arg.as_str());
                if (i + 1) < arg_fmts.len() {
                    args_str.push_str(", ");
                }
            }
            if show_syscalls {
                if let Some(ref mut tef) = tef {
                    let e = tef.emit_duration_start(name, trace_start.elapsed().as_micros() as u64);
                    write!(output, "{}", e)?;
                } else {
                    let name = render_syscall(options.colored_output, name, syscall_num);
                    write!(output, "{}{}({}) = ", t, name, args_str)?;
                }
            }

            name
        } else {
            warn!("unknown syscall number {}", syscall_num);
            // "Syscalls unknown to strace are printed raw, with the unknown system call number printed in hexadecimal form and prefixed with "syscall_":"
            if show_syscalls {
                write!(output, "{}syscall_{:#x} = ", t, syscall_num)?;
            }
            "unknown"
        };

        // Wait for the syscall to complete
        let start = std::time::Instant::now();
        if wait_for_syscall(child)? {
            break;
        }
        let duration = start.elapsed();
        if options.stats.summary != SummaryOption::None {
            let stat = summary_stats.entry(syscall_num).or_default();
            stat.latency += duration;
        }

        let registers =
            ptrace::getregs(child).map_err(|errno| anyhow!("ptrace failed: errno {}", errno))?;
        if registers.rax & (1 << 63) != 0 {
            let errno = registers.rax as i64;
            let err_name: Errno = Errno::from_raw(errno as i32);
            if show_syscalls {
                if let Some(ref mut tef) = tef {
                    let e = tef.emit_duration_end(name, trace_start.elapsed().as_micros() as u64);
                    write!(output, "{}", e)?;
                } else {
                    writeln!(output, "{} {}", errno, err_name)?;
                }
            }
        } else {
            let retval = registers.rax;
            if show_syscalls {
                if let Some(ref mut tef) = tef {
                    let e = tef.emit_duration_end(name, trace_start.elapsed().as_micros() as u64);
                    write!(output, "{}", e)?;
                } else {
                    writeln!(output, "{}", retval)?;
                }
            }
        }

        #[cfg(feature = "cuda_sniff")]
        {
            if show_cuda && syscall_num == IOCTL_N {
                let fd = syscall_arg_registers.first().expect("must exist for ioctl");
                let request = syscall_arg_registers.get(1).expect("must exist for ioctl");
                let argp = syscall_arg_registers.get(2).expect("must exist for ioctl") as *const u64
                    as *mut libc::c_void;
                if let Some(ioctl) = sniff_ioctl(*fd as i32, *request, argp)? {
                    let ioctl = render_cuda(options.colored_output, ioctl);
                    writeln!(output, "  {}{}", t, ioctl)?;
                }
            }
        }
    }

    let trace_end = std::time::Instant::now();
    let trace_duration = trace_end.duration_since(trace_start);
    if options.stats.summary != SummaryOption::None {
        let s = summary_to_table(summary_stats, trace_duration);
        writeln!(output, "{}", s)?;
    }

    if let Some(ref mut tef) = tef {
        tef.finalize(output, trace_start.elapsed().as_micros() as u64)?;
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

/// Reads a null-terminated string from the child process's memory at a given address.
///
/// # Arguments
/// * `pid` - Process ID of the child process.
/// * `addr` - Address in the child process's memory where the string begins.
fn read_path_from_child(pid: libc::pid_t, addr: &u64) -> Result<String> {
    let reader = ptrace::Reader::new(pid);
    let read_size = 1024;
    let s = reader
        .read_string(*addr, read_size)
        .map_err(|errno| anyhow!("peekdata read string failed errno {}", errno))?;
    Ok(String::from_utf8_lossy(s.as_slice()).to_string())
}

/// Takes an iterable of arguments to create a traced process.
pub fn trace_command<T, S, W>(args: T, output: &mut W, options: TraceOptions) -> Result<()>
where
    T: IntoIterator<Item = S>,
    S: AsRef<str>,
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
            do_trace(child, output, options)
        }
    }
}

/// Takes a process ID (PID) and traces it.
pub fn trace_attach(
    pid: i32,
    output: &mut dyn std::io::Write,
    options: TraceOptions,
) -> Result<()> {
    // Attach to the process with the given PID using ptrace
    ptrace::attach(pid).map_err(|errno| anyhow!("ptrace attach failed. errno {}", errno))?;
    do_trace(pid, output, options)
}
