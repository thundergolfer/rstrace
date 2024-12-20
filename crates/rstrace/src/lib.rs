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
use info::{RetCode, EXIT_GROUP_N, EXIT_N, IOCTL_N, OPENAT_N};
use libc::{self, AT_FDCWD};
use nix::errno::Errno;
use nix::sys::ptrace::getevent;
use nix::{
    sys::{signal::Signal, wait::WaitStatus},
    unistd::Pid,
};
use ptrace::Options;
use statistics::summary_to_table;
use terminal::{
    render_cuda, render_syscall, render_syscall_return_addr, render_syscall_return_err,
    render_syscall_return_success,
};
use tracing::{debug, warn};

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

fn make_ts(t_opt: &TimestampOption) -> Result<String> {
    let t = match t_opt {
        TimestampOption::None => String::new(),
        TimestampOption::Absolute => {
            let format = time::format_description::parse("[hour]:[minute]:[second]")?;
            let now = time::OffsetDateTime::now_local()
                .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
            format!("{} ", now.format(&format).unwrap())
        }
        TimestampOption::AbsoluteUsecs => {
            let format =
                time::format_description::parse("[hour]:[minute]:[second].[subsecond digits:6]")?;
            let now = time::OffsetDateTime::now_local()
                .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
            format!("{} ", now.format(&format).unwrap())
        }
        TimestampOption::AbsoluteUNIXUsecs => todo!(),
    };
    Ok(t)
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
    /// Whether to follow forks (ie. child processes).
    pub follow_forks: bool,
    /// Whether to emit TEF trace data.
    pub tef: bool,
}

impl TraceOptions {
    /// Whether to show syscalls by writing to the output.
    pub fn show_syscalls(&self) -> bool {
        (self.stats.summary != SummaryOption::SummaryOnly) && !self.cuda_only
    }
}

fn ptrace_init_options() -> Options {
    ptrace::Options::SysGood | ptrace::Options::TraceExit | ptrace::Options::TraceExec
}

fn ptrace_init_options_fork() -> Options {
    ptrace_init_options() | Options::TraceFork | Options::TraceVFork | Options::TraceClone
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

#[derive(Debug)]
enum PtraceSyscallInfo {
    None = 0,
    Entry = 1,
    Exit = 2,
    Seccomp = 3,
    Unknown = 4,
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

    // Now that we've waited for the tracee to be ready, set the ptrace options.
    debug!(?child, "set options");
    let opts = if options.follow_forks {
        // TODO(Jonathon): currently enabling this
        // breaks the implementation because I've only ever been waiting on the
        // child process, and not on any of its children.
        ptrace_init_options_fork()
    } else {
        ptrace_init_options()
    };

    if let Err(errno) = ptrace::setoptions(child, opts) {
        bail!(
            "failed to ptrace child with PTRACE_O_TRACESYSGOOD. errno={}",
            errno
        );
    }

    // After setting options, single step the child to resume execution.
    debug!(?child, "single step to resume tracee");
    nix::sys::ptrace::syscall(Pid::from_raw(child), None)?;

    let mut summary_stats: HashMap<u64, SyscallStat> = HashMap::new();
    let mut tef = if options.tef {
        Some(tef::TefWriter::new())
    } else {
        None
    };

    // The main tracer loop runs here. It is an outer loop that processes all syscall
    // events until the root child (tracee) exits, and an inner loop (wait_for_syscall)
    // that processes statuses and signals for all children until a syscall event is found.
    debug!("begin trace loop");
    loop {
        let status = nix::sys::wait::waitpid(Pid::from_raw(child), None)
            .map_err(|errno| anyhow!("waitpid had error. errno {}", errno))?;
        // Wait for a syscall to begin or complete.
        match status {
            // `WIFSTOPPED(status), signal is WSTOPSIG(status)
            WaitStatus::Stopped(pid, signal) => {
                // There are three reasons why a child might stop with SIGTRAP:
                // 1) syscall entry
                // 2) syscall exit
                // 3) child calls exec
                //
                // Because we are tracing with PTRACE_O_TRACESYSGOOD, syscall entry and syscall exit
                // are stopped in PtraceSyscall and not here, which means if we get a SIGTRAP here,
                // it's because the child called exec.
                if signal == Signal::SIGTRAP {
                    record_syscall_entry(
                        pid.into(),
                        &options,
                        output,
                        &trace_start,
                        &mut tef,
                        &mut summary_stats,
                    )?;
                    nix::sys::ptrace::syscall(pid, None)?;
                    continue;
                }

                // If we trace with PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK, and PTRACE_O_TRACECLONE,
                // a created child of our tracee will stop with SIGSTOP.
                // If our tracee creates children of their own, we want to trace their syscall times with a new value.
                if signal == Signal::SIGSTOP {
                    if options.follow_forks {
                        // start_times.insert(pid, None);
                        if options.show_syscalls() {
                            writeln!(output, "Attaching to child {}", pid,)?;
                        }
                    }

                    nix::sys::ptrace::syscall(pid, None)?;
                    continue;
                }

                // The SIGCHLD signal is sent to a process when a child process terminates, interrupted, or resumes after being interrupted
                // This means, that if our tracee forked and said fork exits before the parent, the parent will get stopped.
                // Therefor issue a PTRACE_SYSCALL request to the parent to continue execution.
                // This is also important if we trace without the following forks option.
                if signal == Signal::SIGCHLD {
                    nix::sys::ptrace::syscall(pid, Some(signal))?;
                    continue;
                }

                // If we fall through to here, we have another signal that's been sent to the tracee,
                // in this case, just forward the singal to the tracee to let it handle it.
                // TODO: Finer signal handling, edge-cases etc.
                nix::sys::ptrace::cont(pid, signal)?;
            }
            // WIFEXITED(status)
            WaitStatus::Exited(pid, _) => {
                // If the process that exits is the original tracee, we can safely break here,
                // but we need to continue if the process that exits is a child of the original tracee.
                if Pid::from_raw(child) == pid {
                    if options.show_syscalls() {
                        // Handle the fact that the child has exited before we know the return value
                        // of the current syscall.
                        writeln!(output, "?")?;
                    }
                    break;
                } else {
                    continue;
                };
            }
            // The traced process was stopped by a `PTRACE_EVENT_*` event.
            WaitStatus::PtraceEvent(pid, _, code) => {
                fn is_exit_syscall(pid: &Pid) -> Result<bool> {
                    let registers = ptrace::getregs(pid.as_raw())
                        .map_err(|errno| anyhow!("ptrace failed errno {}", errno))?;
                    let reg = registers.orig_rax;
                    Ok(reg == EXIT_N as u64 || reg == EXIT_GROUP_N as u64)
                }

                // We stop at the PTRACE_EVENT_EXIT event because of the PTRACE_O_TRACEEXIT option.
                // We do this to properly catch and log exit-family syscalls, which do not have an PTRACE_SYSCALL_INFO_EXIT event.
                if code == PtraceSyscallInfo::Exit as i32 && is_exit_syscall(&pid)? {
                    let start = std::time::Instant::now();
                    let t: String = make_ts(&options.t)?;
                    record_syscall_exit(
                        pid.into(),
                        &start,
                        &options,
                        &mut summary_stats,
                        &mut tef,
                        output,
                        &trace_start,
                        &t,
                    )?;
                }

                nix::sys::ptrace::syscall(pid, None)?;
            }
            // Tracee is traced with the PTRACE_O_TRACESYSGOOD option.
            WaitStatus::PtraceSyscall(pid) => {
                // ptrace(PTRACE_GETEVENTMSG,...) can be one of three values here:
                // 1) PTRACE_SYSCALL_INFO_NONE
                // 2) PTRACE_SYSCALL_INFO_ENTRY
                // 3) PTRACE_SYSCALL_INFO_EXIT
                let event = match getevent(pid)? as u8 {
                    0 => PtraceSyscallInfo::None,
                    1 => PtraceSyscallInfo::Entry,
                    2 => PtraceSyscallInfo::Exit,
                    3 => PtraceSyscallInfo::Seccomp,
                    _ => PtraceSyscallInfo::Unknown,
                };

                // Snapshot current time, to avoid polluting the syscall time with
                // non-syscall related latency.
                let start = std::time::Instant::now();
                // TODO: it's a bit weird to recalc the timestamp on syscall exit and use it in CUDA output.
                let t: String = make_ts(&options.t)?;

                match event {
                    PtraceSyscallInfo::Entry => record_syscall_entry(
                        pid.into(),
                        &options,
                        output,
                        &trace_start,
                        &mut tef,
                        &mut summary_stats,
                    )?,
                    PtraceSyscallInfo::Exit => record_syscall_exit(
                        pid.into(),
                        &start,
                        &options,
                        &mut summary_stats,
                        &mut tef,
                        output,
                        &trace_start,
                        &t,
                    )?,
                    PtraceSyscallInfo::Seccomp => warn!("unexpected seccomp syscall event"),
                    PtraceSyscallInfo::Unknown => warn!("unknown syscall event"),
                    PtraceSyscallInfo::None => {}
                }

                nix::sys::ptrace::syscall(pid, None)?;
            }
            // WIFSIGNALED(status), signal is WTERMSIG(status) and coredump is WCOREDUMP(status)
            WaitStatus::Signaled(pid, signal, coredump) => {
                writeln!(
                    output,
                    "Child {} terminated by signal {:?} {}",
                    pid,
                    signal,
                    if coredump { "(core dumped)" } else { "" }
                )?;
                break;
            }
            // WIFCONTINUED(status), this usually happens when a process receives a SIGCONT.
            // Just continue with the next iteration of the loop.
            WaitStatus::Continued(_) | WaitStatus::StillAlive => {
                continue;
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

#[allow(clippy::too_many_arguments)]
fn record_syscall_entry(
    child: libc::pid_t,
    options: &TraceOptions,
    output: &mut dyn std::io::Write,
    trace_start: &std::time::Instant,
    tef: &mut Option<tef::TefWriter>,
    summary_stats: &mut HashMap<u64, SyscallStat>,
) -> Result<()> {
    let t: String = make_ts(&options.t)?;
    let show_syscalls = options.show_syscalls();
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

    if options.stats.summary != SummaryOption::None {
        let stat = summary_stats.entry(syscall_num).or_default();
        stat.calls += 1;
    }

    if let Some((name, arg_fmts)) = SYSCALL_MAP.get(&syscall_num) {
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
                    let s = read_path_from_child(child, register).unwrap_or("READ FAILED".into());
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
    } else {
        warn!("unknown syscall number {}", syscall_num);
        // "Syscalls unknown to strace are printed raw, with the unknown system call number printed in hexadecimal form and prefixed with "syscall_":"
        if show_syscalls {
            write!(output, "{}syscall_{:#x} = ", t, syscall_num)?;
        }
    };
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_syscall_exit(
    child: libc::pid_t,
    start: &std::time::Instant,
    options: &TraceOptions,
    summary_stats: &mut HashMap<u64, SyscallStat>,
    tef: &mut Option<tef::TefWriter>,
    output: &mut dyn std::io::Write,
    trace_start: &std::time::Instant,
    timestamp: &str, // timestamp
) -> Result<()> {
    let show_syscalls = options.show_syscalls();
    let show_cuda = show_syscalls || options.cuda_only;
    let registers =
        ptrace::getregs(child).map_err(|errno| anyhow!("ptrace failed: errno {}", errno))?;
    let syscall_num = registers.orig_rax;

    let syscall_arg_registers = [
        registers.rdi,
        registers.rsi,
        registers.rdx,
        registers.r10,
        registers.r8,
        registers.r9,
    ];

    let name = SYSCALL_MAP
        .get(&syscall_num)
        .map(|(name, _)| name)
        .map_or("unknown", |v| v);
    let duration = start.elapsed();
    if options.stats.summary != SummaryOption::None {
        let stat = summary_stats.entry(syscall_num).or_default();
        stat.latency += duration;
    }

    let ret_code = RetCode::from_raw(registers.rax);
    if show_syscalls {
        match ret_code {
            RetCode::Err(errno) => {
                let err_name: Errno = Errno::from_raw(errno as i32);
                if let Some(ref mut tef) = tef {
                    let e = tef.emit_duration_end(name, trace_start.elapsed().as_micros() as u64);
                    write!(output, "{}", e)?;
                } else {
                    writeln!(
                        output,
                        "{}",
                        render_syscall_return_err(options.colored_output, errno, err_name)
                    )?;
                }
            }
            RetCode::Address(addr) => {
                if let Some(ref mut tef) = tef {
                    let e = tef.emit_duration_end(name, trace_start.elapsed().as_micros() as u64);
                    write!(output, "{}", e)?;
                } else {
                    let addr = render_syscall_return_addr(options.colored_output, addr);
                    writeln!(output, "{}", addr)?;
                }
            }
            RetCode::Ok(retval) => {
                if let Some(ref mut tef) = tef {
                    let e = tef.emit_duration_end(name, trace_start.elapsed().as_micros() as u64);
                    write!(output, "{}", e)?;
                } else {
                    writeln!(
                        output,
                        "{}",
                        render_syscall_return_success(options.colored_output, retval)
                    )?;
                }
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
                writeln!(output, "  {}{}", timestamp, ioctl)?;
            }
        }
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
