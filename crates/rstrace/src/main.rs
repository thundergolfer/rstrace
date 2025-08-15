//! rstrace is a Rust implementation of strace to trace system calls and CUDA API calls.
//!
//! # Usage
//!
//! ```bash
//! rstrace -tt ls .
//! ```
use anyhow::Result;
use rstrace::{trace_attach, trace_command};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

use clap::{ArgAction, Parser};

const NAME: &str = "rstrace";

#[derive(Parser, Debug)]
#[clap(
    author,
    name = NAME,
    version = "0.8.0",
    about = "A Rust implementation of strace to trace system calls and CUDA API calls."
)]
struct Cli {
    #[clap(help = "Arguments for the program to trace. e.g. 'ls /tmp/'")]
    args: Vec<String>,

    #[clap(
        short = 'o',
        long = "output",
        help = "send trace output to FILE instead of stderr"
    )]
    output: Option<String>,

    #[arg(
        short = 't',
        long = "timestamp", 
        action = ArgAction::Count,
        help = "Print absolute timestamp. -tt includes microseconds, -ttt uses UNIX timestamps"
    )]
    timestamp_level: u8,

    #[clap(
        short = 'c',
        long = "summary-only",
        help = "Count time, calls, and errors for each syscall and report summary"
    )]
    summary_only: bool,

    #[clap(
        short = 'C',
        long = "summary",
        help = "like -c, but also print the regular output"
    )]
    summary: bool,

    #[clap(
        short = 'j',
        long = "summary-json",
        help = "Count time, calls, and errors for each syscall and report summary in JSON format"
    )]
    summary_json: bool,

    #[clap(
        long = "tef",
        help = "Emit Trace Event Format (TEF) trace data as output"
    )]
    tef: bool,

    #[clap(
        long = "verbose",
        help = "Output human readable information about CUDA ioctls.",
        action = ArgAction::SetTrue,
        default_value_t = false
    )]
    verbose: bool,

    #[clap(
        long = "cuda",
        help = "Enable CUDA ioctl sniffing. [Requires 'cuda_sniff' feature]",
        action = ArgAction::SetTrue
    )]
    cuda_sniff: bool,

    #[clap(
        long = "cuda-only",
        help = "Enable CUDA ioctl sniffing and disable all other output. [Requires 'cuda_sniff' feature]",
        action = ArgAction::SetTrue
    )]
    cuda_only: bool,

    #[clap(
        short = 'p',
        long = "attach",
        help = "Attach to the process with the process ID pid and begin tracing."
    )]
    pid: Option<i32>,

    #[clap(
        short = 'f',
        long = "follow-forks",
        help = "Trace child processes as they are created by currently traced processes as a result of the fork(2), vfork(2) and clone(2) system calls.",
        action = ArgAction::SetTrue,
        default_value_t = false
    )]
    follow_forks: bool,

    #[clap(
        long = "color",
        help = "Enable colored output (default)",
        action = ArgAction::SetTrue,
        default_value_t = true
    )]
    color: bool,

    // Attempt to follow https://no-color.org/.
    // Note however that we don't accept *any* non-empty string.
    #[clap(
        long = "no-color",
        help = None,
        action = ArgAction::SetTrue,
        default_value_t = false,
        value_parser = clap::builder::FalseyValueParser::new(),
        env = "NO_COLOR",
        hide = true, // Not useful for this option to show up in --help.
    )]
    no_color: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let mut output: Box<dyn std::io::Write> = match cli.output {
        Some(path) => Box::new(std::fs::File::create(path)?),
        None => Box::new(std::io::stderr()),
    };

    let t = match cli.timestamp_level {
        0 => rstrace::TimestampOption::None,
        1 => rstrace::TimestampOption::Absolute,
        2 => rstrace::TimestampOption::AbsoluteUsecs,
        _ => rstrace::TimestampOption::AbsoluteUNIXUsecs,
    };
    let s = match (cli.summary_only, cli.summary_json, cli.summary) {
        (true, false, false) => rstrace::SummaryOption::SummaryOnly,
        (false, true, false) => rstrace::SummaryOption::SummaryJSON,
        (false, false, true) => rstrace::SummaryOption::Summary,
        _ => rstrace::SummaryOption::None,
    };
    if cli.tef && s != rstrace::SummaryOption::None {
        anyhow::bail!("--tef cannot be used together with summary output");
    }
    if !cfg!(feature = "cuda_sniff") && cli.cuda_sniff {
        anyhow::bail!("--cuda requires the 'cuda_sniff' feature to be enabled");
    } else if !cfg!(feature = "cuda_sniff") && cli.cuda_only {
        anyhow::bail!("--cuda-only requires the 'cuda_sniff' feature to be enabled");
    } else if cfg!(feature = "cuda_sniff") && cli.cuda_only && s != rstrace::SummaryOption::None {
        anyhow::bail!("--cuda-only and --summary cannot be used together");
    }

    // Adhere to recommendations in https://clig.dev/#output for colored output configuration.
    let no_color = cli.no_color;
    let colored_output = if no_color { false } else { cli.color };

    let options = rstrace::TraceOptions {
        t,
        stats: rstrace::StatisticsOptions { summary: s },
        cuda_sniff: cli.cuda_sniff,
        cuda_only: cli.cuda_only,
        cuda_verbose: cli.verbose,
        colored_output,
        follow_forks: cli.follow_forks,
        tef: cli.tef,
    };

    if let Some(pid) = cli.pid {
        if !cli.args.is_empty() {
            eprintln!("WARN: ignoring command arguments when attaching to a process");
        }
        trace_attach(pid, &mut output, options)
    } else {
        if cli.args.is_empty() {
            anyhow::bail!(
                "{}: must have PROG [ARGS] or -p PID.\nTry '{} -h' for more information.",
                NAME,
                NAME
            );
        }
        trace_command(cli.args, &mut output, options)
    }
}
