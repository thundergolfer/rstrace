//! rstrace is a Rust implementation of strace to trace system calls and CUDA API calls.
//!
//! # Usage
//!
//! ```bash
//! rstrace -tt ls .
//! ```
//! TODO(Jonathon): Implement -f and -ff to follow forks
use anyhow::Result;
use rstrace::trace_command;
use tracing::level_filters::LevelFilter;
use tracing_subscriber;
use tracing_subscriber::EnvFilter;

use clap::{ArgAction, Parser};

#[derive(Parser, Debug)]
#[clap(
    author,
    name = "rstrace",
    version = "0.1.0",
    about = "A Rust implementation of strace to trace system calls and CUDA API calls."
)]
struct Cli {
    #[clap(
        help = "Arguments for the program to trace. e.g. 'ls /tmp/'",
        required = true
    )]
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
        short = 'j',
        long = "summary-json",
        help = "Count time, calls, and errors for each syscall and report summary in JSON format"
    )]
    summary_json: bool,

    #[clap(
        long = "cuda",
        help = "Enable CUDA ioctl sniffing. [Requires 'cuda_sniff' feature]",
        action = ArgAction::SetTrue
    )]
    cuda_sniff: bool,
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

    let output: Box<dyn std::io::Write> = match cli.output {
        Some(path) => Box::new(std::fs::File::create(path)?),
        None => Box::new(std::io::stdout()),
    };

    let t = match cli.timestamp_level {
        0 => rstrace::TimestampOption::None,
        1 => rstrace::TimestampOption::Absolute,
        2 => rstrace::TimestampOption::AbsoluteUsecs,
        _ => rstrace::TimestampOption::AbsoluteUNIXUsecs,
    };
    let s = match (cli.summary_only, cli.summary_json) {
        (true, false) => rstrace::SummaryOption::SummaryOnly,
        (false, true) => rstrace::SummaryOption::SummaryJSON,
        _ => rstrace::SummaryOption::None,
    };
    if !cfg!(feature = "cuda_sniff") && cli.cuda_sniff {
        anyhow::bail!("--cuda requires the 'cuda_sniff' feature to be enabled");
    }
    let options = rstrace::TraceOptions {
        t,
        stats: rstrace::StatisticsOptions { summary: s },
        cuda_sniff: cli.cuda_sniff,
        ..Default::default()
    };

    unsafe { trace_command(cli.args.into_iter(), output, options) }
}
