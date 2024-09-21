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
    #[clap(help = "Arguments for the program to trace")]
    args: Vec<String>,

    #[clap(short = 'o', long = "output", help = "Path to the output file")]
    output: Option<String>,

    #[arg(short = 't', long = "timestamp", action = ArgAction::Count, help = "Print absolute timestamp")]
    timestamp_level: u8,
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
    let options = rstrace::TraceOptions {
        t,
        ..Default::default()
    };

    unsafe { trace_command(cli.args.into_iter(), output, options) }
}
