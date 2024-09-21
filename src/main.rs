use std::process;

use anyhow::Result;
use rstrace::trace_command;
use tracing::level_filters::LevelFilter;
use tracing_subscriber;
use tracing_subscriber::EnvFilter;

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, name = "rstrace", version = "0.1.0", about = "A Rust implementation of strace to trace system calls and CUDA API calls.")]
struct Cli {
    #[clap(help = "Arguments for the program to trace")]
    args: Vec<String>,
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

    unsafe { trace_command(cli.args.into_iter()) }
}
